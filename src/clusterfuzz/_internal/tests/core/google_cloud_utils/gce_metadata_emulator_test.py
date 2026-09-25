# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the fake GCE metadata server."""

import importlib
import json
import os
import re

import google.auth
from google.auth import compute_engine
from google.auth.transport import requests as google_auth_requests
import pytest
import requests

from clusterfuzz._internal.google_cloud_utils import compute_metadata
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.tests.test_libs import gce_metadata_emulator


# TODO(b/555371391) Move this to the new integration test suite
@pytest.mark.skip(
    reason='Experimental: pending migration to the new integration test suite.')
class TestGceMetadataEmulator:
  """Integration tests for the fake GCE metadata server."""

  # TODO(b/555371391) Remove this setup once we have our own butler.py command
  @pytest.fixture(scope='class', autouse=True)
  @classmethod
  def _emulators(cls):
    gce_metadata_emulator.bootstrap()
    importlib.reload(compute_engine._metadata)  # pylint: disable=protected-access
    importlib.reload(compute_metadata)
    with gce_metadata_emulator.trusted_untrusted_pair() as (tworker, uworker):
      cls.tworker = tworker
      cls.uworker = uworker
      yield

  @pytest.fixture(autouse=True)
  def clean_up_after_each_test(self):
    yield
    self.tworker.clear_faults()
    self.uworker.clear_faults()

  def test_default_credentials_come_from_the_trusted_emulator(self):
    """Verifies that google.auth.default() resolves Compute Engine credentials from the tworker emulator, not uworker."""
    assert self.tworker.hostport == os.environ['GCE_METADATA_HOST']
    assert self.uworker.hostport != os.environ['GCE_METADATA_HOST']

    creds, project_id = google.auth.default()

    assert isinstance(creds, compute_engine.Credentials)
    assert project_id == 'test-clusterfuzz'

  def test_refreshing_credentials_yields_the_configured_token(self):
    """Verifies that refreshing Compute Engine credentials returns the token and email from tworker.json."""
    creds = compute_engine.Credentials()
    creds.refresh(google_auth_requests.Request())

    assert creds.token == 'fake-tworker-access-token'
    assert creds.service_account_email == (
        'test-clusterfuzz-service-account-email')

  def test_clusterfuzz_credentials_wrapper_resolves_from_the_emulator(self):
    """Verifies that clusterfuzz's own credentials.get_default() wrapper, not just raw google.auth, lands on the emulator's service account."""
    # get_default() is memoized process-wide, so force a miss rather than
    # depend on whichever test class ran first.
    creds, _ = credentials.get_default(__memoize_force__=True)
    creds.refresh(google_auth_requests.Request())

    assert isinstance(creds, compute_engine.Credentials)
    assert creds.service_account_email == (
        'test-clusterfuzz-service-account-email')

  def test_trusted_and_untrusted_emulators_serve_distinct_identities(self):
    """Verifies that tworker and uworker run on separate ports and serve their respective service account emails and tokens."""
    assert self.tworker.hostport != self.uworker.hostport
    for emulator in (self.tworker, self.uworker):
      assert re.match(r'^127\.0\.0\.1:\d+$', emulator.hostport)

    assert self.tworker.get('instance/service-accounts/default/email') == (
        'test-clusterfuzz-service-account-email')
    assert self.uworker.get('instance/service-accounts/default/email') == (
        'test-unpriv-clusterfuzz-service-account-email')

    tworker_token = json.loads(
        self.tworker.get('instance/service-accounts/default/token'))
    uworker_token = json.loads(
        self.uworker.get('instance/service-accounts/default/token'))
    assert tworker_token['access_token'] == 'fake-tworker-access-token'
    assert uworker_token['access_token'] == 'fake-uworker-access-token'

  def test_get_reads_from_the_trusted_emulator(self):
    """Verifies that compute_metadata.get() is answered by the tworker emulator, the in-process identity, and returns tworker.json's values."""
    assert compute_metadata.get('instance/zone') == (
        'projects/1234567890/zones/us-central1-f')

    assert compute_metadata.get('instance/id') == self.tworker.get(
        'instance/id')
    assert compute_metadata.get('instance/id') != self.uworker.get(
        'instance/id')

  def test_is_gce_connects_to_the_running_emulator(self):
    """Verifies that compute_metadata.is_gce() opens a real connection to the emulator's ephemeral port and finds it listening."""
    assert compute_metadata._METADATA_SERVER == self.tworker.hostport  # pylint: disable=protected-access
    assert compute_metadata.is_gce()

  def test_unknown_attribute_is_a_404(self):
    """Verifies that a key absent from both instance and project attributes is a 404."""
    with pytest.raises(requests.exceptions.HTTPError) as caught:
      self.tworker.get('instance/attributes/does-not-exist')

    assert caught.value.response.status_code == 404

  def test_instance_attributes_fall_back_to_project_attributes(self):
    """Verifies that querying instance/attributes/<key> falls back to project/attributes/<key> when not set on the instance."""
    assert compute_metadata.get('instance/attributes/deployment-bucket') == (
        'test-deployment-bucket')
    assert compute_metadata.get('project/attributes/deployment-bucket') == (
        'test-deployment-bucket')

  def test_get_reads_project_and_instance_attributes(self):
    """Verifies that compute_metadata.get() reads both project/attributes/<key> and instance/attributes/<key>."""
    assert compute_metadata.get('project/attributes/deployment-bucket') == (
        'test-deployment-bucket')
    assert compute_metadata.get('project/attributes/deployment-zip') == (
        'linux-3.zip')
    assert compute_metadata.get(
        'instance/attributes/override_tworker_queue') == 'jobs-linux-test'

  def test_metadata_flavor_header_is_required(self):
    """Verifies that the emulator rejects requests missing the 'Metadata-Flavor: Google' header with HTTP 403 Forbidden."""
    response = self.tworker.session.get(
        f'{self.tworker.url}/computeMetadata/v1/instance/zone', timeout=10)

    assert response.status_code == 403
    assert response.text == ''

  def test_a_second_emulator_cannot_take_a_held_address(self):
    """Verifies that opening an emulator on an address another one already holds raises, instead of failing on a port collision."""
    with pytest.raises(RuntimeError) as caught:
      with gce_metadata_emulator.untrusted_as_default():
        pass

    assert self.tworker.hostport in str(caught.value)
    assert 'uworker' in str(caught.value)

  def test_a_fault_stops_after_the_configured_request_count(self):
    """Verifies that a fault budgeted for one request breaks only that one."""
    self.tworker.inject_fault('instance/zone', status=500, times=1)

    with pytest.raises(requests.exceptions.HTTPError) as caught:
      self.tworker.get('instance/zone')
    assert caught.value.response.status_code == 500

    assert self.tworker.get('instance/zone') == (
        'projects/1234567890/zones/us-central1-f')

  def test_compute_metadata_get_retries_itself_past_transient_faults(self):
    """Verifies that get() retries itself, and only fails past its budget."""
    budget = compute_metadata._RETRIES  # pylint: disable=protected-access

    self.tworker.inject_fault('instance/zone', status=500, times=budget)
    assert compute_metadata.get('instance/zone') == (
        'projects/1234567890/zones/us-central1-f')

    self.tworker.inject_fault('instance/zone', status=500, times=budget + 1)
    with pytest.raises(requests.exceptions.HTTPError) as caught:
      compute_metadata.get('instance/zone')
    assert caught.value.response.status_code == 500

  def test_set_adds_and_overrides_metadata_across_scopes(self):
    """Verifies runtime metadata overrides in project and instance scopes."""
    self.tworker.set_project_attribute('custom-attr', 'from-project')
    assert compute_metadata.get('project/attributes/custom-attr') == (
        'from-project')
    assert compute_metadata.get('instance/attributes/custom-attr') == (
        'from-project')

    self.tworker.set_instance_attribute('custom-attr', 'from-instance')
    assert compute_metadata.get('instance/attributes/custom-attr') == (
        'from-instance')
    assert compute_metadata.get('project/attributes/custom-attr') == (
        'from-project')

    self.tworker.set_instance_metadata('preempted', 'TRUE')
    assert compute_metadata.get('instance/preempted') == 'TRUE'


# TODO(b/555371391) Move this to the new integration test suite
@pytest.mark.skip(
    reason='Experimental: pending migration to the new integration test suite.')
class TestGceMetadataEmulatorUntrustedDefault:
  """Integration tests for a test class that runs as the untrusted worker."""

  # TODO(b/555371391) Remove this setup once we have our own butler.py command
  @pytest.fixture(scope='class', autouse=True)
  @classmethod
  def _emulator(cls):
    gce_metadata_emulator.bootstrap()
    importlib.reload(compute_engine._metadata)  # pylint: disable=protected-access
    importlib.reload(compute_metadata)
    with gce_metadata_emulator.untrusted_as_default() as uworker:
      cls.uworker = uworker
      yield

  def test_default_credentials_come_from_the_untrusted_emulator(self):
    """Verifies that google.auth.default() resolves the uworker identity when uworker holds the default address."""
    assert self.uworker.hostport == os.environ['GCE_METADATA_HOST']

    creds, project_id = google.auth.default()
    creds.refresh(google_auth_requests.Request())

    assert isinstance(creds, compute_engine.Credentials)
    assert project_id == 'test-clusterfuzz'
    assert creds.service_account_email == (
        'test-unpriv-clusterfuzz-service-account-email')
    assert creds.token == 'fake-uworker-access-token'

  def test_clusterfuzz_credentials_wrapper_resolves_to_the_untrusted_identity(
      self):
    """Verifies that clusterfuzz's credentials.get_default() wrapper also follows the default address to uworker."""
    # get_default() is memoized process-wide, so a tworker result cached by an
    # earlier test class would otherwise be handed back here, and refreshing it
    # would ask uworker for a service account it does not serve.
    creds, _ = credentials.get_default(__memoize_force__=True)
    creds.refresh(google_auth_requests.Request())

    assert creds.service_account_email == (
        'test-unpriv-clusterfuzz-service-account-email')

  def test_get_reads_from_the_untrusted_emulator(self):
    """Verifies that compute_metadata.get() is answered by uworker, whose instance/id differs from tworker's."""
    assert compute_metadata.get('instance/id') == '2222222222222222222'
    assert compute_metadata.get('instance/id') == self.uworker.get(
        'instance/id')
    assert compute_metadata.get('instance/hostname') == (
        'uworker-1.c.test-clusterfuzz.internal')
