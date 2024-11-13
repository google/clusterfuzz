# Copyright 2023 Google LLC
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
"""Batch tests."""

import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import batch
from clusterfuzz._internal.tests.test_libs import test_utils

# pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class GetSpecFromConfigTest(unittest.TestCase):
  """Tests for get_spec_from_config."""

  def setUp(self):
    self.maxDiff = None
    self.job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    self.job.put()

  def test_nonpreemptible(self):
    """Tests that get_spec_from_config works for non-preemptibles as
    expected."""
    spec = batch._get_spec_from_config('analyze', self.job.name)
    expected_spec = batch.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=110,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/google.com:clusterfuzz/regions/gce-region/subnetworks/subnetworkname',
        network='projects/google.com:clusterfuzz/global/networks/networkname',
        gce_region='gce-region',
        gce_zone='gce-zone',
        project='test-clusterfuzz',
        preemptible=False,
        machine_type='n1-standard-1',
        max_run_duration='21600s')

    self.assertCountEqual(spec, expected_spec)

  def test_preemptible(self):
    """Tests that get_spec_from_config works for preemptibles as expected."""
    spec = batch._get_spec_from_config('fuzz', self.job.name)
    expected_spec = batch.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=75,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/google.com:clusterfuzz/regions/gce-region/subnetworks/subnetworkname',
        network='projects/google.com:clusterfuzz/global/networks/networkname',
        gce_zone='gce-zone',
        gce_region='gce-region',
        project='test-clusterfuzz',
        preemptible=True,
        machine_type='n1-standard-1',
        max_run_duration='21600s')

    self.assertCountEqual(spec, expected_spec)

  def test_corpus_pruning(self):
    """Tests that corpus pruning uses a spec of 24 hours and a different one
    than normal."""
    pruning_spec = batch._get_spec_from_config('corpus_pruning', self.job.name)
    self.assertEqual(pruning_spec.max_run_duration, f'{24 * 60 * 60}s')
    normal_spec = batch._get_spec_from_config('analyze', self.job.name)
    self.assertNotEqual(pruning_spec, normal_spec)
    job = data_types.Job(name='libfuzzer_chrome_msan', platform='LINUX')
    job.put()
    # This behavior is important for grouping batch alike tasks into a single
    # batch job.
    pruning_spec2 = batch._get_spec_from_config('corpus_pruning', job.name)
    self.assertEqual(pruning_spec, pruning_spec2)
