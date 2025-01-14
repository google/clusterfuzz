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
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

# pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class GetSpecsFromConfigTest(unittest.TestCase):
  """Tests for _get_specs_from_config."""

  def setUp(self):
    self.maxDiff = None
    self.job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    self.job.put()
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.random_weighted_choice',
    ])
    self.mock.random_weighted_choice.return_value = batch.WeightedSubconfig(
        name='east4-network2',
        weight=1,
    )

  def test_nonpreemptible(self):
    """Tests that _get_specs_from_config works for non-preemptibles as
        expected."""
    spec = _get_spec_from_config('analyze', self.job.name)
    expected_spec = batch.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=110,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/project_name/regions/us-east4/subnetworks/subnetworkname2',
        network='projects/project_name/global/networks/networkname2',
        gce_region='us-east4',
        project='test-clusterfuzz',
        preemptible=False,
        machine_type='n1-standard-1',
        priority=1,
        retry=True,
        max_run_duration='21600s',
    )

    self.assertCountEqual(spec, expected_spec)

  def test_fuzz_get_specs_from_config(self):
    """Tests that _get_specs_from_config works for fuzz tasks as expected."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = _get_spec_from_config('fuzz', job.name)
    expected_spec = batch.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=75,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/project_name/regions/us-east4/subnetworks/subnetworkname2',
        network='projects/project_name/global/networks/networkname2',
        gce_region='us-east4',
        project='test-clusterfuzz',
        preemptible=True,
        machine_type='n1-standard-1',
        priority=0,
        retry=False,
        max_run_duration='21600s',
    )

    self.assertCountEqual(spec, expected_spec)

  def test_corpus_pruning(self):
    """Tests that corpus pruning uses a spec of 24 hours and a different one
        than normal."""
    pruning_spec = _get_spec_from_config('corpus_pruning', self.job.name)
    self.assertEqual(pruning_spec.max_run_duration, f'{24 * 60 * 60}s')
    normal_spec = _get_spec_from_config('analyze', self.job.name)
    self.assertNotEqual(pruning_spec, normal_spec)
    job = data_types.Job(name='libfuzzer_chrome_msan', platform='LINUX')
    job.put()
    # This behavior is important for grouping batch alike tasks into a single
    # batch job.
    pruning_spec2 = _get_spec_from_config('corpus_pruning', job.name)
    self.assertEqual(pruning_spec, pruning_spec2)

  def test_get_specs_from_config_disk_size(self):
    """Tests that DISK_SIZE_GB is respected."""
    size = 500
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {size}\n',
        platform='LINUX',
        name='libfuzzer_asan_test').put()

    spec = batch._get_specs_from_config(
        [batch.BatchTask('fuzz', 'libfuzzer_asan_test', None)])
    self.assertEqual(spec['fuzz', 'libfuzzer_asan_test'].disk_size_gb, size)

  def test_get_specs_from_config_no_disk_size(self):
    """Test that disk_size_gb isn't mandatory."""
    data_types.Job(platform='LINUX', name='libfuzzer_asan_test').put()
    spec = batch._get_specs_from_config(
        [batch.BatchTask('fuzz', 'libfuzzer_asan_test', None)])
    conf = batch._get_batch_config()
    expected_size = (
        conf.get('mapping')['LINUX-PREEMPTIBLE-UNPRIVILEGED']['disk_size_gb'])
    self.assertEqual(spec['fuzz', 'libfuzzer_asan_test'].disk_size_gb,
                     expected_size)

  def test_get_specs_from_config_with_disk_size_override(self):
    """Tests that disk_size_gb can be overridden by the job environment."""
    job_name = 'libfuzzer_asan_test'
    original_size = 75
    overridden_size = 200
    # First, create a job with the original disk size
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {original_size}\n',
        platform='LINUX',
        name=job_name).put()

    # Then override it by creating a new job with a larger disk size
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {overridden_size}\n',
        platform='LINUX',
        name=job_name).put()

    spec = batch._get_specs_from_config(
        [batch.BatchTask('fuzz', job_name, None)])
    self.assertEqual(spec['fuzz', job_name].disk_size_gb, overridden_size)


def _get_spec_from_config(command, job_name):
  return list(
      batch._get_specs_from_config([batch.BatchTask(command, job_name,
                                                    None)]).values())[0]
