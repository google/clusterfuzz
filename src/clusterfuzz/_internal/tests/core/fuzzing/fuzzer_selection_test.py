# Copyright 2019 Google LLC
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
"""Tests for fuzzer_selection.py."""

import os
import unittest

import parameterized

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _get_job_list_for_fuzzer(fuzzer):
  """Helper function to return the mappings for a fuzzer as a list."""
  query = data_types.FuzzerJob.query()
  query.filter(data_types.FuzzerJob.fuzzer == fuzzer.name)
  return [m.job for m in ndb_utils.get_all_from_query(query)]


def _get_fuzzer_list_for_job(job):
  """Helper function to return the mappings for a job as a list."""
  fuzzers = data_types.Fuzzer.query().filter(data_types.Fuzzer.jobs == job.name)
  return [fuzzer.name for fuzzer in fuzzers]


@test_utils.with_cloud_emulators('datastore')
class UpdateMappingsForFuzzerTest(unittest.TestCase):
  """Tests for the update_mappings_for_fuzzer function."""

  def setUp(self):
    job_1 = data_types.Job()
    job_1.name = 'job_1'
    job_1.environment_string = 'test = 1'
    job_1.put()

    job_2 = data_types.Job()
    job_2.name = 'job_2'
    job_2.environment_string = 'test = 2'
    job_2.put()

  def test_no_mappings(self):
    """Ensure that we do nothing if a fuzzer has no mappings."""
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'no_mappings'
    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    self.assertEqual(_get_job_list_for_fuzzer(fuzzer), [])

  def test_new_addition(self):
    """Ensure that we add mappings for a new fuzzer."""
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'new_addition'
    fuzzer.jobs = ['job_1', 'job_2']
    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertIn('job_1', mappings)
    self.assertIn('job_2', mappings)

  def test_mapping_added(self):
    """Ensure that we properly add mappings for existing fuzzers."""
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'adding_jobs'
    fuzzer.jobs = ['job_1']
    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertIn('job_1', mappings)
    self.assertNotIn('job_2', mappings)

    fuzzer.jobs += ['job_2']
    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertIn('job_1', mappings)
    self.assertIn('job_2', mappings)

  def test_mapping_subsituted(self):
    """Ensure that mappings are subsituted properly."""
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'adding_jobs'
    fuzzer.jobs = ['job_1']
    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertIn('job_1', mappings)
    self.assertNotIn('job_2', mappings)

    fuzzer.jobs = ['job_2']
    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertNotIn('job_1', mappings)
    self.assertIn('job_2', mappings)

  def test_mapping_removed(self):
    """Ensure that mappings are removed properly."""
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'adding_jobs'
    fuzzer.jobs = ['job_1']
    fuzzer.put()

    fuzzer_selection.update_mappings_for_fuzzer(fuzzer, [])

    mappings = _get_job_list_for_fuzzer(fuzzer)
    self.assertEqual([], mappings)


@test_utils.with_cloud_emulators('datastore')
class UpdateMappingsForJobTest(unittest.TestCase):
  """Tests for the update_mappings_for_job function."""

  def setUp(self):
    self.fuzzer_1 = data_types.Fuzzer()
    self.fuzzer_1.name = 'fuzzer_1'
    self.fuzzer_1.put()

    self.fuzzer_2 = data_types.Fuzzer()
    self.fuzzer_2.name = 'fuzzer_2'
    self.fuzzer_2.put()

  def test_no_mappings(self):
    """Ensure that we do nothing if a job has no mappings."""
    job = data_types.Job()
    job.name = 'no_mappings'
    job.put()

    fuzzer_selection.update_mappings_for_job(job, [])

    self.assertEqual(_get_fuzzer_list_for_job(job), [])

  def test_new_addition(self):
    """Ensure that we add mappings for a new job."""
    job = data_types.Job()
    job.name = 'new_addition'
    job.put()

    fuzzer_selection.update_mappings_for_job(job, ['fuzzer_1', 'fuzzer_2'])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertIn('fuzzer_1', mappings)
    self.assertIn('fuzzer_2', mappings)

  def test_mapping_added(self):
    """Ensure that we properly add mappings for existing jobs."""
    job = data_types.Job()
    job.name = 'adding_fuzzers'
    job.put()

    fuzzer_selection.update_mappings_for_job(job, ['fuzzer_1'])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertIn('fuzzer_1', mappings)
    self.assertNotIn('fuzzer_2', mappings)

    fuzzer_selection.update_mappings_for_job(job, ['fuzzer_1', 'fuzzer_2'])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertIn('fuzzer_1', mappings)
    self.assertIn('fuzzer_2', mappings)

  def test_mapping_substituted(self):
    """Ensure that mappings are substituted properly."""
    job = data_types.Job()
    job.name = 'substitute_fuzzers'
    job.put()

    fuzzer_selection.update_mappings_for_job(job, ['fuzzer_1'])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertIn('fuzzer_1', mappings)
    self.assertNotIn('fuzzer_2', mappings)

    fuzzer_selection.update_mappings_for_job(job, ['fuzzer_2'])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertNotIn('fuzzer_1', mappings)
    self.assertIn('fuzzer_2', mappings)

  def test_mapping_removed(self):
    """Ensure that mappings are removed properly."""
    job = data_types.Job()
    job.name = 'remove_fuzzer'
    job.put()

    self.fuzzer_1.jobs.append('remove_fuzzer')
    self.fuzzer_1.put()

    fuzzer_selection.update_mappings_for_job(job, [])

    mappings = _get_fuzzer_list_for_job(job)
    self.assertEqual([], mappings)


def _mock_random_weighted_choice(items, weight_attribute='weight'):  # pylint: disable=unused-argument
  """Mock random_weighted_choice."""
  # Always select the first element rather than a random one for the sake of
  # determinism.
  return items[0]


@test_utils.with_cloud_emulators('datastore')
class GetFuzzTaskPayloadTest(unittest.TestCase):
  """Tests for the get_fuzz_task_payload function."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.random_weighted_choice',
    ])

    self.mock.random_weighted_choice.side_effect = _mock_random_weighted_choice

  def test_no_mappings(self):
    """Ensure that we raise an exception if we don't find a task."""
    self.assertEqual(
        (None, None), fuzzer_selection.get_fuzz_task_payload(platform='linux'))

  @parameterized.parameterized.expand([('False',), ('True',)])
  def test_platform_restriction(self, local_development):
    """Ensure that we can find a task with a valid platform."""
    os.environ['LOCAL_DEVELOPMENT'] = local_development
    windows_mapping = data_types.FuzzerJob()
    windows_mapping.fuzzer = 'wrong_fuzzer'
    windows_mapping.job = 'job_1'
    windows_mapping.platform = 'windows'
    windows_mapping.put()

    data_types.FuzzerJobs(
        platform='windows', fuzzer_jobs=[windows_mapping]).put()

    self.assertEqual(
        (None, None), fuzzer_selection.get_fuzz_task_payload(platform='linux'))

    linux_mapping = data_types.FuzzerJob()
    linux_mapping.fuzzer = 'right_fuzzer'
    linux_mapping.job = 'job_2'
    linux_mapping.platform = 'linux'
    linux_mapping.put()

    data_types.FuzzerJobs(platform='linux', fuzzer_jobs=[linux_mapping]).put()

    argument, job = fuzzer_selection.get_fuzz_task_payload('linux')
    self.assertEqual(('right_fuzzer', 'job_2'), (argument, job))


@test_utils.with_cloud_emulators('datastore')
class UpdatePlatformForJobTest(unittest.TestCase):
  """Tests for update_platform_for_job."""

  def test_jobs_updated(self):
    """Ensure that we properly update multiple jobs."""
    fuzzer_1_mapping = data_types.FuzzerJob()
    fuzzer_1_mapping.fuzzer = 'fuzzer_1'
    fuzzer_1_mapping.job = 'test_job'
    fuzzer_1_mapping.platform = 'wrong_platform'
    fuzzer_1_mapping.put()

    fuzzer_2_mapping = data_types.FuzzerJob()
    fuzzer_2_mapping.fuzzer = 'fuzzer_2'
    fuzzer_2_mapping.job = 'test_job'
    fuzzer_2_mapping.platform = 'wrong_platform'
    fuzzer_2_mapping.put()

    fuzzer_selection.update_platform_for_job('test_job', 'right_platform')

    platforms = [
        job.platform
        for job in ndb_utils.get_all_from_model(data_types.FuzzerJob)
    ]
    self.assertListEqual(platforms, ['right_platform', 'right_platform'])

  def test_unrelated_job_not_updated(self):
    """Ensure that we only update platform for the specified job's mappings."""
    fuzzer_1_mapping = data_types.FuzzerJob()
    fuzzer_1_mapping.fuzzer = 'fuzzer_1'
    fuzzer_1_mapping.job = 'test_job'
    fuzzer_1_mapping.platform = 'wrong_platform'
    fuzzer_1_mapping.put()

    fuzzer_2_mapping = data_types.FuzzerJob()
    fuzzer_2_mapping.fuzzer = 'fuzzer_2'
    fuzzer_2_mapping.job = 'unrelated_job'
    fuzzer_2_mapping.platform = 'unrelated_platform'
    fuzzer_2_mapping.put()

    fuzzer_selection.update_platform_for_job('test_job', 'right_platform')

    query = data_types.FuzzerJob.query()
    query = query.filter(data_types.FuzzerJob.fuzzer == 'fuzzer_2')
    fuzzer_2_mapping = query.get()

    self.assertEqual(fuzzer_2_mapping.platform, 'unrelated_platform')


class SelectFuzzTargetTest(unittest.TestCase):
  """Tests for select_fuzz_target."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.random_weighted_choice',
    ])

    self.mock.random_weighted_choice.side_effect = lambda x: x[0]

  def test_empty_weights(self):
    """Ensure that we select with even weights if none are specified."""
    fuzzer_selection.select_fuzz_target(['target_0', 'target_1'], {})

    expected_target_0 = fuzzer_selection.WeightedTarget('target_0', 1.0)
    expected_target_1 = fuzzer_selection.WeightedTarget('target_1', 1.0)
    self.mock.random_weighted_choice.assert_called_once_with(
        [expected_target_0, expected_target_1])

  def test_weights_for_some_targets(self):
    """Ensure that we use weights we applicable, and defaults where not."""
    fuzzer_selection.select_fuzz_target(
        ['weighted_0', 'weighted_1', 'unweighted_0'], {
            'weighted_0': 2.0,
            'weighted_1': 0.5
        })

    expected_weighted_0 = fuzzer_selection.WeightedTarget('weighted_0', 2.0)
    expected_weighted_1 = fuzzer_selection.WeightedTarget('weighted_1', 0.5)
    expected_unweighted_0 = fuzzer_selection.WeightedTarget('unweighted_0', 1.0)

    self.mock.random_weighted_choice.assert_called_once_with(
        [expected_weighted_0, expected_weighted_1, expected_unweighted_0])


@test_utils.with_cloud_emulators('datastore')
class GetFuzzTargetWeightsTest(unittest.TestCase):
  """Tests for get_fuzz_target_weights."""

  def setUp(self):
    test_helpers.patch_environ(self)

    data_types.FuzzTarget(
        engine='engine',
        project='proj',
        binary='child_0',
    ).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='engine_proj_child_0',
        engine='engine',
        job='some_job_engine',
        weight=1.5,
    ).put()

    data_types.FuzzTarget(
        engine='engine',
        project='proj',
        binary='child_1',
    ).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='engine_proj_child_1',
        engine='engine',
        job='some_job_engine',
        weight=0.75,
    ).put()

    data_types.FuzzTarget(
        engine='different_fuzzer',
        binary='child_2',
        project='test-project',
    ).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='different_fuzzer_child_2',
        engine='different_fuzzer',
        job='some_job_different_fuzzer',
        weight=3.0,
    ).put()

  def test_empty_if_no_children(self):
    """Ensure that we function properly if a fuzzer has no children."""
    os.environ['TASK_NAME'] = 'fuzz'
    os.environ['JOB_NAME'] = 'some_job_blackbox'

    result = fuzzer_selection.get_fuzz_target_weights()

    self.assertEqual(result, {})

  def test_weights_specified_for_children(self):
    """Ensure that we return the correct weights for a fuzzer with children."""
    os.environ['TASK_NAME'] = 'fuzz'
    os.environ['JOB_NAME'] = 'some_job_engine'

    result = fuzzer_selection.get_fuzz_target_weights()

    self.assertEqual(result, {'child_0': 1.5, 'child_1': 0.75})
