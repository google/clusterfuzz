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
"""Tests for schedule_corpus_pruning."""

import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import schedule_corpus_pruning


@test_utils.with_cloud_emulators('datastore')
class ScheduleCorpusPruningTest(unittest.TestCase):
  """Tests for schedule_corpus_pruning."""

  def setUp(self):
    helpers.patch_environ(self)

    # Two fuzz targets with two jobs enabled, one with and one without pruning.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer_1', project='project_1').put()
    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer_2', project='project_1').put()

    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_1',
        engine='libFuzzer',
        job='continuous_fuzzing_job_with_pruning').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_2',
        engine='libFuzzer',
        job='continuous_fuzzing_job_with_pruning').put()
    data_types.Job(
        name='continuous_fuzzing_job_with_pruning',
        platform='LINUX',
        environment_string=('CORPUS_PRUNE = True\n'
                            'RELEASE_BUILD_BUCKET_PATH=DOES_NOT_MATTER')).put()

    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_1',
        engine='libFuzzer',
        job='continuous_fuzzing_job_without_pruning').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_2',
        engine='libFuzzer',
        job='continuous_fuzzing_job_without_pruning').put()
    data_types.Job(
        name='continuous_fuzzing_job_without_pruning',
        platform='LINUX',
        environment_string=('CORPUS_PRUNE = False\n'
                            'RELEASE_BUILD_BUCKET_PATH=DOES_NOT_MATTER')).put()

    # Two fuzz targets with two CUSTOM_BINARY jobs, with and without pruning.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer_a', project='project_1').put()
    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer_b', project='project_1').put()

    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_a',
        engine='libFuzzer',
        job='custom_binary_job_with_pruning').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_b',
        engine='libFuzzer',
        job='custom_binary_job_with_pruning').put()
    data_types.Job(
        name='custom_binary_job_with_pruning',
        platform='LINUX',
        environment_string=('CORPUS_PRUNE = True\n'
                            'CUSTOM_BINARY = True')).put()

    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_a',
        engine='libFuzzer',
        job='custom_binary_job_without_pruning').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer_b',
        engine='libFuzzer',
        job='custom_binary_job_without_pruning').put()
    data_types.Job(
        name='custom_binary_job_without_pruning',
        platform='LINUX',
        environment_string=('CORPUS_PRUNE = False\n'
                            'CUSTOM_BINARY = True')).put()

  def test_schedule_corpus_pruning(self):
    """Test schedule_corpus_pruning.Handler.."""
    tasks = schedule_corpus_pruning.get_tasks_to_schedule()
    tasks_expected = [('libFuzzer_test_fuzzer_1',
                       'continuous_fuzzing_job_with_pruning', 'jobs-linux'),
                      ('libFuzzer_test_fuzzer_2',
                       'continuous_fuzzing_job_with_pruning', 'jobs-linux'),
                      ('libFuzzer_test_fuzzer_a',
                       'custom_binary_job_with_pruning', 'jobs-linux'),
                      ('libFuzzer_test_fuzzer_b',
                       'custom_binary_job_with_pruning', 'jobs-linux')]

    for i, actual_value in enumerate(tasks):
      # Cannot assert all values at once as `tasks` is a generator, not a list.
      self.assertEqual(tasks_expected[i], actual_value)
