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
"""Tests for the preprocess butler script."""

import unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler.scripts import preprocess


@test_utils.with_cloud_emulators('datastore')
class GetTaskRequisitesTest(unittest.TestCase):
  """Tests retrieving what each kind of task needs to be preprocessed."""

  def test_fuzz_returns_job_and_fuzzer(self):
    """Fuzz returns the given job and the fuzzer named by its argument."""
    data_types.Job(name='linux_asan_d8').put()
    data_types.Fuzzer(name='js_fuzzer').put()

    requisites = preprocess.get_task_requisites('fuzz', 'js_fuzzer',
                                                'linux_asan_d8')

    self.assertEqual('linux_asan_d8', requisites.job.name)
    self.assertEqual('js_fuzzer', requisites.fuzzer.name)

  def test_fuzz_with_unknown_fuzzer_raises(self):
    """Fuzz is rejected when no fuzzer has the name given as argument."""
    data_types.Job(name='linux_asan_d8').put()

    with self.assertRaises(preprocess.PreprocessError):
      preprocess.get_task_requisites('fuzz', 'js_fuzzer', 'linux_asan_d8')

  def test_corpus_pruning_returns_fuzz_target(self):
    """Corpus pruning looks its argument up as a fuzz target, not a fuzzer."""
    data_types.Job(name='libfuzzer_asan_v8').put()
    data_types.FuzzTarget(
        engine='libFuzzer', project='v8', binary='json_fuzzer').put()

    requisites = preprocess.get_task_requisites(
        'corpus_pruning', 'libFuzzer_v8_json_fuzzer', 'libfuzzer_asan_v8')

    self.assertEqual('json_fuzzer', requisites.fuzz_target.binary)
    self.assertIsNone(requisites.fuzzer)

  def test_fuzzer_based_task_without_job_raises(self):
    """A task with no testcase to take the job from is rejected without one."""
    data_types.Fuzzer(name='js_fuzzer').put()

    with self.assertRaises(preprocess.PreprocessError):
      preprocess.get_task_requisites('fuzz', 'js_fuzzer')

  def test_task_with_unknown_job_raises(self):
    """A task is rejected when the job to run it with is not in Datastore."""
    data_types.Fuzzer(name='js_fuzzer').put()

    with self.assertRaises(preprocess.PreprocessError):
      preprocess.get_task_requisites('fuzz', 'js_fuzzer', 'linux_asan_d8')

  def test_testcase_task_defaults_to_testcase_job(self):
    """A testcase task given no job runs with the job stored in its testcase."""
    data_types.Job(name='linux_asan_d8').put()
    testcase = data_types.Testcase(job_type='linux_asan_d8')
    testcase.put()

    requisites = preprocess.get_task_requisites('progression',
                                                str(testcase.key.id()))

    self.assertEqual('linux_asan_d8', requisites.job.name)
    self.assertEqual(testcase.key, requisites.testcase.key)

  def test_testcase_task_uses_given_job(self):
    """A testcase task given a job runs with it, not with its testcase's job."""
    data_types.Job(name='linux_asan_d8').put()
    data_types.Job(name='linux_msan_d8').put()
    testcase = data_types.Testcase(job_type='linux_asan_d8')
    testcase.put()

    requisites = preprocess.get_task_requisites('variant', str(
        testcase.key.id()), 'linux_msan_d8')

    self.assertEqual('linux_msan_d8', requisites.job.name)
    self.assertEqual(testcase.key, requisites.testcase.key)

  def test_testcase_task_with_unknown_testcase_raises(self):
    """A testcase task is rejected when no testcase has the id it was given."""
    data_types.Job(name='linux_asan_d8').put()

    with self.assertRaises(errors.InvalidTestcaseError):
      preprocess.get_task_requisites('minimize', '1337', 'linux_asan_d8')

  def test_analyze_on_uploaded_testcase_returns_testcase(self):
    """Analyze accepts a testcase that has upload metadata."""
    data_types.Job(name='linux_asan_d8').put()
    testcase = data_types.Testcase(job_type='linux_asan_d8')
    testcase.put()
    data_types.TestcaseUploadMetadata(testcase_id=testcase.key.id()).put()

    requisites = preprocess.get_task_requisites('analyze',
                                                str(testcase.key.id()))

    self.assertEqual(testcase.key, requisites.testcase.key)

  def test_analyze_on_fuzzer_found_testcase_raises(self):
    """Analyze is rejected on a testcase with no upload metadata, which its
    preprocess would delete."""
    data_types.Job(name='linux_asan_d8').put()
    testcase = data_types.Testcase(job_type='linux_asan_d8')
    testcase.put()

    with self.assertRaises(preprocess.PreprocessError):
      preprocess.get_task_requisites('analyze', str(testcase.key.id()))
