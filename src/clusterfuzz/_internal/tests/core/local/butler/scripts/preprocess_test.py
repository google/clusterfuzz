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

import argparse
import unittest
from unittest import mock

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
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


@test_utils.with_cloud_emulators('datastore')
class PreprocessTaskTest(unittest.TestCase):
  """Tests setting up the environment and running preprocess for a task."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_sets_task_payload_and_tworker_env_during_preprocess(self):
    """Sets TASK_PAYLOAD and tworker env vars during preprocess and removes
    TASK_PAYLOAD afterwards."""
    job = data_types.Job(name='linux_asan_d8', environment_string='JOB_VAR = 1')
    job.put()
    fuzzer = data_types.Fuzzer(name='js_fuzzer')
    fuzzer.put()
    requisites = preprocess.TaskRequisites(job=job, fuzzer=fuzzer)
    seen_env = {}

    def fake_tworker_preprocess(utask_module, task_argument, job_type,
                                uworker_env):
      seen_env['module'] = utask_module
      seen_env['task_argument'] = task_argument
      seen_env['job_type'] = job_type
      seen_env['uworker_env'] = uworker_env
      seen_env['task_payload'] = environment.get_value('TASK_PAYLOAD')
      seen_env['tworker'] = environment.get_value('TWORKER')
      seen_env['remote_utask_execution'] = environment.get_value(
          'REMOTE_UTASK_EXECUTION')
      seen_env['task_lease_seconds'] = environment.get_value(
          'TASK_LEASE_SECONDS')
      seen_env['bot_name'] = environment.get_value('BOT_NAME')
      seen_env['fail_wait'] = environment.get_value('FAIL_WAIT')
      seen_env['job_name'] = environment.get_value('JOB_NAME')
      return ('https://input', 'https://output')

    with mock.patch(
        'clusterfuzz._internal.bot.tasks.utasks.tworker_preprocess',
        side_effect=fake_tworker_preprocess):
      result = preprocess.preprocess_task('fuzz', 'js_fuzzer', job.name,
                                          requisites)

    self.assertEqual(('https://input', 'https://output'), result)
    self.assertIs(fuzz_task, seen_env['module'])
    self.assertEqual('js_fuzzer', seen_env['task_argument'])
    self.assertEqual('linux_asan_d8', seen_env['job_type'])
    self.assertEqual('fuzz js_fuzzer linux_asan_d8 None',
                     seen_env['task_payload'])
    self.assertTrue(seen_env['tworker'])
    self.assertTrue(seen_env['remote_utask_execution'])
    self.assertEqual(
        tasks.get_task_duration('fuzz'), seen_env['task_lease_seconds'])
    self.assertTrue(seen_env['bot_name'])
    self.assertIsNotNone(seen_env['fail_wait'])
    self.assertEqual('linux_asan_d8', seen_env['job_name'])
    self.assertEqual('1', seen_env['uworker_env']['JOB_VAR'])
    self.assertIsNone(environment.get_value('TASK_PAYLOAD'))


class ParseArgsTest(unittest.TestCase):
  """Tests parsing and validating grouped script arguments."""

  def test_fuzz_args(self):
    """Fuzz accepts --fuzzer and --job."""
    parsed = preprocess._parse_args(  # pylint: disable=protected-access
        ['--task', 'fuzz', '--fuzzer', 'js_fuzzer', '--job', 'linux_asan_d8'])

    self.assertEqual('fuzz', parsed.task)
    self.assertEqual('js_fuzzer', parsed.argument)
    self.assertEqual('linux_asan_d8', parsed.job)

  def test_corpus_pruning_args(self):
    """Corpus pruning accepts --fuzz-target and --job."""
    parsed = preprocess._parse_args([  # pylint: disable=protected-access
        '--task', 'corpus_pruning', '--fuzz-target', 'libFuzzer_v8_json_fuzzer',
        '--job', 'libfuzzer_asan_v8'
    ])

    self.assertEqual('corpus_pruning', parsed.task)
    self.assertEqual('libFuzzer_v8_json_fuzzer', parsed.argument)
    self.assertEqual('libfuzzer_asan_v8', parsed.job)

  def test_testcase_task_args_without_job(self):
    """Testcase tasks accept --testcase-id without --job."""
    parsed = preprocess._parse_args(  # pylint: disable=protected-access
        ['--task', 'progression', '--testcase-id', '12345'])

    self.assertEqual('progression', parsed.task)
    self.assertEqual('12345', parsed.argument)
    self.assertIsNone(parsed.job)

  def test_testcase_task_args_with_job(self):
    """Testcase tasks accept an optional --job override."""
    parsed = preprocess._parse_args([  # pylint: disable=protected-access
        '--task', 'variant', '--testcase-id', '12345', '--job', 'linux_msan_d8'
    ])

    self.assertEqual('variant', parsed.task)
    self.assertEqual('12345', parsed.argument)
    self.assertEqual('linux_msan_d8', parsed.job)

  def test_missing_required_target_flag_rejected(self):
    """Missing the task's required target flag exits with an error."""
    for argv in (
        ['--task', 'fuzz', '--job', 'linux_asan_d8'],
        ['--task', 'corpus_pruning', '--job', 'libfuzzer_asan_v8'],
        ['--task', 'minimize'],
    ):
      with self.subTest(argv=argv), self.assertRaises(SystemExit):
        preprocess._parse_args(argv)  # pylint: disable=protected-access

  def test_missing_required_job_rejected(self):
    """Fuzz and corpus_pruning without --job exit with an error."""
    for argv in (
        ['--task', 'fuzz', '--fuzzer', 'js_fuzzer'],
        ['--task', 'corpus_pruning', '--fuzz-target', 'libFuzzer_v8_json'],
    ):
      with self.subTest(argv=argv), self.assertRaises(SystemExit):
        preprocess._parse_args(argv)  # pylint: disable=protected-access

  def test_mismatched_target_flag_rejected(self):
    """Passing a target flag belonging to another task group is rejected."""
    for argv in (
        ['--task', 'fuzz', '--testcase-id', '12345', '--job', 'linux_asan_d8'],
        [
            '--task', 'fuzz', '--fuzzer', 'js_fuzzer', '--testcase-id', '12345',
            '--job', 'linux_asan_d8'
        ],
        [
            '--task', 'corpus_pruning', '--fuzzer', 'js_fuzzer', '--job',
            'libfuzzer_asan_v8'
        ],
        ['--task', 'progression', '--fuzzer', 'js_fuzzer'],
    ):
      with self.subTest(argv=argv), self.assertRaises(SystemExit):
        preprocess._parse_args(argv)  # pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class ExecuteTest(unittest.TestCase):
  """Tests the butler execute entrypoint dry-run guard."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.configure',
        'local.butler.scripts.preprocess.preprocess_task',
    ])

  def test_dry_run_skips_preprocess_task(self):
    """Validates requisites without running preprocess when --non-dry-run is
    omitted."""
    data_types.Job(name='linux_asan_d8').put()
    data_types.Fuzzer(name='js_fuzzer').put()
    args = argparse.Namespace(
        non_dry_run=False,
        script_args=[
            '--task', 'fuzz', '--fuzzer', 'js_fuzzer', '--job', 'linux_asan_d8'
        ])

    preprocess.execute(args)

    self.mock.preprocess_task.assert_not_called()

  def test_non_dry_run_executes_preprocess_task(self):
    """Runs preprocess_task when --non-dry-run is passed."""
    data_types.Job(name='linux_asan_d8').put()
    data_types.Fuzzer(name='js_fuzzer').put()
    self.mock.preprocess_task.return_value = ('https://in', 'https://out')
    args = argparse.Namespace(
        non_dry_run=True,
        script_args=[
            '--task', 'fuzz', '--fuzzer', 'js_fuzzer', '--job', 'linux_asan_d8'
        ])

    preprocess.execute(args)

    self.mock.preprocess_task.assert_called_once()
