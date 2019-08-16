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
"""Tests for corpus_pruning_task."""
# pylint: disable=unused-argument
import mock
import os
import shutil
import tempfile
import unittest

from base import utils
from bot.tasks import minimize_task
from datastore import data_handler
from datastore import data_types
from google_cloud_utils import blobs
from system import environment
from tests.test_libs import helpers
from tests.test_libs import test_utils
from tests.test_libs import untrusted_runner_helpers

TEST_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'minimize_task_data')


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class LibFuzzerMinimizeTaskTest(unittest.TestCase):
  """libFuzzer Minimize task tests."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'bot.tasks.minimize_task._run_libfuzzer_testcase',
        'bot.tasks.minimize_task._run_libfuzzer_tool',
    ])

    test_utils.setup_pubsub(utils.get_application_id())

    environment.set_value('APP_ARGS', '%TESTCASE% fuzz_target')
    environment.set_value('APP_DIR', '/libfuzzer')
    environment.set_value('APP_NAME', 'launcher.py')
    environment.set_value('APP_PATH', '/libfuzzer/launcher.py')
    environment.set_value('BOT_TMPDIR', '/bot_tmpdir')
    environment.set_value('CRASH_STACKTRACES_DIR', '/crash_stacks')
    environment.set_value('FUZZER_DIR', '/fuzzer_dir')
    environment.set_value('INPUT_DIR', '/input_dir')
    environment.set_value('JOB_NAME', 'libfuzzer_asan_test')
    environment.set_value('USER_PROFILE_IN_MEMORY', True)

  def test_libfuzzer_skip_minimization_initial_crash_state(self):
    """Test libFuzzer minimization skipping with a valid initial crash state."""
    # TODO(ochang): Fix circular import.
    from crash_analysis.crash_result import CrashResult

    testcase = data_types.Testcase(
        minimized_keys='',
        fuzzed_keys='FUZZED_KEY',
        job_type='libfuzzer_asan_job',
        security_flag=True)
    testcase.put()

    stacktrace = (
        '==14970==ERROR: AddressSanitizer: heap-buffer-overflow on address '
        '0x61b00001f7d0 at pc 0x00000064801b bp 0x7ffce478dbd0 sp '
        '0x7ffce478dbc8 READ of size 4 at 0x61b00001f7d0 thread T0\n'
        '#0 0x64801a in frame0() src/test.cpp:1819:15\n'
        '#1 0x647ac5 in frame1() src/test.cpp:1954:25\n'
        '#2 0xb1dee7 in frame2() src/test.cpp:160:9\n'
        '#3 0xb1ddd8 in frame3() src/test.cpp:148:34\n')
    self.mock._run_libfuzzer_testcase.return_value = CrashResult(  # pylint: disable=protected-access
        1, 1.0, stacktrace)

    self.mock._run_libfuzzer_tool.return_value = (None, None)  # pylint: disable=protected-access

    minimize_task.do_libfuzzer_minimization(testcase, '/testcase_file_path')

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertEqual('Heap-buffer-overflow', testcase.crash_type)
    self.assertEqual('frame0\nframe1\nframe2\n', testcase.crash_state)
    self.assertEqual('0x61b00001f7d0', testcase.crash_address)
    self.assertEqual(
        '[Command line] python /libfuzzer/launcher.py /testcase_file_path '
        'fuzz_target\n\n'
        '+----------------------------------------Release Build Stacktrace'
        '----------------------------------------+\n%s' % stacktrace,
        testcase.crash_stacktrace)


class MinimizeTaskTestUntrusted(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Minimize task tests for untrusted."""

  def setUp(self):
    """Set up."""
    super(MinimizeTaskTestUntrusted, self).setUp()
    environment.set_value('JOB_NAME', 'libfuzzer_asan_job')

    helpers.patch(self, [
        'datastore.data_handler.get_data_bundle_bucket_name',
    ])

    patcher = mock.patch(
        'bot.fuzzers.libFuzzer.fuzzer.LibFuzzer.fuzzer_directory',
        new_callable=mock.PropertyMock)

    mock_fuzzer_directory = patcher.start()
    self.addCleanup(patcher.stop)

    mock_fuzzer_directory.return_value = os.path.join(
        environment.get_value('ROOT_DIR'), 'src', 'python', 'bot', 'fuzzers',
        'libFuzzer')

    job = data_types.Job(
        name='libfuzzer_asan_job',
        environment_string=(
            'APP_NAME = launcher.py\n'
            'RELEASE_BUILD_BUCKET_PATH = '
            'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-([0-9]+).zip\n'
            'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
            'clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-%s.srcmap.json\n'))
    job.put()

    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer', project='test-project')
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer',
        engine='libFuzzer',
        job='libfuzzer_asan_job')

    environment.set_value('USE_MINIJAIL', True)
    data_types.Fuzzer(
        revision=1,
        file_size='builtin',
        source='builtin',
        name='libFuzzer',
        max_testcases=4,
        builtin=True).put()
    self.temp_dir = tempfile.mkdtemp(dir=environment.get_value('FUZZ_INPUTS'))

  def tearDown(self):
    super(MinimizeTaskTestUntrusted, self).tearDown()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_minimize(self):
    """Test minimize."""
    testcase_file_path = os.path.join(self.temp_dir, 'testcase')
    with open(testcase_file_path, 'wb') as f:
      f.write('EEE')

    with open(testcase_file_path) as f:
      fuzzed_keys = blobs.write_blob(f)

    testcase_path = os.path.join(self.temp_dir, 'testcase')

    testcase = data_types.Testcase(
        crash_type='Null-dereference WRITE',
        crash_address='',
        crash_state='Foo\n',
        crash_stacktrace='',
        crash_revision=1337,
        fuzzed_keys=fuzzed_keys,
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_test_fuzzer',
        job_type='libfuzzer_asan_job',
        original_absolute_path=testcase_path,
        absolute_path=testcase_path,
        minimized_arguments='%TESTCASE% test_fuzzer')
    testcase.put()

    self._setup_env(job_type='libfuzzer_asan_job')
    environment.set_value('APP_ARGS', testcase.minimized_arguments)
    environment.set_value('LIBFUZZER_MINIMIZATION_ROUNDS', 3)
    minimize_task.execute_task(testcase.key.id(), 'libfuzzer_asan_job')

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertNotEqual('', testcase.minimized_keys)
    self.assertNotEqual('NA', testcase.minimized_keys)
    self.assertNotEqual(testcase.fuzzed_keys, testcase.minimized_keys)

    blobs.read_blob_to_disk(testcase.minimized_keys, testcase_path)

    with open(testcase_path) as f:
      self.assertEqual(1, len(f.read()))
