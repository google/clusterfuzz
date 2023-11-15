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
import os
import shutil
import tempfile
import unittest
# pylint: disable=unused-argument
from unittest import mock

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import init as fuzzers_init
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks.utasks import minimize_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import untrusted_runner_helpers

TEST_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'minimize_task_data')


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class LibFuzzerMinimizeTaskTest(unittest.TestCase):
  """libFuzzer Minimize task tests."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task._run_libfuzzer_testcase',
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task._run_libfuzzer_tool',
    ])

    test_utils.setup_pubsub(utils.get_application_id())

    environment.set_value('APP_ARGS', '%TESTCASE% fuzz_target')
    environment.set_value('APP_DIR', '/libfuzzer')
    environment.set_value('APP_NAME', '')
    environment.set_value('APP_PATH', '')
    environment.set_value('BOT_TMPDIR', '/bot_tmpdir')
    environment.set_value('CRASH_STACKTRACES_DIR', '/crash_stacks')
    environment.set_value('FUZZER_DIR', '/fuzzer_dir')
    environment.set_value('INPUT_DIR', '/input_dir')
    environment.set_value('JOB_NAME', 'libfuzzer_asan_test')
    environment.set_value('USER_PROFILE_IN_MEMORY', True)

  def test_libfuzzer_skip_minimization_initial_crash_state(self):
    """Test libFuzzer minimization skipping with a valid initial crash state."""
    # TODO(ochang): Fix circular import.
    from clusterfuzz._internal.crash_analysis.crash_result import CrashResult

    data_types.Job(name='libfuzzer_asan_job').put()
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
        '+----------------------------------------Release Build Stacktrace'
        '----------------------------------------+\n%s' % stacktrace,
        testcase.crash_stacktrace)


class MinimizeTaskTestUntrusted(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Minimize task tests for untrusted."""

  def setUp(self):
    """Set up."""
    super().setUp()
    environment.set_value('JOB_NAME', 'libfuzzer_asan_job')

    patcher = mock.patch(
        'clusterfuzz._internal.bot.fuzzers.libFuzzer.fuzzer.LibFuzzer.fuzzer_directory',
        new_callable=mock.PropertyMock)

    mock_fuzzer_directory = patcher.start()
    self.addCleanup(patcher.stop)

    mock_fuzzer_directory.return_value = os.path.join(
        environment.get_value('ROOT_DIR'), 'src', 'clusterfuzz', '_internal',
        'bot', 'fuzzers', 'libFuzzer')

    job = data_types.Job(
        name='libfuzzer_asan_job',
        environment_string=(
            'RELEASE_BUILD_BUCKET_PATH = '
            'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-([0-9]+).zip\n'
            'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
            'clusterfuzz-test-data/test_libfuzzer_builds/'
            'test-libfuzzer-build-%s.srcmap.json\n'))
    job.put()

    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer',
        engine='libFuzzer',
        job='libfuzzer_asan_job').put()

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
    super().tearDown()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_minimize(self):
    """Test minimize."""
    helpers.patch(self, ['clusterfuzz._internal.base.utils.is_oss_fuzz'])
    self.mock.is_oss_fuzz.return_value = True

    testcase_file_path = os.path.join(self.temp_dir, 'testcase')
    with open(testcase_file_path, 'wb') as f:
      f.write(b'EEE')

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
        absolute_path=testcase_path,
        minimized_arguments='%TESTCASE% test_fuzzer')
    testcase.put()

    data_types.FuzzTarget(engine='libFuzzer', binary='test_fuzzer').put()

    fuzzers_init.run()

    self._setup_env(job_type='libfuzzer_asan_job')
    environment.set_value('APP_ARGS', testcase.minimized_arguments)
    environment.set_value('LIBFUZZER_MINIMIZATION_ROUNDS', 3)
    environment.set_value('UBSAN_OPTIONS',
                          'unneeded_option=1:silence_unsigned_overflow=1')
    setup_input = setup.preprocess_setup_testcase(testcase)
    uworker_input = uworker_io.DeserializedUworkerMsg(
        job_type='libfuzzer_asan_job',
        testcase=testcase,
        setup_input=setup_input,
        testcase_id=str(testcase.key.id()))
    minimize_task.utask_main(uworker_input)

    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertNotEqual('', testcase.minimized_keys)
    self.assertNotEqual('NA', testcase.minimized_keys)
    self.assertNotEqual(testcase.fuzzed_keys, testcase.minimized_keys)
    self.assertEqual({
        'ASAN_OPTIONS': {},
        'UBSAN_OPTIONS': {
            'silence_unsigned_overflow': 1
        }
    }, testcase.get_metadata('env'))

    blobs.read_blob_to_disk(testcase.minimized_keys, testcase_path)

    with open(testcase_path, 'rb') as f:
      self.assertEqual(1, len(f.read()))


class ExtractCrashResultTest(unittest.TestCase):
  """Test _extract_crash_result."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task.CrashResult.get_stacktrace',
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task.CrashResult.get_symbolized_data',
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task.data_handler.filter_stacktrace',
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task.utils.get_crash_stacktrace_output',
    ])

  def test_nonnull_crash_result_returns(self):
    """Test a expected crash result input is extracted as expected."""
    from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
    from clusterfuzz.stacktraces import CrashInfo
    stacktrace = (
        '==14970==ERROR: AddressSanitizer: heap-buffer-overflow on address '
        '0x61b00001f7d0 at pc 0x00000064801b bp 0x7ffce478dbd0 sp '
        '0x7ffce478dbc8 READ of size 4 at 0x61b00001f7d0 thread T0\n'
        '#0 0x64801a in frame0() src/test.cpp:1819:15\n'
        '#1 0x647ac5 in frame1() src/test.cpp:1954:25\n'
        '#2 0xb1dee7 in frame2() src/test.cpp:160:9\n'
        '#3 0xb1ddd8 in frame3() src/test.cpp:148:34\n')
    crash_result = CrashResult(1, 1.1, stacktrace)
    mock_min_state = CrashInfo()
    mock_min_state.crash_type = 'Heap-buffer-overflow'
    mock_min_state.crash_address = '0x61b00001f7d0'
    mock_min_state.crash_state = 'frame0\nframe1\nframe2\n'
    mock_min_state.crash_stacktrace = \
      '+----------------------------------------Release Build Stacktrace' \
      '----------------------------------------+\n%s' % stacktrace
    filtered_stacktrace = mock_min_state.crash_stacktrace

    self.mock.get_stacktrace.return_value = None  # This return value does not matter
    self.mock.get_crash_stacktrace_output.return_value = None  # This return value does not matter
    self.mock.get_symbolized_data.return_value = mock_min_state
    self.mock.filter_stacktrace.return_value = filtered_stacktrace
    command = ''  # This value does not matter
    expected = {
        'crash_type': 'Heap-buffer-overflow',
        'crash_address': '0x61b00001f7d0',
        'crash_state': 'frame0\nframe1\nframe2\n',
        'crash_stacktrace':
            '+----------------------------------------Release Build Stacktrace'
            '----------------------------------------+\n%s' % stacktrace,
    }
    self.assertEqual(expected,
                     minimize_task._extract_crash_result(crash_result, command))  # pylint: disable=protected-access

  def test_null_crash_result_raises_error(self):
    """Test a null crash result input raises an error as expected."""
    crash_result = None
    command = ''

    with self.assertRaises(errors.BadStateError):
      minimize_task._extract_crash_result(crash_result, command)  # pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class UTaskPostprocessTest(unittest.TestCase):
  """Tests for utask_postprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.utasks.minimize_task.finalize_testcase',
    ])

  def _get_generic_input(self):
    testcase = data_types.Testcase()
    uworker_input = uworker_io.UworkerInput(
        job_type='job_type', testcase_id='testcase_id', testcase=testcase)
    uworker_input = uworker_io.serialize_uworker_input(uworker_input)
    uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
    return uworker_input

  def _create_output(self, uworker_input=None, **kwargs):
    uworker_output = uworker_io.UworkerOutput(**kwargs)
    uworker_output = uworker_io.serialize_uworker_output(uworker_output)
    uworker_output = uworker_io.deserialize_uworker_output(uworker_output)
    if uworker_input:
      uworker_output.uworker_input = uworker_input
    return uworker_output

  def test_error_does_not_finalize_testcase(self):
    """Checks that an output with an error does not finalize a testcase."""
    uworker_output = self._create_output(
        error_type=uworker_msg_pb2.ErrorType.UNHANDLED)
    minimize_task.utask_postprocess(uworker_output)
    self.assertFalse(self.mock.finalize_testcase.called)

  def test_generic_output_finalizes_testcase(self):
    """Checks that an output with all critical fields finalizes a testcase."""
    self.mock.finalize_testcase.return_value = None
    last_crash_result_dict = {'crash_type': 'placeholder'}
    minimize_task_output = uworker_io.MinimizeTaskOutput(
        last_crash_result_dict=last_crash_result_dict)
    uworker_output = self._create_output(
        uworker_input=self._get_generic_input(),
        minimize_task_output=minimize_task_output)

    minimize_task.utask_postprocess(uworker_output)

    self.assertTrue(self.mock.finalize_testcase.called)


@test_utils.with_cloud_emulators('datastore')
class UTaskMainTest(unittest.TestCase):
  """Tests for minimize_worker.UTaskMain."""

  def setUp(self):
    helpers.patch_environ(self)

  @mock.patch(
      'clusterfuzz._internal.build_management.build_manager.check_app_path',
      return_value=False)
  @mock.patch(
      'clusterfuzz._internal.build_management.build_manager.setup_build')
  @mock.patch('clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase')
  @mock.patch('clusterfuzz._internal.bot.tasks.setup.setup_testcase')
  def test_check_app_path_exit(self, setup_testcase, preprocess_setup_testcase,
                               setup_build, check_app_path):
    """Tests that the path taken when check_app_path returns False, works as
    expected."""
    preprocess_setup_testcase.return_value = None
    setup_testcase.return_value = ([], '/path', None)
    del setup_build
    del check_app_path
    testcase = data_types.Testcase()
    testcase.put()
    build_fail_wait = 10
    environment.set_value('FAIL_WAIT', 10)
    uworker_input = uworker_io.UworkerInput(testcase=testcase)
    uworker_input = uworker_io.serialize_uworker_input(uworker_input)
    uworker_input = uworker_io.deserialize_uworker_input(uworker_input)
    uworker_output = minimize_task.utask_main(uworker_input)
    uworker_output = uworker_io.serialize_uworker_output(uworker_output)
    uworker_output = uworker_io.deserialize_uworker_output(uworker_output)
    self.assertEqual(uworker_output.minimize_task_output.build_fail_wait,
                     build_fail_wait)
    self.assertEqual(uworker_output.error_type,
                     uworker_msg_pb2.ErrorType.MINIMIZE_SETUP)
