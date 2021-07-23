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
"""Test the launcher.py script for AFL-based fuzzers."""
# pylint: disable=protected-access

from functools import partial
import os

import mock
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.afl import fuzzer
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.core.bot.fuzzers.engine_common_test import \
    GetTimeoutTestBase
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class LauncherTestBase(fake_filesystem_unittest.TestCase):
  """Provides common functionality used by TestCases for launcher.py."""
  INPUT_DIR = '/inputdir'
  TARGET_PATH = '/target'
  TARGET_OPTIONS_PATH = TARGET_PATH + '.options'
  TEMP_DIR = '/tmp'
  BUILD_DIR = '/build'
  OUTPUT_DIR = '/tmp/afl_output_dir'
  CRASHES_DIR = '/tmp/afl_output_dir/default/crashes'
  DEFAULT_INPUT_DIR_CONTENTS = [fuzzer.AFL_DUMMY_INPUT]
  DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

  def setUp(self):
    """Setup for launcher test base."""
    test_helpers.patch_environ(self)
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['BUILD_DIR'] = self.BUILD_DIR

    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir(self.INPUT_DIR)
    if not os.path.exists(self.TEMP_DIR):
      self.fs.create_dir(self.TEMP_DIR)

    self._create_file(fuzzer.AFL_DUMMY_INPUT)
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.utils.get_temp_dir',
    ])

    self.mock.get_temp_dir.return_value = self.TEMP_DIR
    dont_use_strategies(self)

  def _create_file(self, filename, directory=None, contents=' '):
    """Write |contents| to |filename| in self.INPUT_DIR. Create |filename| if it
    doesn't exist.
    """
    if directory is None:
      directory = self.INPUT_DIR

    file_path = os.path.join(directory, filename)
    return file_path, self.fs.create_file(file_path, contents=contents)

  def _assert_elements_equal(self, l1, l2):
    """Assert that the elements of |l1| and |l2|. Modifies |l1| and |l2| by
    sorting them."""
    self.assertEqual(sorted(l1), sorted(l2))


class FuzzingStrategiesTest(fake_filesystem_unittest.TestCase):
  """Tests for launcher.FuzzingStrategies."""

  NUM_FILES = 1000
  INPUT_DIR = '/input'

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    for file_num in range(self.NUM_FILES):
      self.fs.create_file(os.path.join(self.INPUT_DIR, str(file_num)))

    test_helpers.patch(
        self,
        ['clusterfuzz._internal.bot.fuzzers.engine_common.is_lpm_fuzz_target'])
    self.mock.is_lpm_fuzz_target.return_value = True
    self.strategies = launcher.FuzzingStrategies(None)


class AflFuzzInputDirectoryTest(LauncherTestBase):
  """Test the launcher.AflFuzzInputDirectory class. Note that most of the
  methods tested are called from AflFuzzInputDirectory.__init__, so we will
  create the object rather than call them directly in these cases."""

  def setUp(self):
    super().setUp()
    self.temp_input_dir = os.path.join(self.TEMP_DIR, 'afl_input_dir')
    self.fs.create_dir(self.temp_input_dir)
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.bot.fuzzers.engine_common.is_lpm_fuzz_target'])
    self.mock.is_lpm_fuzz_target.return_value = True
    self.strategies = launcher.FuzzingStrategies(None)

  def _new_afl_input(self):
    """Create a new AflFuzzInputDirectory object."""
    return launcher.AflFuzzInputDirectory(self.temp_input_dir, self.TARGET_PATH,
                                          self.strategies)

  def test_corpus_subset(self):
    """Tests that create_new_if_needed works as intended when told to use a 75
    file corpus subset."""
    self.strategies.use_corpus_subset = True
    self.strategies.corpus_subset_size = 75
    # Now test create_new_if_needed obeys corpus_subset.
    self.strategies.use_corpus_subset = True
    for file_num in range(self.strategies.corpus_subset_size):
      self._create_file(str(file_num), directory=self.temp_input_dir)

    afl_input = self._new_afl_input()
    self.assertEqual(
        len(os.listdir(afl_input.input_directory)),
        self.strategies.corpus_subset_size)

    self.assertTrue(self.strategies.use_corpus_subset)


class AflFuzzOutputDirectoryTest(LauncherTestBase):
  """Test the launcher.AflFuzzOutputDirectory class."""
  QUEUE_DIR = '/tmp/afl_output_dir/default/queue'

  # Note that this is just a file that is part of the input corpus.
  # It isn't an AFL testcase.
  INPUT_TESTCASE_FILENAME = '1'
  INPUT_TESTCASE_INO = 1
  QUEUE_INPUT_LINK_FILENAME = 'id:000000,orig:1'
  QUEUE_INPUT_COPIED_FILENAME = 'id:000002,orig:2'
  QUEUE_TESTCASE_FILENAME = 'id:000001,src:000000,op:flip1,pos:0,+cov'
  QUEUE_TESTCASE_INO = 2

  def setUp(self):
    super().setUp()
    # Creates self.OUTPUT_DIR.
    self.afl_output = launcher.AflFuzzOutputDirectory()
    os.makedirs(self.CRASHES_DIR)
    os.makedirs(self.QUEUE_DIR)

    self.input_testcase_path, input_testcase_obj = self._create_file(
        self.INPUT_TESTCASE_FILENAME)

    input_testcase_obj.SetIno(self.INPUT_TESTCASE_INO)
    self.input_directory_inodes = set(
        [os.stat(self.input_testcase_path).st_ino])

    self.queue_input_link_path, queue_input_link_obj = self._create_file(
        self.QUEUE_INPUT_LINK_FILENAME, directory=self.QUEUE_DIR)

    queue_input_link_obj.SetIno(self.INPUT_TESTCASE_INO)

    self.queue_copied_testcase_path, _ = self._create_file(
        self.QUEUE_INPUT_COPIED_FILENAME, directory=self.QUEUE_DIR)

    self.queue_testcase_path, queue_testcase_obj = self._create_file(
        self.QUEUE_TESTCASE_FILENAME, directory=self.QUEUE_DIR)

    queue_testcase_obj.SetIno(self.QUEUE_TESTCASE_INO)

  def test_is_testcase(self):
    """Test that is_testcase() works as expected."""

    # Test that testcases must be files and not directories.
    dir_name = 'id:000004,src:000000,op:flip1,pos:0,+cov'
    os.mkdir(dir_name)
    self.assertFalse(self.afl_output.is_testcase(dir_name))

    # Test that it returns False for a non-testcase.
    non_testcase_filename = 'non-testcase'
    non_testcase_path, _ = self._create_file(non_testcase_filename)
    self.assertFalse(self.afl_output.is_testcase(non_testcase_path))

    # Test that files produced by AFL are considered testcases.
    self.assertTrue(self.afl_output.is_testcase(self.queue_testcase_path))

  def test_is_new_testcase(self):
    """Test that is_new_testcase behaves as expected when passed non-hard
    links."""
    # Test that it returns False for a non_testcase.
    non_testcase_filename = 'non-testcase'
    non_testcase_path, _ = self._create_file(non_testcase_filename)
    self.assertFalse(self.afl_output.is_new_testcase(non_testcase_path))

    # Test that it returns True for a new testcase.
    self.assertTrue(self.afl_output.is_new_testcase(self.queue_testcase_path))

    # Test that it returns False for a copied testcase.
    self.assertFalse(
        self.afl_output.is_new_testcase(self.queue_copied_testcase_path))

  def test_count_new_units(self):
    """Test that count_new_units works as expected."""
    self.afl_output.destination_directory_inodes = set()
    # Test that it works as intended.
    self.assertEqual(self.afl_output.count_new_units(self.afl_output.queue), 1)

    # Test that hard links aren't counted as new units because they are copies
    # of files from the original output directory.
    self.afl_output.destination_directory_inodes = self.input_directory_inodes
    self.assertEqual(self.afl_output.count_new_units(self.afl_output.queue), 1)

    # Test that copies aren't counted as new units.
    self.fs.RemoveObject(self.queue_copied_testcase_path)
    self.assertEqual(self.afl_output.count_new_units(self.afl_output.queue), 1)

    # Test that non-testcases aren't counted as new units.
    self._create_file('README.txt', directory=self.afl_output.queue)
    self.assertEqual(self.afl_output.count_new_units(self.afl_output.queue), 1)

  def test_remove_hang_in_queue(self):
    """Test that remove_hang_in_queue works as expected."""
    self.assertIn(self.QUEUE_INPUT_LINK_FILENAME, os.listdir(self.QUEUE_DIR))
    self.afl_output.remove_hang_in_queue(self.queue_input_link_path)
    self.assertNotIn(self.QUEUE_INPUT_LINK_FILENAME, os.listdir(self.QUEUE_DIR))


class SetSanitizerOptionsTest(LauncherTestBase):
  """Test that we set the sanitzer options correctly. This is very important
  as afl-fuzz will refuse to run if we do it incorrectly.
  """

  DUMMY_OPTION = 'dummy_option=dummy_value'
  REQUIRED_ASAN_OPTIONS = ['symbolize=0', 'abort_on_error=1']
  REQUIRED_MSAN_OPTIONS = ['symbolize=0', 'exit_code=86']

  def _del_opts(self):
    if 'ASAN_OPTIONS' in os.environ:
      del os.environ['ASAN_OPTIONS']

    if 'MSAN_OPTIONS' in os.environ:
      del os.environ['MSAN_OPTIONS']

  def assert_sanitizer_opts_set(self, sanitizer_options_variable,
                                *additional_options):
    """Test that sanitizer options are set."""
    if sanitizer_options_variable == 'ASAN_OPTIONS':
      required_options = self.REQUIRED_ASAN_OPTIONS
    else:
      required_options = self.REQUIRED_MSAN_OPTIONS

    if additional_options:
      opts = required_options + list(additional_options)
    else:
      opts = required_options

    sanitizer_options_value = os.environ[sanitizer_options_variable]
    for opt in opts:
      self.assertIn(opt, sanitizer_options_value)

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)

  def test_left_unset(self):
    launcher.set_additional_sanitizer_options_for_afl_fuzz()
    self.assertNotIn('ASAN_OPTIONS', os.environ)
    self.assertNotIn('MSAN_OPTIONS', os.environ)

  def test_set_when_empty(self):
    os.environ['ASAN_OPTIONS'] = ''
    os.environ['MSAN_OPTIONS'] = ''
    launcher.set_additional_sanitizer_options_for_afl_fuzz()
    self.assert_sanitizer_opts_set('ASAN_OPTIONS')
    self.assert_sanitizer_opts_set('MSAN_OPTIONS')

  def test_opts_preserved(self):
    """Test opts preserved."""
    os.environ['ASAN_OPTIONS'] = self.DUMMY_OPTION
    os.environ['MSAN_OPTIONS'] = self.DUMMY_OPTION
    launcher.set_additional_sanitizer_options_for_afl_fuzz()
    self.assert_sanitizer_opts_set('ASAN_OPTIONS', self.DUMMY_OPTION)
    self.assert_sanitizer_opts_set('MSAN_OPTIONS', self.DUMMY_OPTION)

    self._del_opts()
    os.environ['ASAN_OPTIONS'] = self.DUMMY_OPTION
    launcher.set_additional_sanitizer_options_for_afl_fuzz()
    self.assert_sanitizer_opts_set('ASAN_OPTIONS', self.DUMMY_OPTION)
    self.assertNotIn('MSAN_OPTIONS', os.environ)

  def test_options_file(self):
    """Test *SAN_OPTIONS set from .options file."""
    os.environ['ASAN_OPTIONS'] = self.DUMMY_OPTION
    os.environ['MSAN_OPTIONS'] = self.DUMMY_OPTION
    self._create_file(
        self.TARGET_OPTIONS_PATH,
        contents='[asan]\nfake_option=1\n[msan]\nfake_option=2')
    engine_common.process_sanitizer_options_overrides(self.TARGET_PATH)
    launcher.set_additional_sanitizer_options_for_afl_fuzz()
    self.assert_sanitizer_opts_set('ASAN_OPTIONS', self.DUMMY_OPTION,
                                   'fake_option=1')
    self.assert_sanitizer_opts_set('MSAN_OPTIONS', self.DUMMY_OPTION,
                                   'fake_option=2')


class AflRunnerTest(LauncherTestBase):
  """Tests for AflRunnerCommon."""
  TESTCASE_FILE_PATH = '/testcase'
  ARBITRARY_OUTPUT = 'No new instrumentation output, test case may be useless'
  ARBITRARY_RET_CODE = 99
  BAD_FILENAME = 'badfile'
  BAD_FILE_CONTENTS = 'bad'

  def setUp(self):
    super().setUp()
    test_helpers.patch_environ(self)
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.bot.fuzzers.engine_common.is_lpm_fuzz_target'])
    self.mock.is_lpm_fuzz_target.return_value = True
    environment.set_value('HARD_TIMEOUT_OVERRIDE', 600)
    config = launcher.AflConfig.from_target_path(self.TARGET_PATH)

    self.runner = launcher.AflRunner(self.TARGET_PATH, config,
                                     self.TESTCASE_FILE_PATH, self.INPUT_DIR)

    self.fuzz_result = new_process.ProcessResult()
    self.args = ['-iinput1', '-ooutput', '123', '456']
    self.times_called = 0

  def test_gen_afl_args(self):
    """Test that we are generating arguments for AFL correctly."""
    target_path = '/targetpath'
    output_dir = '/afl_output_dir'
    input_dir = '/inputdir'
    extra_args = ['extra1', 'extra2']
    testcase_file_path = '/testcase'
    config = launcher.AflConfig.from_target_path(target_path)
    config.additional_afl_arguments.extend(extra_args)
    runner = launcher.AflRunner(target_path, config, testcase_file_path,
                                input_dir)

    afl_args = runner.generate_afl_args()

    self.assertIn(target_path, afl_args)
    target_idx = afl_args.index(target_path)

    # Test that output_dir is the parameter for -o and that it is being passed
    # to afl and not the target binary.
    output_dir_argument = [arg for arg in afl_args if output_dir in arg][0]
    self.assertIn('-o', output_dir_argument)
    self.assertLess(afl_args.index(output_dir_argument), target_idx)

    input_dir_argument = [arg for arg in afl_args if input_dir in arg][0]
    self.assertIn('-i', input_dir_argument)
    self.assertLess(afl_args.index(input_dir_argument), target_idx)

    for extra_arg in extra_args:
      self.assertIn(extra_arg, afl_args)
      self.assertLess(afl_args.index(extra_arg), len(afl_args))

  def test_afl_setup(self):
    """Test AflRunner.afl_setup."""
    self._create_file(self.runner.stderr_file_path)
    self.runner.afl_setup()
    self.assertFalse(os.path.exists(self.runner.stderr_file_path))

  def test_set_environment_variables(self):
    """Test AflRunner.set_environment_variables."""
    self.runner.afl_setup()
    self.assertEqual(os.environ['AFL_DRIVER_STDERR_DUPLICATE_FILENAME'],
                     self.runner.stderr_file_path)
    self.assertEqual(os.environ['AFL_BENCH_UNTIL_CRASH'], '1')

  def test_set_resume(self):
    """Test AflRunner.set_resume."""
    self.runner.set_resume(self.args)
    self.assertIn('-i-', self.args)

  def test_get_arg_index(self):
    """Test AflRunner.get_arg_index."""
    # Test that it finds the correct index.
    self.assertEqual(self.runner.get_arg_index(self.args, '-o'), 1)
    # Test that it returns negative one when the flag is not self.args.
    self.assertEqual(self.runner.get_arg_index(self.args, '-z'), -1)

  def test_set_input_arg(self):
    """Test AflRunner.set_input_arg."""
    self.runner.set_input_arg(self.args, 'input2')
    self.assertEqual(self.args, ['-iinput2', '-ooutput', '123', '456'])

  def test_set_timeout_arg(self):
    """Test AflRunner.set_input_arg."""
    # Test that it is added when it doesn't yet exist.
    self.runner.set_timeout_arg(self.args, 1000)
    self.assertIn('-t1000', self.args)

    # Test that it is changed if it already exists.
    self.runner.set_timeout_arg(self.args, 2000)
    self.assertNotIn('-t1000', self.args)
    self.assertIn('-t2000', self.args)

    # Test that skip_hangs functionality works.
    self.runner.set_timeout_arg(self.args, 3000, True)
    self.assertIn('-t3000+', self.args)

  def test_set_arg(self):
    """Test AflRunnerCommon.set_arg."""
    self.runner.set_arg(self.args, '-i', 'input2')
    self.assertEqual(self.args, ['-iinput2', '-ooutput', '123', '456'])

    self.runner.set_arg(self.args, '-x', 'dict')
    self.assertEqual(self.args,
                     ['-xdict', '-iinput2', '-ooutput', '123', '456'])

  def test_should_try_fuzzing(self):
    """Test AflRunnerCommon.should_try_fuzzing."""
    # Test that it returns True when we haven't fuzzed yet.
    time_left = 100
    num_retries = 0
    self.assertTrue(self.runner.should_try_fuzzing(time_left, num_retries))

    time_left = 0
    # Test that it returns False when there is no time left to fuzz.
    self.assertFalse(self.runner.should_try_fuzzing(time_left, num_retries))

    time_left = 100
    num_retries = launcher.AflRunnerCommon.MAX_FUZZ_RETRIES + 1
    # Test that it returns False when there is no time left to fuzz.
    self.assertFalse(self.runner.should_try_fuzzing(time_left, num_retries))

  def test_prepare_retry_if_cpu_error(self):
    """Test AflRunner.prepare_retry_if_cpu_error."""
    # Test that it doesn't prepare a retry if the error is unrelated:
    if 'AFL_NO_AFFINITY' in os.environ:
      del os.environ['AFL_NO_AFFINITY']

    self.fuzz_result.output = (
        '[-] PROGRAM ABORT : All test cases time out, giving up!\n'
        'Location : perform_dry_run(), afl-fuzz.c:3240\n')

    self.assertFalse(self.runner.prepare_retry_if_cpu_error(self.fuzz_result))
    self.assertNotIn('AFL_NO_AFFINITY', os.environ)

    # Now test that it tries to fix the issue it is supposed to.
    self.fuzz_result.output = (
        '[-] PROGRAM ABORT : No more free CPU cores\n'
        'Location : bind_to_free_cpu(), afl-fuzz.c:484\n')

    self.assertTrue(self.runner.prepare_retry_if_cpu_error(self.fuzz_result))
    self.runner.afl_setup()
    self.assertIn('AFL_NO_AFFINITY', os.environ)
    self.assertEqual(os.environ['AFL_NO_AFFINITY'], '1')

    # Now test it doesn't try to fix the issue again (this is a sanity check
    # on our code).
    self.assertFalse(self.runner.prepare_retry_if_cpu_error(self.fuzz_result))

  def test_fuzzer_stderr_ioerror(self):
    """Test AflRunner.fuzzer_stderr when there is an error reading the
    stderr file."""
    test_helpers.patch(
        self, ['clusterfuzz._internal.base.utils.read_from_handle_truncated'])

    self.mock.read_from_handle_truncated.side_effect = IOError
    self.assertIsNone(self.runner._fuzzer_stderr)
    self.assertEqual(self.runner.fuzzer_stderr, '')

  def test_fuzzer_stderr(self):
    """Test AflRunner.fuzzer_stderr works correctly."""
    stderr = 'hello'
    self.fs.create_file(self.runner.stderr_file_path, contents=stderr)
    self.assertIsNone(self.runner._fuzzer_stderr)
    self.assertEqual(self.runner.fuzzer_stderr, stderr)

    # Now test that it doesn't read more than launcher.MAX_OUTPUT_LEN
    stderr = (launcher.MAX_OUTPUT_LEN + 1) * 'a'
    with open(self.runner.stderr_file_path, 'w+') as file_handle:
      file_handle.write(stderr)

    # A truncated marker will be added, so _fuzzer_stderr will actually be
    # allowed to be greater than MAX_OUTPUT_LEN, but not by much.
    self.assertLess(
        len(self.runner.fuzzer_stderr), launcher.MAX_OUTPUT_LEN + 50)

  def _process_result(self,
                      command=None,
                      output=None,
                      return_code=0,
                      time_executed=20,
                      timed_out=False):
    """Creates a new_process.ProcessResult with specified values or good
    defaults."""
    if command is None:
      command = ['afl-fuzz', '-iin', '-oout', './fuzzer']
    if output is None:
      output = self.ARBITRARY_OUTPUT

    return new_process.ProcessResult(
        command=command,
        output=output,
        return_code=return_code,
        time_executed=time_executed,
        timed_out=timed_out)

  def _initialization_for_run_afl(self):
    """Initialization."""
    # Test that it works when everything works normally (no errors).
    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.afl.launcher.AflRunner.run_and_wait',
    ])

    # Make sure this initialized or else it will remove CRASHES_DIR.
    self.runner.afl_output  # pylint: disable=pointless-statement
    self.fs.create_dir(self.CRASHES_DIR)
    self.runner.initial_max_total_time = 100
    self.mock.run_and_wait.side_effect = (
        lambda *args, **kwargs: self._process_result())

    self._write_bad_input()

  def test_do_offline_mutations_small_testcase(self):
    """Tests that do_offline_mutations doesn't remove non-oversized testcases
    from the corpus."""
    # <1 MB testcase isn't oversized.
    self.assertTrue(self._do_offline_mutations(2**20 - 1))

  def test_do_offline_mutations_large_testcase(self):
    """Tests that do_offline_mutations doesn't add oversized testcases to the
    corpus."""
    # 1 MB testcase is oversized.
    self.assertFalse(self._do_offline_mutations(2**20))

  def _do_offline_mutations(self, size):
    """Creates a file |size| bytes long in the input directory, then calls
    do_offline_mutations and returns whether the file is in the input directory.
    """
    contents = 'A' * size  # 1 MB
    filename = 'test-file'
    input_dir = self.runner.afl_input.input_directory
    filepath = os.path.join(input_dir, filename)
    self.fs.create_file(filepath, contents=contents)
    self.runner.strategies.is_mutations_run = True
    self.runner.do_offline_mutations()
    return filename in os.listdir(input_dir)

  def test_run_afl_fuzz_fuzz_success(self):
    """Test AflRunner.run_afl_fuzz_and_handle_error when fuzzing succeeds."""
    self._initialization_for_run_afl()

    self.assertEqual(self.runner.run_afl_fuzz(self.args).return_code, 0)
    self.assertEqual(self.runner.fuzzer_stderr, '')

  def test_run_afl_fuzz_one_cpu_error(self):
    """Test AflRunner.run_afl_fuzz_and_handle_error works as intended when there
    is an error binding to CPU, but afl-fuzz is able to run in the end."""

    def one_cpu_error(*args, **kwargs):  # pylint: disable=unused-argument
      self.times_called += 1
      if self.times_called == 1:
        return self._process_result(
            output='PROGRAM ABORT :No more free CPU cores',
            return_code=self.ARBITRARY_RET_CODE)

      return self._process_result()

    self._initialization_for_run_afl()
    self.mock.run_and_wait.side_effect = one_cpu_error
    self.assertEqual(self.runner.run_afl_fuzz(self.args).return_code, 0)

  @mock.patch('clusterfuzz._internal.metrics.logs.log_error')
  def test_run_afl_fuzz_two_cpu_errors(self, mock_log_error):
    """Test AflRunner.run_afl_fuzz_and_handle_error works as intended when there
    is an error binding to CPU and afl-fuzz is never able to run in the end.
    Note that this should never happen in real life."""
    self._initialization_for_run_afl()

    def two_cpu_errors(*args, **kwargs):  # pylint: disable=unused-argument
      return self._process_result(
          output='PROGRAM ABORT :No more free CPU cores',
          return_code=self.ARBITRARY_RET_CODE)

    self.mock.run_and_wait.side_effect = two_cpu_errors
    fuzz_result = self.runner.run_afl_fuzz(self.args)
    self.assertNotEqual(0, fuzz_result.return_code)
    mock_log_error.assert_called_with(
        ('Afl exited with a non-zero exitcode: %s. Cannot recover.' %
         fuzz_result.return_code),
        engine_output=fuzz_result.output)

  def _write_bad_input(self):
    """Writes a "bad" file into the input directory."""
    self._create_file(self.BAD_FILENAME, contents=self.BAD_FILE_CONTENTS)


class GetFuzzTimeoutTest(GetTimeoutTestBase):
  """Get fuzz timeout tests."""
  function = staticmethod(
      partial(launcher.get_fuzz_timeout, is_mutations_run=False))

  def test_validation(self):
    """Test that get_fuzz_timeout rejects an invalid combination of
    HARD_TIMEOUT_OVERRIDE and MERGE_TIMEOUT_OVERRIDE."""
    self.validation_helper({
        'FUZZ_TEST_TIMEOUT': self.valid_hard_timeout,
        'HARD_TIMEOUT_OVERRIDE': self.valid_hard_timeout,
        'MERGE_TIMEOUT_OVERRIDE': self.valid_hard_timeout
    })

  def test_correctness(self):
    """Test that get_fuzz_timeout returns what we expect."""
    expected_fuzz_timeout = (
        self.valid_hard_timeout - launcher.POSTPROCESSING_TIMEOUT -
        self.valid_merge_timeout)

    self.call_helper(
        expected_fuzz_timeout, {
            'FUZZ_TEST_TIMEOUT': self.valid_hard_timeout,
            'MERGE_TIMEOUT_OVERRIDE': self.valid_merge_timeout
        })


class AflConfigTest(LauncherTestBase):
  """Test AflConfig."""

  def setUp(self):
    super().setUp()
    self.target_path = '/build_dir/target'
    self.options_path = self.target_path + '.options'

  def _create_options_file(self, contents):
    self._create_file(self.options_path, contents=contents)

  def _get_config(self):
    return launcher.AflConfig.from_target_path(self.target_path)

  def test_num_persistent_executions(self):
    """"Test that AflConfig sets the number of persistent executions we
    specified."""
    self._create_options_file('[libfuzzer]\n'
                              'dict=my_dict.dict\n'
                              'max_len=1337\n'
                              '[AFL]\n'
                              'N=800\n')

    self.assertEqual('800', self._get_config().num_persistent_executions)

  def test_dont_defer(self):
    """"Test that AflConfig allows .options file to opt-out of AFL's
    forkserver."""
    self._create_options_file('[env]\n'
                              'INVALID_ENV_VAR=blah\n'
                              'AFL_DRIVER_DONT_DEFER=1\n')

    env = self._get_config().additional_env_vars
    self.assertEqual('1', env.get('AFL_DRIVER_DONT_DEFER', None))

  def test_use_default_dict_without_fuzz_target_extension(self):
    """Test that AflConfig uses the default dict when none is specified. This
    is for case when fuzz target does not have an extension."""
    self.target_path = '/build_dir/target'
    dict_path = '/build_dir/target.dict'
    self._create_file(dict_path, contents='')

    self.assertIn('-x' + dict_path, self._get_config().additional_afl_arguments)

  def test_use_default_dict_with_fuzz_target_extension(self):
    """Test that AflConfig uses the default dict when none is specified. This
    is for the case when fuzz target has an extension."""
    self.target_path = '/build_dir/target.exe'
    dict_path = '/build_dir/target.dict'
    self._create_file(dict_path, contents='')

    self.assertIn('-x' + dict_path, self._get_config().additional_afl_arguments)

  def test_libfuzzer_section_dict(self):
    """"Test that AflConfig uses the dict specified by the libfuzzer section of
    a .options file."""

    self._create_options_file('[libfuzzer]\n'
                              'dict=my_dict.dict\n'
                              'max_len=1337\n')

    self.assertIn('-x/build_dir/my_dict.dict',
                  self._get_config().additional_afl_arguments)

  def test_close_fd_mask(self):
    """"Test that AflConfig instructs afl_driver to close fd mask if specified
    by the libfuzzer section of a .options file."""

    fd_mask_value = 3
    self._create_options_file(
        ('[libfuzzer]\n'
         'close_fd_mask={fd_mask_value}\n'
         'max_len=1337\n').format(fd_mask_value=fd_mask_value))

    afl_additional_env_vars = self._get_config().additional_env_vars
    self.assertIn('AFL_DRIVER_CLOSE_FD_MASK', afl_additional_env_vars)
    self.assertEqual(
        str(fd_mask_value), afl_additional_env_vars['AFL_DRIVER_CLOSE_FD_MASK'])


class ListFullFilePathsTest(LauncherTestBase):
  """Tests for list_full_file_paths."""
  DUMMY_2_FILENAME = 'dummyfile2'
  DUMMY_3_FILENAME = 'dummyfile3'

  def setUp(self):
    super().setUp()
    self.dummy_file_path = os.path.join(self.INPUT_DIR, fuzzer.AFL_DUMMY_INPUT)
    self.dummy_3_file_path, _ = self._create_file(self.DUMMY_3_FILENAME)

  def test_list_full_file_paths(self):
    """Test that list_full_file_paths works as intended."""
    # Test it works with just files:
    self._assert_elements_equal(
        launcher.list_full_file_paths(self.INPUT_DIR),
        [self.dummy_file_path, self.dummy_3_file_path])

    # Test it works with a subdirectory by not returning it:
    dummy_dir = os.path.join(self.INPUT_DIR, 'dummydir')
    self.fs.create_dir(dummy_dir)
    self._create_file(self.DUMMY_2_FILENAME, directory=dummy_dir)

    self._assert_elements_equal(
        launcher.list_full_file_paths(self.INPUT_DIR),
        [self.dummy_file_path, self.dummy_3_file_path])


class CorpusTest(fake_filesystem_unittest.TestCase):
  """Tests for Corpus and CorpusElement classes."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.corpus = launcher.Corpus()
    self.guard = 0

  def _get_unique_feature(self):
    """Returns an arbitrary, unique, feature for use in testing."""
    guard = self.guard
    self.guard += 1
    default_hit_count = 1
    return (guard, default_hit_count)

  def _create_file(self, path, size=1):
    """Creates a file at |path| that is |size| bytes large."""
    self.fs.create_file(path, contents=size * 'A')

  def test_corpus_element(self):
    """Tests CorpusElement class."""
    path = '/path/to/file'
    size = 20
    self._create_file(path, size=size)
    corpus_element = launcher.CorpusElement(path)
    self.assertEqual(path, corpus_element.path)
    self.assertEqual(size, corpus_element.size)

  def test_element_paths(self):
    """Tests that element_paths is the set of filepaths of elements in the
    corpus."""
    filenames = ['file_1', 'file_2']
    for filename in filenames:
      feature = self._get_unique_feature()
      self._create_file(filename)
      self.corpus.associate_features_with_file([feature], filename)
    self.assertEqual(set(filenames), self.corpus.element_paths)

  def test_associate_new_features_with_file(self):
    """Tests that associate_features_with_file associates new features with a
    file."""
    # Create an arbitrary number of features.
    features = [self._get_unique_feature() for _ in range(3)]
    filename = 'element'
    self._create_file(filename)
    self.corpus.associate_features_with_file(features, filename)
    for feature in features:
      self.assertEqual(filename,
                       self.corpus.features_and_elements[feature].path)

  def test_associate_feature_with_smaller_file(self):
    """Tests that associate_features_with_file associates features with the
    smallest file. Also verify that an element that isn't the smallest
    associated with any feature isn't part of the corpus."""
    features = [self._get_unique_feature()]
    larger_filename = 'larger'
    self._create_file(larger_filename, size=2)
    self.corpus.associate_features_with_file(features, larger_filename)
    smaller_filename = 'smaller'
    self._create_file(smaller_filename, size=1)
    self.corpus.associate_features_with_file(features, smaller_filename)
    self.assertEqual(smaller_filename,
                     self.corpus.features_and_elements[features[0]].path)
    self.assertEqual(set([smaller_filename]), self.corpus.element_paths)

  def test_file_with_one_feature_remains(self):
    """Test that a file remains in the corpus as long as it the smallest element
    for at least one feature."""
    feature_1 = self._get_unique_feature()
    feature_2 = self._get_unique_feature()
    larger_filename = 'larger'
    self._create_file(larger_filename, size=2)
    self.corpus.associate_features_with_file([feature_1, feature_2],
                                             larger_filename)
    smaller_filename = 'smaller'
    self._create_file(smaller_filename, size=1)
    self.corpus.associate_features_with_file([feature_2], smaller_filename)
    self.assertEqual(smaller_filename,
                     self.corpus.features_and_elements[feature_2].path)
    self.assertEqual(larger_filename,
                     self.corpus.features_and_elements[feature_1].path)
    self.assertEqual(
        set([smaller_filename, larger_filename]), self.corpus.element_paths)


def dont_use_strategies(obj):
  """Helper function to prevent using fuzzing strategies, unless asked for."""
  test_helpers.patch(obj, [
      'clusterfuzz._internal.bot.fuzzers.engine_common.decide_with_probability',
  ])
  obj.mock.decide_with_probability.return_value = False
