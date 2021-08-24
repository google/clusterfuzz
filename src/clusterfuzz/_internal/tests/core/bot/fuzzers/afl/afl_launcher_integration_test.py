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
"""Integration tests for AFL launcher.py."""

import os
import re
import shutil
import unittest

import mock

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.afl import fuzzer
from clusterfuzz._internal.bot.fuzzers.afl import launcher
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.core.bot.fuzzers.afl.afl_launcher_test import \
    dont_use_strategies
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')


def clear_temp_dir():
  """Clear temp directory."""
  if os.path.exists(TEMP_DIRECTORY):
    shutil.rmtree(TEMP_DIRECTORY)


def create_temp_dir():
  """Create temp directory."""
  os.mkdir(TEMP_DIRECTORY)


def get_fuzz_timeout(fuzz_time):
  """Return timeout for fuzzing."""
  return (fuzz_time + launcher.AflRunner.AFL_CLEAN_EXIT_TIME +
          launcher.AflRunner.SIGTERM_WAIT_TIME)


def no_errors(f):
  """Decorator that asserts neither metrics.logs.log_error nor
  metrics.logs.log_fatal_and_exit were called."""

  def call_f(self, *args, **kwargs):
    test_helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_error'])

    result = f(self, *args, **kwargs)
    self.assertEqual(0, self.mock.log_error.call_count)
    return result

  return call_f


def setup_testcase_and_corpus(testcase, corpus, fuzz=False):
  """Setup testcase and corpus."""
  copied_testcase_path = os.path.join(TEMP_DIRECTORY, testcase)
  shutil.copy(os.path.join(DATA_DIRECTORY, testcase), copied_testcase_path)

  copied_corpus_path = os.path.join(TEMP_DIRECTORY, corpus)
  src_corpus_path = os.path.join(DATA_DIRECTORY, corpus)

  if os.path.exists(src_corpus_path):
    shutil.copytree(src_corpus_path, copied_corpus_path)
  else:
    os.mkdir(copied_corpus_path)
    with open(os.path.join(copied_corpus_path, fuzzer.AFL_DUMMY_INPUT),
              'w') as f:
      f.write(' ')

  if fuzz:
    os.environ['FUZZ_CORPUS_DIR'] = copied_corpus_path

  return copied_testcase_path


def run_launcher(*args):
  """Run launcher.py."""
  mock_stdout = test_utils.MockStdout()

  os.environ['FUZZ_TARGET'] = args[1]
  with mock.patch('sys.stdout', mock_stdout):
    launcher.main(['launcher.py'] + list(args))

  return mock_stdout.getvalue()


def mocked_is_testcase(path):
  """Mocked version of AflFuzzOutputDirectory.is_testcase that looks for "COLON"
  instead of ":" because this repo cannot be used on windows if it has filenames
  with ":"."""
  testcase_regex = re.compile(r'idCOLON\d{6},.+')
  return (os.path.isfile(path) and
          bool(re.match(testcase_regex, os.path.basename(path))))


def mocked_fuzz(runner):
  """Mocked version of AflRunner.fuzz."""
  fuzz_args = runner.generate_afl_args()

  runner._fuzz_args = fuzz_args  # pylint: disable=protected-access
  engine_common.recreate_directory(runner.afl_output.output_directory)
  runner._fuzzer_stderr = ''  # pylint: disable=protected-access

  # Create the queue directory within AFL's output directory.
  queue = runner.afl_output.queue
  engine_common.recreate_directory(queue)
  new_corpus_dir = os.path.join(DATA_DIRECTORY, 'merge_new_corpus')
  for filename in os.listdir(new_corpus_dir):
    src = os.path.join(new_corpus_dir, filename)
    dst = os.path.join(queue, filename)
    shutil.copy(src, dst)

  return new_process.ProcessResult(
      command=[], return_code=0, output='', time_executed=1)


@unittest.skipIf(not environment.get_value('AFL_INTEGRATION_TESTS'),
                 'AFL_INTEGRATION_TESTS=1 must be set')
class BaseLauncherTest(unittest.TestCase):
  """Base AFL launcher tests."""

  def setUp(self):
    os.environ['BUILD_DIR'] = DATA_DIRECTORY
    os.environ['FUZZ_INPUTS_DISK'] = TEMP_DIRECTORY
    os.environ['FAIL_RETRIES'] = '1'

    test_helpers.patch_environ(self)
    dont_use_strategies(self)

    # Make it easy to assert if things were logged.
    test_helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.log', 'os.getpid',
        'clusterfuzz._internal.bot.fuzzers.afl.launcher.rand_cmplog_level',
        'clusterfuzz._internal.bot.fuzzers.afl.launcher.rand_schedule'
    ])
    self.mock.rand_cmplog_level.return_value = '2'
    self.mock.rand_schedule.return_value = 'fast'
    self.logged_messages = []

    def mocked_log(message, **kwargs):  # pylint: disable=unused-argument
      self.logged_messages.append(message)

    self.mock.log.side_effect = mocked_log
    self.mock.getpid.return_value = 1337

    clear_temp_dir()
    create_temp_dir()

  def tearDown(self):
    clear_temp_dir()

  def _test_abnormal_return_code(self):
    """Test that abnormal return codes from single runs of the fuzz target (eg:
    not 0 or 1, which is ASAN's return code for errors) are logged."""
    test_helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_error'])
    testcase_path = setup_testcase_and_corpus('crash', 'empty_corpus')
    run_launcher(testcase_path, 'return_code_255')
    self.mock.log_error.assert_called_with(
        'AFL target exited with abnormal exit code: 255.',
        output='ERROR: returning 255\n')

  def _test_libfuzzerize_corpus(self, mock_get_timeout):
    """Test that libfuzzerize_corpus properly merges new testcases back into
    the corpus."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus(
        'empty', 'input_corpus', fuzz=True)
    input_corpus = os.environ['FUZZ_CORPUS_DIR']

    corpus_path = os.path.join(DATA_DIRECTORY, 'merge_initial_corpus')
    for filename in os.listdir(corpus_path):
      src = os.path.join(corpus_path, filename)
      dst = os.path.join(input_corpus, filename)
      shutil.copy(src, dst)

    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.afl.launcher.AflRunnerCommon.fuzz',
        'clusterfuzz._internal.bot.fuzzers.afl.launcher.AflFuzzOutputDirectory.is_testcase'
    ])

    self.mock.fuzz.side_effect = mocked_fuzz
    self.mock.is_testcase.side_effect = mocked_is_testcase

    run_launcher(testcase_path, 'test_fuzzer', input_corpus)
    self.assertEqual(
        sorted([
            # Ensure that smaller files are favored. This file has the same
            # coverage as
            # 'idCOLON000000,larger_same_cov_idCOLON000001,non_initial_cov' but
            # is smaller, so merge should use 'idCOLON000001,non_initial_cov'
            # and not
            # 'idCOLON000000,larger_same_cov_idCOLON000001,non_initial_cov'.
            # This filename is the hash of idCOLON000001,non_initial_cov.
            '3dce8306f3c1810d5d81ed5ebb0ccea947277a61',
            # This file reaches unique paths and should therefore be merged.
            # This filename is the hash of idCOLON000002,unique_cov.
            '4c1fe29b1a967d34a6fcc078b8fb653dd807dee7',
            # Ensure we aren't removing anything from the input corpus. Thus
            # even though 'in1' and 'nearly_empty' are redundant they should
            # both be here Similarly, even though 'in1' and 'nearly_empty' have
            # the same coverage as idCOLON000003,nearly_empty_copy (from
            # merge_new_corpus/) and '254_ascending_and_0xa' has the same
            # coverage as 'idCOLON000004,same_cov_254_ascending_and_0xa0xa'
            # (also from merge_new_corpus/) neither of those files should be
            # merged into the input corpus.
            '254_ascending_and_0xa0xa',
            'nearly_empty',
            # AFL's dummy file, which was not originally part of the input
            # corpus, but is added by launcher.
            'in1'
        ]),
        sorted(os.listdir(input_corpus)))
    self.assertIn('Merge completed successfully.', self.logged_messages)


class TestLauncher(BaseLauncherTest):
  """AFL launcher tests."""

  def test_abnormal_return_code(self):
    self._test_abnormal_return_code()

  def test_single_testcase_crash(self):
    """Tests launcher with a crashing testcase."""
    testcase_path = setup_testcase_and_corpus('crash', 'empty_corpus')
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        output)

    # Make sure we didn't fuzz.
    self.assertNotIn('afl-fuzz', output)

  def test_assert(self):
    """Tests launcher with a crashing testcase(assert)."""
    os.environ['ASAN_OPTIONS'] = 'handle_abort=1'
    testcase_path = setup_testcase_and_corpus('crash', 'empty_corpus')
    output = run_launcher(testcase_path, 'assert_fail')
    self.assertIn('Assertion `false\' failed.', output)
    self.assertIn('ERROR: AddressSanitizer: ABRT on unknown address', output)

  @mock.patch('clusterfuzz._internal.bot.fuzzers.afl.launcher.get_fuzz_timeout')
  def test_fuzz_no_crash(self, mock_get_timeout):
    """Tests fuzzing (no crash)."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'Command: {0}/afl-fuzz -l2 -pfast -Sdefault -i{1}/corpus '
        '-o{1}/temp-1337/afl_output_dir -mnone '
        '{0}/test_fuzzer 2147483647'.format(DATA_DIRECTORY, TEMP_DIRECTORY),
        output)

    # New items should've been added to the corpus.
    self.assertNotEqual(len(os.listdir(os.environ['FUZZ_CORPUS_DIR'])), 0)

  @unittest.skip('AFL++ does not handle crashes in input corpus properly.')
  @mock.patch('clusterfuzz._internal.bot.fuzzers.afl.launcher.get_fuzz_timeout')
  def test_fuzz_input_crash(self, mock_get_timeout):
    """Tests fuzzing (crash in input)."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'always_crash_fuzzer')
    self.assertIn(
        'Command: {0}/afl-fuzz -l2 -pfast -Sdefault -i{1}/corpus '
        '-o{1}/temp-1337/afl_output_dir -mnone '
        '{0}/always_crash_fuzzer 2147483647'.format(DATA_DIRECTORY,
                                                    TEMP_DIRECTORY), output)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address '
        '0x000000000000', output)

    # No testcase should have been copied back.
    self.assertEqual(os.path.getsize(testcase_path), 0)

  @mock.patch('clusterfuzz._internal.bot.fuzzers.afl.launcher.get_fuzz_timeout')
  def test_fuzz_crash(self, mock_get_timeout):
    """Tests fuzzing (crash)."""
    # *WARNING* Do not lower the fuzz timeout unless you really know what you
    # are doing. Doing so will cause the test to fail on rare ocassion, which
    # will break deploys.
    mock_get_timeout.return_value = get_fuzz_timeout(120.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)

    output = run_launcher(testcase_path, 'easy_crash_fuzzer')
    self.assertIn(
        'Command: {0}/afl-fuzz -l2 -pfast -Sdefault -i{1}/corpus '
        '-o{1}/temp-1337/afl_output_dir -mnone '
        '{0}/easy_crash_fuzzer 2147483647'.format(DATA_DIRECTORY,
                                                  TEMP_DIRECTORY), output)

    self.assertIn('ERROR: AddressSanitizer: heap-use-after-free on address',
                  output)

    # Testcase should've been copied back.
    self.assertGreaterEqual(os.path.getsize(testcase_path), 3)
    with open(testcase_path, 'rb') as f:
      self.assertEqual(f.read()[:3], b'ABC')

  @no_errors
  @unittest.skip('AFL++ cant consistently find testcases fast enough for test.')
  @mock.patch('clusterfuzz._internal.bot.fuzzers.afl.launcher.get_fuzz_timeout')
  def test_fuzz_merge(self, mock_get_timeout):
    """Tests fuzzing with merge."""
    mock_get_timeout.return_value = get_fuzz_timeout(15.0)
    testcase_path = setup_testcase_and_corpus(
        'empty', 'redundant_corpus', fuzz=True)
    corpus_path = os.environ['FUZZ_CORPUS_DIR']

    for i in range(100):
      with open(os.path.join(corpus_path, '%04d' % i), 'w') as f:
        f.write('A' * 256)
    output = run_launcher(testcase_path, 'test_fuzzer')

    self.assertIn(
        'Command: {0}/afl-fuzz -l2 -pfast -Sdefault -i{1}/redundant_corpus '
        '-o{1}/temp-1337/afl_output_dir -mnone '
        '{0}/test_fuzzer 2147483647'.format(DATA_DIRECTORY, TEMP_DIRECTORY),
        output)

    self.assertIn('Merging corpus.', self.logged_messages)
    self.assertNotIn('Timed out in merge', ' '.join(self.logged_messages))
    self.assertIn('Merge completed successfully.', self.logged_messages)

  @no_errors
  @mock.patch('clusterfuzz._internal.bot.fuzzers.afl.launcher.get_fuzz_timeout')
  def test_libfuzzerize_corpus(self, mock_get_timeout):
    self._test_libfuzzerize_corpus(mock_get_timeout)
