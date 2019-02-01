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
"""Integration tests for libfuzzer launcher.py."""
import mock
import os
import shutil
import StringIO
import unittest

import parameterized

from bot.fuzzers import libfuzzer
from bot.fuzzers.libFuzzer import launcher
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')


def clear_temp_dir():
  """Clear temp directory."""
  if os.path.exists(TEMP_DIRECTORY):
    shutil.rmtree(TEMP_DIRECTORY)

  os.mkdir(TEMP_DIRECTORY)


def get_fuzz_timeout(fuzz_time):
  """Return timeout for fuzzing."""
  return (fuzz_time + libfuzzer.LibFuzzerCommon.LIBFUZZER_CLEAN_EXIT_TIME +
          libfuzzer.LibFuzzerCommon.SIGTERM_WAIT_TIME)


def mock_random_choice(seq):
  """Always returns first element from the sequence."""
  # We could try to mock a particular |seq| to be a list with a single element,
  # but it does not work well, as random_choice returns a 'mock.mock.MagicMock'
  # object that behaves differently from the actual type of |seq[0]|.
  return seq[0]


def setup_testcase_and_corpus(testcase, corpus, fuzz=False):
  """Setup testcase and corpus."""
  clear_temp_dir()
  copied_testcase_path = os.path.join(TEMP_DIRECTORY, testcase)
  shutil.copy(os.path.join(DATA_DIRECTORY, testcase), copied_testcase_path)

  copied_corpus_path = os.path.join(TEMP_DIRECTORY, corpus)
  src_corpus_path = os.path.join(DATA_DIRECTORY, corpus)

  if os.path.exists(src_corpus_path):
    shutil.copytree(src_corpus_path, copied_corpus_path)
  else:
    os.mkdir(copied_corpus_path)

  if fuzz:
    os.environ['FUZZ_CORPUS_DIR'] = copied_corpus_path

  return copied_testcase_path


def run_launcher(*args):
  """Run launcher.py."""
  string_io = StringIO.StringIO()

  with mock.patch('sys.stdout', string_io):
    launcher.main(['launcher.py'] + list(args))

  return string_io.getvalue()


class BaseLauncherTest(unittest.TestCase):
  """Base libFuzzer launcher tests."""

  def setUp(self):
    test_helpers.patch_environ(self)

    os.environ['BUILD_DIR'] = DATA_DIRECTORY
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['FUZZ_INPUTS_DISK'] = TEMP_DIRECTORY
    os.environ['FUZZ_TEST_TIMEOUT'] = '4800'
    os.environ['JOB_NAME'] = 'libfuzzer_asan'
    os.environ['INPUT_DIR'] = TEMP_DIRECTORY

    test_helpers.patch(self, [
        'atexit.register',
        'bot.fuzzers.engine_common.do_corpus_subset',
        'bot.fuzzers.engine_common.get_merge_timeout',
        'bot.fuzzers.engine_common.random_choice',
        'bot.fuzzers.libFuzzer.launcher.do_ml_rnn_generator',
        'bot.fuzzers.libFuzzer.launcher.do_radamsa_generator',
        'bot.fuzzers.libFuzzer.launcher.do_random_max_length',
        'bot.fuzzers.libFuzzer.launcher.do_recommended_dictionary',
        'bot.fuzzers.libFuzzer.launcher.do_value_profile',
        'bot.fuzzers.libFuzzer.launcher.get_dictionary_analysis_timeout',
        'os.getpid',
    ])

    # Prevent errors from occurring after tests complete by preventing the
    # launcher script from registering exit handlers.
    self.mock.register.side_effect = lambda func, *args, **kwargs: func

    self.mock.getpid.return_value = 1337

    self.mock.do_corpus_subset.return_value = False
    self.mock.do_ml_rnn_generator.return_value = False
    self.mock.do_radamsa_generator.return_value = False
    self.mock.do_random_max_length.return_value = False
    self.mock.do_recommended_dictionary.return_value = False
    self.mock.do_value_profile.return_value = False
    self.mock.get_dictionary_analysis_timeout.return_value = 5
    self.mock.get_merge_timeout.return_value = 10
    self.mock.random_choice.side_effect = mock_random_choice

  def assert_has_stats(self, output, testcase_path):
    """Asserts that libFuzzer stats are in output."""
    self.assertIn('stat::number_of_executed_units:', output)
    self.assertIn('stat::average_exec_per_sec:', output)
    self.assertIn('stat::new_units_added:', output)
    self.assertIn('stat::slowest_unit_time_sec:', output)
    self.assertIn('stat::peak_rss_mb:', output)

    self.assertTrue(os.path.exists(testcase_path + '.stats2'))

  def assert_corpus_loaded(self, output, directory):
    self.assertIn('Loading corpus dir: ' + directory, output)


@test_utils.integration
class TestLauncher(BaseLauncherTest):
  """libFuzzer launcher tests."""

  def test_single_testcase_crash(self):
    """Tests launcher with a crashing testcase."""
    testcase_path = setup_testcase_and_corpus('crash', 'empty_corpus')
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'Running command: {0}/test_fuzzer '
        '-rss_limit_mb=2048 -timeout=25 -runs=100 '
        '{1}/crash'.format(DATA_DIRECTORY, TEMP_DIRECTORY), output)

    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        output)

  def test_single_testcase_empty(self):
    """Tests launcher with an empty testcase."""
    testcase_path = setup_testcase_and_corpus('empty', 'empty_corpus')
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'Running command: {0}/test_fuzzer '
        '-rss_limit_mb=2048 -timeout=25 -runs=100 '
        '{1}/empty'.format(DATA_DIRECTORY, TEMP_DIRECTORY), output)
    self.assertIn('NOTE: fuzzing was not performed', output)

  @test_utils.slow
  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_no_crash(self, mock_get_timeout):
    """Tests fuzzing (no crash)."""
    self.mock.do_value_profile.return_value = True

    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer', '-max_len=256')
    expected = ('Command: {build_dir}/test_fuzzer -max_len=256 '
                '-rss_limit_mb=2048 -timeout=25 -use_value_profile=1 '
                '-artifact_prefix={temp_dir}/ -max_total_time=5 '
                '-print_final_stats=1 {temp_dir}/temp-1337/new '
                '{temp_dir}/corpus'.format(
                    build_dir=DATA_DIRECTORY, temp_dir=TEMP_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output,
                              os.path.join(TEMP_DIRECTORY, 'temp-1337', 'new'))
    self.assert_corpus_loaded(output, os.path.join(TEMP_DIRECTORY, 'corpus'))

    # New items should've been added to the corpus.
    self.assertNotEqual(len(os.listdir(os.environ['FUZZ_CORPUS_DIR'])), 0)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_crash(self, mock_get_timeout):
    """Tests fuzzing (crash)."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'always_crash_fuzzer', '-max_len=100')
    expected = (
        'Command: {build_dir}/always_crash_fuzzer -max_len=100 '
        '-rss_limit_mb=2048 -timeout=25 -artifact_prefix={temp_dir}/ '
        '-max_total_time=5 -print_final_stats=1 {temp_dir}/temp-1337/new '
        '{temp_dir}/corpus'.format(
            build_dir=DATA_DIRECTORY, temp_dir=TEMP_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output,
                              os.path.join(TEMP_DIRECTORY, 'temp-1337', 'new'))
    self.assert_corpus_loaded(output, os.path.join(TEMP_DIRECTORY, 'corpus'))

    self.assertIn('Test unit written to {0}/crash-'.format(TEMP_DIRECTORY),
                  output)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address '
        '0x000000000000', output)

    # Testcase (non-zero) should've been copied back.
    self.assertNotEqual(os.path.getsize(testcase_path), 0)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_from_subset(self, mock_get_timeout):
    """Tests fuzzing from corpus subset."""
    self.mock.do_corpus_subset.return_value = True
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)

    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer', '-max_len=100')
    expected = (
        'Command: {build_dir}/test_fuzzer -max_len=100 '
        '-rss_limit_mb=2048 -timeout=25 -artifact_prefix={temp_dir}/ '
        '-max_total_time=5 -print_final_stats=1 {temp_dir}/temp-1337/new '
        '{temp_dir}/temp-1337/subset'.format(
            build_dir=DATA_DIRECTORY, temp_dir=TEMP_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output,
                              os.path.join(TEMP_DIRECTORY, 'temp-1337', 'new'))
    self.assert_corpus_loaded(
        output, os.path.join(TEMP_DIRECTORY, 'temp-1337', 'subset'))

    self.assertIn('READ units: 10', output)

  def test_minimize(self):
    """Tests minimize."""
    testcase_path = setup_testcase_and_corpus(
        'aaaa', 'empty_corpus', fuzz=False)

    minimize_output_path = os.path.join(TEMP_DIRECTORY, 'minimized_testcase')
    output = run_launcher(testcase_path, 'crash_with_A_fuzzer', '-max_len=1337',
                          '--cf-minimize-to=' + minimize_output_path,
                          '--cf-minimize-timeout=60')

    expected = ('CRASH_MIN: failed to minimize beyond %s (1 bytes), '
                'exiting' % minimize_output_path)
    self.assertIn(expected, output)
    self.assertTrue(os.path.exists(minimize_output_path))

    with open(minimize_output_path) as f:
      result = f.read()
      self.assertEqual('A', result)

  def test_cleanse(self):
    """Tests cleanse."""
    testcase_path = setup_testcase_and_corpus(
        'aaaa', 'empty_corpus', fuzz=False)

    cleanse_output_path = os.path.join(TEMP_DIRECTORY, 'cleansed_testcase')
    output = run_launcher(testcase_path, 'crash_with_A_fuzzer', '-max_len=1337',
                          '--cf-cleanse-to=' + cleanse_output_path,
                          '--cf-cleanse-timeout=60')

    expected = 'CLEANSE: Replaced byte'
    self.assertIn(expected, output)
    self.assertTrue(os.path.exists(cleanse_output_path))

    with open(cleanse_output_path) as f:
      result = f.read()
      self.assertFalse(all(c == 'A' for c in result))

  @mock.patch('bot.fuzzers.dictionary_manager.DictionaryManager.'
              'parse_recommended_dictionary_from_log_lines')
  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_analyze_dict(self, mock_get_timeout,
                        mock_parse_recommended_dictionary):
    """Tests recommended dictionary analysis."""
    test_helpers.patch(self, [
        'bot.fuzzers.dictionary_manager.DictionaryManager.'
        'update_recommended_dictionary',
    ])
    mock_parse_recommended_dictionary.return_value = set([
        '"USELESS_0"',
        '"APPLE"',
        '"USELESS_1"',
        '"GINGER"',
        '"USELESS_2"',
        '"BEET"',
        '"USELESS_3"',
    ])
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)

    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    run_launcher(testcase_path, 'analyze_dict_fuzzer')

    expected_recommended_dictionary = set([
        '"APPLE"',
        '"GINGER"',
        '"BEET"',
    ])

    self.assertIn(expected_recommended_dictionary,
                  self.mock.update_recommended_dictionary.call_args[0])

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_max_length_strategy_with_override(self, mock_get_timeout):
    """Tests max length strategy with override."""
    self.mock.do_random_max_length.return_value = True
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'always_crash_fuzzer', '-max_len=100')
    expected = (
        'Command: {build_dir}/always_crash_fuzzer -max_len=100 '
        '-rss_limit_mb=2048 -timeout=25 -artifact_prefix={temp_dir}/ '
        '-max_total_time=5 -print_final_stats=1 {temp_dir}/temp-1337/new '
        '{temp_dir}/corpus'.format(
            build_dir=DATA_DIRECTORY, temp_dir=TEMP_DIRECTORY))
    self.assertIn(expected, output)

  @mock.patch('random.SystemRandom.randint', lambda a, b, c: 1337)
  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_max_length_strategy_without_override(self, mock_get_timeout):
    """Tests max length strategy without override."""
    self.mock.do_random_max_length.return_value = True
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'always_crash_fuzzer')
    expected = (
        'Command: {build_dir}/always_crash_fuzzer -rss_limit_mb=2048 '
        '-timeout=25 -max_len=1337 -artifact_prefix={temp_dir}/ '
        '-max_total_time=5 -print_final_stats=1 {temp_dir}/temp-1337/new '
        '{temp_dir}/corpus'.format(
            build_dir=DATA_DIRECTORY, temp_dir=TEMP_DIRECTORY))
    self.assertIn(expected, output)

  @mock.patch('metrics.logs.log_error')
  def test_exit_failure_logged(self, mock_log_error):
    """Test that we log when libFuzzer's exit code indicates it ran into an
    error."""
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    os.environ['EXIT_FUZZER_CODE'] = '1'
    run_launcher(testcase_path, 'exit_fuzzer', '-max_len=100')
    self.assertEqual(1, mock_log_error.call_count)

  @parameterized.parameterized.expand(['77', '27'])
  @mock.patch('metrics.logs.log_error')
  def test_exit_target_bug_not_logged(self, exit_code, mock_log_error):
    """Test that we dont log when exit code indicates bug found in target."""

    def mocked_log_error(*args, **kwargs):  # pylint: disable=unused-argument
      self.assertNotIn(launcher.ENGINE_ERROR_MESSAGE, args)

    mock_log_error.side_effect = mocked_log_error
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    os.environ['EXIT_FUZZER_CODE'] = exit_code
    run_launcher(testcase_path, 'exit_fuzzer', '-max_len=100')


@test_utils.integration
class TestLauncherMinijail(BaseLauncherTest):
  """libFuzzer launcher tests (minijail)."""

  def setUp(self):
    super(TestLauncherMinijail, self).setUp()
    os.environ['USE_MINIJAIL'] = 'True'

  def test_single_testcase_empty(self):
    """Tests launcher with an empty testcase."""
    testcase_path = setup_testcase_and_corpus('empty', 'empty_corpus')
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'Running command: {0}/test_fuzzer '
        '-rss_limit_mb=2048 -timeout=25 -runs=100 '
        '/empty'.format(DATA_DIRECTORY), output)

  def test_single_testcase_crash(self):
    """Tests launcher with a crashing testcase."""
    testcase_path = setup_testcase_and_corpus('crash', 'empty_corpus')
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'Running command: {0}/test_fuzzer '
        '-rss_limit_mb=2048 -timeout=25 -runs=100 '
        '/crash'.format(DATA_DIRECTORY), output)

    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        output)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_no_crash(self, mock_get_timeout):
    """Tests fuzzing (no crash)."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer', '-max_len=256')
    expected = ('Command: {build_dir}/test_fuzzer -max_len=256 '
                '-rss_limit_mb=2048 -timeout=25 -artifact_prefix=/ '
                '-max_total_time=5 -print_final_stats=1 /new '
                '/corpus'.format(build_dir=DATA_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output, '/new')
    self.assert_corpus_loaded(output, '/corpus')

    # New items should've been added to the corpus.
    self.assertIn('FUZZ_CORPUS_DIR', os.environ)
    self.assertNotEqual(len(os.listdir(os.environ['FUZZ_CORPUS_DIR'])), 0)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_crash(self, mock_get_timeout):
    """Tests fuzzing (crash)."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus('empty', 'corpus', fuzz=True)
    output = run_launcher(testcase_path, 'always_crash_fuzzer', '-max_len=100')
    expected = ('Command: {build_dir}/always_crash_fuzzer -max_len=100 '
                '-rss_limit_mb=2048 -timeout=25 -artifact_prefix=/ '
                '-max_total_time=5 -print_final_stats=1 /new '
                '/corpus'.format(build_dir=DATA_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output, '/new')
    self.assert_corpus_loaded(output, '/corpus')

    self.assertIn('Test unit written to /crash-', output)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address '
        '0x000000000000', output)

    # Testcase (non-zero) should've been copied back.
    self.assertNotEqual(os.path.getsize(testcase_path), 0)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_from_subset(self, mock_get_timeout):
    """Tests fuzzing from corpus subset."""
    self.mock.do_corpus_subset.return_value = True
    self.mock.do_value_profile.return_value = True

    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer', '-max_len=100')
    expected = ('Command: {build_dir}/test_fuzzer -max_len=100 '
                '-rss_limit_mb=2048 -timeout=25 -use_value_profile=1 '
                '-artifact_prefix=/ -max_total_time=5 -print_final_stats=1 '
                '/new /subset'.format(build_dir=DATA_DIRECTORY))
    self.assertIn(expected, output)
    self.assert_has_stats(output, testcase_path)

    self.assert_corpus_loaded(output, '/new')
    self.assert_corpus_loaded(output, '/subset')
    self.assertIn('READ units: 10', output)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_out_directory(self, mock_get_timeout):
    """Test /out mapping."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    output = run_launcher(testcase_path, 'check_out', '-max_len=100')
    self.assertIn('SUCCESS!', output)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_tmp_directory(self, mock_get_timeout):
    """Test /tmp mapping."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    output = run_launcher(testcase_path, 'check_tmp', '-max_len=100')
    self.assertIn('SUCCESS!', output)

  def test_minimize(self):
    """Tests minimize."""
    testcase_path = setup_testcase_and_corpus(
        'aaaa', 'empty_corpus', fuzz=False)

    minimize_output_path = os.path.join(TEMP_DIRECTORY, 'minimized_testcase')
    output = run_launcher(testcase_path, 'crash_with_A_fuzzer', '-max_len=1337',
                          '--cf-minimize-to=' + minimize_output_path,
                          '--cf-minimize-timeout=60')
    self.assertIn(
        'CRASH_MIN: failed to minimize beyond /minimized_crash '
        '(1 bytes), exiting', output)
    self.assertTrue(os.path.exists(minimize_output_path))
    with open(minimize_output_path) as f:
      result = f.read()
      self.assertEqual('A', result)

  def test_cleanse(self):
    """Tests cleanse."""
    testcase_path = setup_testcase_and_corpus(
        'aaaa', 'empty_corpus', fuzz=False)

    cleanse_output_path = os.path.join(TEMP_DIRECTORY, 'cleansed_testcase')
    output = run_launcher(testcase_path, 'crash_with_A_fuzzer', '-max_len=1337',
                          '--cf-cleanse-to=' + cleanse_output_path,
                          '--cf-cleanse-timeout=60')

    expected = 'CLEANSE: Replaced byte'
    self.assertIn(expected, output)
    self.assertTrue(os.path.exists(cleanse_output_path))

    with open(cleanse_output_path) as f:
      result = f.read()
      self.assertFalse(all(c == 'A' for c in result))

  @mock.patch('bot.fuzzers.dictionary_manager.DictionaryManager.'
              'parse_recommended_dictionary_from_log_lines')
  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_analyze_dict(self, mock_get_timeout,
                        mock_parse_recommended_dictionary):
    """Tests recommended dictionary analysis."""
    mock_parse_recommended_dictionary.return_value = set([
        '"USELESS_0"',
        '"APPLE"',
        '"USELESS_1"',
        '"GINGER"',
        '"USELESS_2"',
        '"BEET"',
        '"USELESS_3"',
    ])
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)

    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)

    test_helpers.patch(self, [
        'bot.fuzzers.dictionary_manager.DictionaryManager.'
        'update_recommended_dictionary',
    ])
    run_launcher(testcase_path, 'analyze_dict_fuzzer')

    expected_recommended_dictionary = set([
        '"APPLE"',
        '"GINGER"',
        '"BEET"',
    ])

    self.assertIn(expected_recommended_dictionary,
                  self.mock.update_recommended_dictionary.call_args[0])

  @mock.patch('metrics.logs.log_error')
  def test_exit_failure_not_logged(self, mock_log_error):
    """Test that we don't log based on libFuzzer's exit code.

    Test that we don't log when libFuzzer returns 1 since under minijail, this
    doesn't mean the fuzzer ran into an error. Minijail returns 1 if the fuzzer
    returns nonzero.
    """
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)

    def mocked_log_error(*args, **kwargs):  # pylint: disable=unused-argument
      self.assertNotIn(launcher.ENGINE_ERROR_MESSAGE, args)

    mock_log_error.side_effect = mocked_log_error
    os.environ['EXIT_FUZZER_CODE'] = '1'
    run_launcher(testcase_path, 'exit_fuzzer', '-max_len=100')
