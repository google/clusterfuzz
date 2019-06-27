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

from future import standard_library
standard_library.install_aliases()

import mock
import os
import shutil
import tempfile
import unittest

import parameterized

from bot.fuzzers import libfuzzer
from bot.fuzzers import strategy
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.libFuzzer import launcher
from bot.fuzzers.libFuzzer import strategy_selection
from build_management import build_manager
from datastore import data_types
from system import environment
from system import shell
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIRECTORY = os.path.join(TEST_PATH, 'temp')
DATA_DIRECTORY = os.path.join(TEST_PATH, 'data')

_get_directory_file_count_orig = shell.get_directory_file_count


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


def mock_get_directory_file_count(dir_path):
  """Mocked version, always return 1 for new testcases directory."""
  if dir_path == os.path.join(fuzzer_utils.get_temp_dir(), 'new'):
    return 1

  return _get_directory_file_count_orig(dir_path)


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
  mock_stdout = test_utils.MockStdout()
  with mock.patch('sys.stdout', mock_stdout):
    launcher.main(['launcher.py'] + list(args))

  return mock_stdout.getvalue()


def set_strategy_pool(strategies=None):
  """Helper method to create instances of strategy pools
  for patching use."""
  strategy_pool = strategy_selection.StrategyPool()

  if strategies is not None:
    for strategy_tuple in strategies:
      strategy_pool.add_strategy(strategy_tuple)

  return strategy_pool


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
        'bot.fuzzers.mutator_plugin._download_mutator_plugin_archive',
        'bot.fuzzers.mutator_plugin._get_mutator_plugins_from_bucket',
        'bot.fuzzers.libFuzzer.strategy_selection.'
        'generate_weighted_strategy_pool',
        'bot.fuzzers.libFuzzer.launcher.get_dictionary_analysis_timeout',
        'os.getpid',
    ])

    # Prevent errors from occurring after tests complete by preventing the
    # launcher script from registering exit handlers.
    self.mock.register.side_effect = lambda func, *args, **kwargs: func

    self.mock.getpid.return_value = 1337

    self.mock._get_mutator_plugins_from_bucket.return_value = []  # pylint: disable=protected-access
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool()
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

  def _test_fuzz_with_mutator_plugin(self, temp_subdir):
    """Tests fuzzing with a mutator plugin."""

    os.environ['MUTATOR_PLUGINS_DIR'] = os.path.join(
        TEMP_DIRECTORY, temp_subdir, 'mutator-plugins')
    fuzz_target_name = 'test_fuzzer'
    # Call before setting up the plugin since this call will erase the directory
    # the plugin is written to.
    testcase_path = setup_testcase_and_corpus(
        'empty', 'empty_corpus', fuzz=True)
    plugin_archive_name = 'custom_mutator_plugin-libfuzzer_asan-test_fuzzer.zip'
    plugin_archive_path = os.path.join(DATA_DIRECTORY, plugin_archive_name)

    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.MUTATOR_PLUGIN_STRATEGY])
    self.mock._get_mutator_plugins_from_bucket.return_value = [  # pylint: disable=protected-access
        plugin_archive_name
    ]
    self.mock._download_mutator_plugin_archive.return_value = (  # pylint: disable=protected-access
        plugin_archive_path)
    custom_mutator_print_string = 'CUSTOM MUTATOR\n'
    try:
      output = run_launcher(testcase_path, fuzz_target_name, '-runs=10')

    finally:
      shutil.rmtree(os.environ['MUTATOR_PLUGINS_DIR'])
    # custom_mutator_print_string gets printed before the custom mutator mutates
    # a test case. Assert that the count is greater than 1 to ensure that the
    # function didn't crash on its first execution (after printing).
    self.assertGreater(output.count(custom_mutator_print_string), 1)

  def _test_merge_reductions(self, temp_subdir):
    """Tests that reduced testcases are merged back into the original corpus
    without deleting the larger version."""
    testcase_path = setup_testcase_and_corpus(
        'empty', 'empty_corpus', fuzz=True)
    fuzz_target_name = 'analyze_dict_fuzzer'
    test_helpers.patch(self, [
        'bot.fuzzers.libFuzzer.launcher.create_merge_directory',
        'bot.fuzzers.libFuzzer.launcher.get_merge_directory',
        'system.shell.get_directory_file_count',
    ])

    self.mock.get_directory_file_count.side_effect = (
        mock_get_directory_file_count)

    self.mock.get_merge_directory.side_effect = lambda: os.path.join(
        fuzzer_utils.get_temp_dir(), temp_subdir, launcher.MERGE_DIRECTORY_NAME)

    minimal_unit_contents = 'APPLE'
    minimal_unit_hash = '569bea285d70dda2218f89ef5454ea69fb5111ef'
    nonminimal_unit_contents = 'APPLEO'
    nonminimal_unit_hash = '540d9ba6239483d60cd7448a3202b96c90409186'

    def mocked_create_merge_directory():
      """A mocked version of create_merge_directory that adds some interesting
      files to the merge corpus and initial corpus."""
      merge_directory_path = launcher.get_merge_directory()
      shell.create_directory(
          merge_directory_path, create_intermediates=True, recreate=True)

      # Write the minimal unit to the merge directory.
      minimal_unit_path = os.path.join(merge_directory_path, minimal_unit_hash)
      with open(minimal_unit_path, 'w+') as file_handle:
        file_handle.write(minimal_unit_contents)

      # Write the nonminimal unit to the corpus directory.
      corpus_directory = os.getenv('FUZZ_CORPUS_DIR')
      nonminimal_unit_path = os.path.join(corpus_directory,
                                          nonminimal_unit_hash)
      with open(nonminimal_unit_path, 'w+') as file_handle:
        file_handle.write(nonminimal_unit_contents)

      return merge_directory_path

    self.mock.create_merge_directory.side_effect = mocked_create_merge_directory
    run_launcher(testcase_path, fuzz_target_name, '-runs=10')
    corpus_directory = os.getenv('FUZZ_CORPUS_DIR')
    # Verify that both the newly found minimal testcase and the nonminimal
    # testcase are in the corpus.
    self.assertIn(minimal_unit_hash, os.listdir(corpus_directory))
    self.assertIn(nonminimal_unit_hash, os.listdir(corpus_directory))


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
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.VALUE_PROFILE_STRATEGY])

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
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.CORPUS_SUBSET_STRATEGY])
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
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.RANDOM_MAX_LENGTH_STRATEGY])
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
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.RANDOM_MAX_LENGTH_STRATEGY])
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
    """Test that we don't log when exit code indicates bug found in target."""

    def mocked_log_error(*args, **kwargs):  # pylint: disable=unused-argument
      self.assertNotIn(launcher.ENGINE_ERROR_MESSAGE, args)

    mock_log_error.side_effect = mocked_log_error
    testcase_path = setup_testcase_and_corpus(
        'empty', 'corpus_with_some_files', fuzz=True)
    os.environ['EXIT_FUZZER_CODE'] = exit_code
    run_launcher(testcase_path, 'exit_fuzzer', '-max_len=100')

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_with_mutator_plugin(self, mock_get_timeout):
    """Tests fuzzing with a mutator plugin. Wrapper around
    _test_fuzz_with_mutator_plugin."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    self._test_fuzz_with_mutator_plugin('nominijail-plugin')

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_merge_reductions(self, mock_get_timeout):
    """Tests merging reductions. Wrapper around _test_merge_reductions."""
    mock_get_timeout.return_value = get_fuzz_timeout(1.0)
    self._test_merge_reductions('nominijail-merge')


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

    self.assertIn('Test unit written to /crash-', output)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address '
        '0x000000000000', output)

    # Testcase (non-zero) should've been copied back.
    self.assertNotEqual(os.path.getsize(testcase_path), 0)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_from_subset(self, mock_get_timeout):
    """Tests fuzzing from corpus subset."""
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.CORPUS_SUBSET_STRATEGY, strategy.VALUE_PROFILE_STRATEGY])

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

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_fuzz_with_mutator_plugin(self, mock_get_timeout):
    """Tests fuzzing with a mutator plugin. Wrapper around
    _test_fuzz_with_mutator_plugin."""
    mock_get_timeout.return_value = get_fuzz_timeout(5.0)
    self._test_fuzz_with_mutator_plugin('minijail-plugin')

  @mock.patch('bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout')
  def test_merge_reductions(self, mock_get_timeout):
    """Tests merging. Wrapper around _test_merge_reductions."""
    mock_get_timeout.return_value = get_fuzz_timeout(1.0)
    self._test_merge_reductions('minijail-merge')


@test_utils.integration
@test_utils.with_cloud_emulators('datastore')
class TestLauncherFuchsia(BaseLauncherTest):
  """libFuzzer launcher tests (Fuchsia)."""

  def setUp(self):
    # Cannot simply call super(TestLauncherFuchsia).setUp, because the
    # with_cloud_emulators decorator modifies what the parent class would be.
    # Just explicitly call BaseLauncherTest's setUp.
    BaseLauncherTest.setUp(self)

    # Set up a Fuzzer.
    data_types.Fuzzer(
        revision=1,
        additional_environment_string=
        'FUCHSIA_RESOURCES_URL = gs://fuchsia-resources-05-20-2019/*\n'
        'FUCHSIA_BUILD_URL = gs://fuchsia-build-info-05-20-2019/*\n',
        builtin=True,
        differential=False,
        file_size='builtin',
        jobs=['libfuzzer_asan_test_fuzzer'],
        name='libFuzzer',
        source='builtin',
        max_testcases=4).put()

    # Set up a FuzzerJob.
    data_types.FuzzerJob(
        fuzzer='libFuzzer',
        job='libfuzzer_asan_test_fuzzer',
        platform='FUCHSIA',
        weight=1.0).put()

    # Set up a FuzzTarget
    data_types.FuzzTarget(
        binary='libfuzzer_asan_test_fuzzer',
        engine='libFuzzer',
        project='test-project').put()

    # Set up a FuzzTargetJob
    data_types.FuzzTargetJob(
        engine='libFuzzer',
        fuzz_target_name='libFuzzer_libfuzzer_asan_test_fuzzer',
        job='libfuzzer_asan_test_fuzzer',
        weight=1.0).put()

    # Set up a Job
    data_types.Job(
        environment_string=(
            'CUSTOM_BINARY = True\n'
            'FUCHSIA_RESOURCES_URL = gs://fuchsia-resources-05-20-2019/*\n'
            'FUCHSIA_BUILD_URL = gs://fuchsia-build-info-05-20-2019/*\n'
            'QUEUE_OVERRIDE=FUCHSIA\n'
            'OS_OVERRIDE=FUCHSIA'),
        name='libfuzzer_asan_test_fuzzer',
        platform='FUCHSIA',
        templates=['libfuzzer', 'engine_asan']).put()

    # Set up a JobTemplate
    data_types.JobTemplate(
        name='libfuzzer',
        environment_string=('APP_NAME = launcher.py\n'
                            'MAX_FUZZ_THREADS = 1\n'
                            'MAX_TESTCASES = 4\n'
                            'FUZZ_TEST_TIMEOUT = 4800\n'
                            'TEST_TIMEOUT = 30\n'
                            'WARMUP_TIMEOUT = 30\n'
                            'BAD_BUILD_CHECK = False\n'
                            'THREAD_ALIVE_CHECK_INTERVAL = 1\n'
                            'REPORT_OOMS_AND_HANGS = True\n'
                            'CORPUS_FUZZER_NAME_OVERRIDE = libFuzzer\n'
                            'ENABLE_GESTURES = False\n'
                            'THREAD_DELAY = 30.0')).put()

    # Set up another JobTemplate
    data_types.JobTemplate(
        name='engine_asan',
        environment_string=(
            'LSAN = True\n'
            'ADDITIONAL_ASAN_OPTIONS = quarantine_size_mb=64:strict_memcmp=1'
            ':symbolize=0:fast_unwind_on_fatal=0'
            ':allocator_release_to_os_interval_ms=500\n')).put()

    environment.set_value('QUEUE_OVERRIDE', 'FUCHSIA')
    environment.set_value('OS_OVERRIDE', 'FUCHSIA')
    environment.set_value('FUCHSIA_RESOURCES_URL',
                          'gs://fuchsia-resources-05-20-2019/*')
    environment.set_value('FUCHSIA_BUILD_URL',
                          'gs://fuchsia-build-info-05-20-2019/*')
    self.tmp_resources_dir = tempfile.mkdtemp()
    environment.set_value('RESOURCES_DIR', self.tmp_resources_dir)

  def tearDown(self):
    shutil.rmtree(self.tmp_resources_dir, ignore_errors=True)

  def test_fuzzer_can_boot_and_run(self):
    """Tests running a single round of fuzzing on a Fuchsia target, using
    'echo' in place of a fuzzing command."""
    # TODO(flowerhack): Fuchsia's `fuzz` only calls 'echo running on fuchsia!'
    # right now by default, but we'll call it explicitly in here as we
    # diversity `fuzz`'s functionality
    build_manager.setup_fuchsia_build()
    environment.set_value('FUZZ_TARGET', 'example_fuzzers/toy_fuzzer')
    testcase_path = setup_testcase_and_corpus('aaaa', 'empty_corpus', fuzz=True)
    output = run_launcher(testcase_path, 'test_fuzzer')
    self.assertIn(
        'localhost run \'fuchsia-pkg://fuchsia.com/example_fuzzers#meta/'
        'toy_fuzzer.cmx\'', output)
