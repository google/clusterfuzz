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
"""Tests for libFuzzer engine."""
# pylint: disable=unused-argument

from future import standard_library
standard_library.install_aliases()
import os
import shutil
import unittest

import mock
import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from bot.fuzzers import engine_common
from bot.fuzzers import libfuzzer
from bot.fuzzers import strategy_selection
from bot.fuzzers.libFuzzer import engine
from bot.fuzzers.libFuzzer import launcher
from fuzzing import strategy
from system import new_process
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEST_DIR = os.path.join(TEST_PATH, 'launcher_test_data')
TEMP_DIR = os.path.join(TEST_PATH, 'temp')
DATA_DIR = os.path.join(TEST_PATH, 'data')


class PrepareTest(fake_fs_unittest.TestCase):
  """Prepare() tests."""

  def setUp(self):
    # Set up fake filesystem.
    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

    test_helpers.patch(self, [
        'bot.fuzzers.engine_common.unpack_seed_corpus_if_needed',
    ])

    self.fs.create_dir('/inputs')
    self.fs.create_file('/path/target')
    self.fs.create_file('/path/blah.dict')
    self.fs.create_file('/path/target_seed_corpus.zip')
    self.fs.create_file(
        '/path/target.options',
        contents=('[libfuzzer]\n'
                  'max_len=31337\n'
                  'timeout=11\n'
                  'dict=blah.dict\n'))

    os.environ['FUZZ_INPUTS_DISK'] = '/inputs'

    test_helpers.patch(self, ['bot.fuzzers.libFuzzer.launcher.pick_strategies'])

    self.mock.pick_strategies.return_value = launcher.StrategyInfo(
        fuzzing_strategies=['strategy1', 'strategy2'],
        arguments=['-arg1'],
        additional_corpus_dirs=['/new_corpus_dir'],
        extra_env={'extra_env': '1'},
        use_dataflow_tracing=False,
        is_mutations_run=True)

  def test_prepare(self):
    """Test prepare."""
    engine_impl = engine.LibFuzzerEngine()
    options = engine_impl.prepare('/corpus_dir', '/path/target', '/path')
    self.assertEqual('/corpus_dir', options.corpus_dir)
    self.assertItemsEqual([
        '-max_len=31337', '-timeout=11', '-rss_limit_mb=2048', '-arg1',
        '-dict=/path/blah.dict'
    ], options.arguments)
    self.assertItemsEqual(['strategy1', 'strategy2'], options.strategies)
    self.assertItemsEqual(['/new_corpus_dir', '/corpus_dir'],
                          options.fuzz_corpus_dirs)
    self.assertDictEqual({'extra_env': '1'}, options.extra_env)
    self.assertFalse(options.use_dataflow_tracing)
    self.assertTrue(options.is_mutations_run)

    self.mock.unpack_seed_corpus_if_needed.assert_called_with(
        '/path/target', '/corpus_dir')

  def test_prepare_invalid_dict(self):
    """Test prepare with an invalid dict path."""
    with open('/path/target.options', 'w') as f:
      f.write('[libfuzzer]\n'
              'max_len=31337\n'
              'timeout=11\n'
              'dict=not_exist.dict\n')

    engine_impl = engine.LibFuzzerEngine()
    options = engine_impl.prepare('/corpus_dir', '/path/target', '/path')
    self.assertItemsEqual(
        ['-max_len=31337', '-timeout=11', '-rss_limit_mb=2048', '-arg1'],
        options.arguments)

  def test_prepare_auto_add_dict(self):
    """Test prepare automatically adding dict argument."""
    with open('/path/target.options', 'w') as f:
      f.write('[libfuzzer]\n' 'max_len=31337\n' 'timeout=11\n')
    self.fs.create_file('/path/target.dict')

    engine_impl = engine.LibFuzzerEngine()
    options = engine_impl.prepare('/corpus_dir', '/path/target', '/path')
    self.assertItemsEqual([
        '-max_len=31337', '-timeout=11', '-rss_limit_mb=2048', '-arg1',
        '-dict=/path/target.dict'
    ], options.arguments)


class FuzzTest(fake_fs_unittest.TestCase):
  """Fuzz() tests."""

  def setUp(self):
    # Set up fake filesystem.
    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

    self.fs.create_dir('/corpus')
    self.fs.create_dir('/fuzz-inputs')
    self.fs.create_dir('/fake')
    self.fs.create_file('/target')
    self.fs.add_real_directory(TEST_DIR)

    test_helpers.patch(self, [
        'bot.fuzzers.libfuzzer.LibFuzzerRunner.fuzz',
        'bot.fuzzers.libfuzzer.LibFuzzerRunner.merge',
        'os.getpid',
    ])

    os.environ['JOB_NAME'] = 'libfuzzer_asan_job'
    os.environ['FUZZ_INPUTS_DISK'] = '/fuzz-inputs'

    self.mock.getpid.return_value = 9001
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_fuzz(self):
    """Test fuzz."""
    engine_impl = engine.LibFuzzerEngine()
    options = engine.LibFuzzerOptions(
        '/corpus',
        ['-arg=1', '-timeout=123', '-dict=blah.dict', '-max_len=9001'], [],
        ['/corpus'], {}, False, False)

    with open(os.path.join(TEST_DIR, 'crash.txt')) as f:
      fuzz_output = f.read()

    def mock_fuzz(*args, **kwargs):  # pylint: disable=unused-argument
      """Mock fuzz."""
      self.fs.create_file('/fuzz-inputs/temp-9001/new/A')
      self.fs.create_file('/fuzz-inputs/temp-9001/new/B')
      return new_process.ProcessResult(
          command='command',
          return_code=0,
          output=fuzz_output,
          time_executed=2.0,
          timed_out=False)

    def mock_merge(*args, **kwargs):  # pylint: disable=unused-argument
      """Mock merge."""
      self.fs.create_file('/fuzz-inputs/temp-9001/merge-corpus/A')
      return new_process.ProcessResult(
          command='merge-command',
          return_code=0,
          output='merge',
          time_executed=2.0,
          timed_out=False)

    self.mock.fuzz.side_effect = mock_fuzz
    self.mock.merge.side_effect = mock_merge

    result = engine_impl.fuzz('/target', options, '/fake', 3600)
    self.assertEqual(1, len(result.crashes))
    self.assertEqual(fuzz_output, result.logs)

    crash = result.crashes[0]
    self.assertEqual('/fake/crash-1e15825e6f0b2240a5af75d84214adda1b6b5340',
                     crash.input_path)
    self.assertEqual(fuzz_output, crash.stacktrace)
    self.assertItemsEqual(['-arg=1', '-timeout=123'], crash.reproduce_args)
    self.assertEqual(2, crash.crash_time)

    self.mock.fuzz.assert_called_with(
        mock.ANY, ['/fuzz-inputs/temp-9001/new', '/corpus'],
        additional_args=[
            '-arg=1', '-timeout=123', '-dict=blah.dict', '-max_len=9001',
            '-artifact_prefix=/fake/'
        ],
        extra_env={},
        fuzz_timeout=1470.0)

    self.mock.merge.assert_called_with(
        mock.ANY, [
            '/fuzz-inputs/temp-9001/merge-corpus', '/fuzz-inputs/temp-9001/new',
            '/corpus'
        ],
        additional_args=['-arg=1', '-timeout=123'],
        merge_timeout=1800.0,
        tmp_dir='/fuzz-inputs/temp-9001/merge-workdir')

    self.assertDictEqual({
        'actual_duration': 2,
        'average_exec_per_sec': 21,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_size': 0,
        'crash_count': 1,
        'dict_used': 1,
        'edge_coverage': 1603,
        'edges_total': 398467,
        'expected_duration': 1450,
        'feature_coverage': 3572,
        'fuzzing_time_percent': 0.13793103448275862,
        'initial_edge_coverage': 1603,
        'initial_feature_coverage': 3572,
        'leak_count': 0,
        'log_lines_from_engine': 2,
        'log_lines_ignored': 67,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 9001,
        'merge_edge_coverage': 0,
        'new_edges': 0,
        'new_features': 0,
        'new_units_added': 1,
        'new_units_generated': 0,
        'number_of_executed_units': 1249,
        'oom_count': 0,
        'peak_rss_mb': 1197,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'timeout_count': 0,
        'timeout_limit': 123,
        'strategy_selection_method': 'default',
    }, result.stats)


def set_strategy_pool(strategies=None):
  """Helper method to create instances of strategy pools
  for patching use."""
  strategy_pool = strategy_selection.StrategyPool()

  if strategies is not None:
    for strategy_tuple in strategies:
      strategy_pool.add_strategy(strategy_tuple)

  return strategy_pool


def mock_random_choice(seq):
  """Always returns first element from the sequence."""
  # We could try to mock a particular |seq| to be a list with a single element,
  # but it does not work well, as random_choice returns a 'mock.mock.MagicMock'
  # object that behaves differently from the actual type of |seq[0]|.
  return seq[0]


def clear_temp_dir():
  """Clear temp directory."""
  if os.path.exists(TEMP_DIR):
    shutil.rmtree(TEMP_DIR)

  os.mkdir(TEMP_DIR)


def setup_testcase_and_corpus(testcase, corpus):
  """Setup testcase and corpus."""
  clear_temp_dir()
  copied_testcase_path = os.path.join(TEMP_DIR, testcase)
  shutil.copy(os.path.join(DATA_DIR, testcase), copied_testcase_path)

  copied_corpus_path = os.path.join(TEMP_DIR, corpus)
  src_corpus_path = os.path.join(DATA_DIR, corpus)

  if os.path.exists(src_corpus_path):
    shutil.copytree(src_corpus_path, copied_corpus_path)
  else:
    os.mkdir(copied_corpus_path)

  return copied_testcase_path, copied_corpus_path


def get_fuzz_timeout(fuzz_time):
  """Return timeout for fuzzing."""
  return (fuzz_time + libfuzzer.LibFuzzerCommon.LIBFUZZER_CLEAN_EXIT_TIME +
          libfuzzer.LibFuzzerCommon.SIGTERM_WAIT_TIME)


@test_utils.integration
class IntegrationTests(unittest.TestCase):
  """Base libFuzzer launcher tests."""

  def setUp(self):
    test_helpers.patch_environ(self)

    os.environ['BUILD_DIR'] = DATA_DIR
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['FUZZ_INPUTS_DISK'] = TEMP_DIR
    os.environ['FUZZ_TEST_TIMEOUT'] = '4800'
    os.environ['JOB_NAME'] = 'libfuzzer_asan'
    os.environ['INPUT_DIR'] = TEMP_DIR

    test_helpers.patch(self, [
        'bot.fuzzers.engine_common.get_merge_timeout',
        'bot.fuzzers.engine_common.random_choice',
        'bot.fuzzers.mutator_plugin._download_mutator_plugin_archive',
        'bot.fuzzers.mutator_plugin._get_mutator_plugins_from_bucket',
        'bot.fuzzers.strategy_selection.generate_weighted_strategy_pool',
        'bot.fuzzers.libFuzzer.launcher.get_dictionary_analysis_timeout',
        'bot.fuzzers.libFuzzer.launcher.get_fuzz_timeout',
        'os.getpid',
    ])

    self.mock.getpid.return_value = 1337

    self.mock._get_mutator_plugins_from_bucket.return_value = []  # pylint: disable=protected-access
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool()
    self.mock.get_dictionary_analysis_timeout.return_value = 5
    self.mock.get_merge_timeout.return_value = 10
    self.mock.random_choice.side_effect = mock_random_choice

  def assert_has_stats(self, stats):
    """Asserts that libFuzzer stats are in output."""
    self.assertIn('number_of_executed_units', stats)
    self.assertIn('average_exec_per_sec', stats)
    self.assertIn('new_units_added', stats)
    self.assertIn('slowest_unit_time_sec', stats)
    self.assertIn('peak_rss_mb', stats)

  def test_single_testcase_crash(self):
    """Tests launcher with a crashing testcase."""
    testcase_path, _ = setup_testcase_and_corpus('crash', 'empty_corpus')
    engine_impl = engine.LibFuzzerEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    result = engine_impl.reproduce(target_path, testcase_path, [], 30)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000',
        result.output)

  @test_utils.slow
  def test_fuzz_no_crash(self):
    """Tests fuzzing (no crash)."""
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.VALUE_PROFILE_STRATEGY])

    self.mock.get_fuzz_timeout.return_value = get_fuzz_timeout(5.0)
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.LibFuzzerEngine()

    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)

    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assert_has_stats(results.stats)
    self.assertListEqual([
        os.path.join(DATA_DIR, 'test_fuzzer'),
        '-max_len=256',
        '-timeout=25',
        '-rss_limit_mb=2048',
        '-use_value_profile=1',
        '-artifact_prefix=' + TEMP_DIR + '/',
        '-max_total_time=5',
        '-print_final_stats=1',
        os.path.join(TEMP_DIR, 'temp-1337/new'),
        os.path.join(TEMP_DIR, 'corpus'),
    ], results.command)
    self.assertEqual(0, len(results.crashes))

    # New items should've been added to the corpus.
    self.assertNotEqual(0, len(os.listdir(corpus_path)))

  def test_fuzz_crash(self):
    """Tests fuzzing (crash)."""
    self.mock.get_fuzz_timeout.return_value = get_fuzz_timeout(5.0)
    _, corpus_path = setup_testcase_and_corpus('empty', 'corpus')
    engine_impl = engine.LibFuzzerEngine()

    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'always_crash_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)

    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assert_has_stats(results.stats)
    self.assertListEqual([
        os.path.join(DATA_DIR, 'always_crash_fuzzer'),
        '-max_len=100',
        '-timeout=25',
        '-rss_limit_mb=2048',
        '-artifact_prefix=' + TEMP_DIR + '/',
        '-max_total_time=5',
        '-print_final_stats=1',
        os.path.join(TEMP_DIR, 'temp-1337/new'),
        os.path.join(TEMP_DIR, 'corpus'),
    ], results.command)
    self.assertEqual(1, len(results.crashes))

    self.assertEqual(TEMP_DIR, os.path.dirname(results.crashes[0].input_path))
    self.assertEqual(results.logs, results.crashes[0].stacktrace)
    self.assertListEqual([
        '-timeout=25',
        '-rss_limit_mb=2048',
    ], results.crashes[0].reproduce_args)

    self.assertIn('Test unit written to {0}/crash-'.format(TEMP_DIR),
                  results.logs)
    self.assertIn(
        'ERROR: AddressSanitizer: SEGV on unknown address '
        '0x000000000000', results.logs)

  def test_fuzz_from_subset(self):
    """Tests fuzzing from corpus subset."""
    self.mock.generate_weighted_strategy_pool.return_value = set_strategy_pool(
        [strategy.CORPUS_SUBSET_STRATEGY])
    self.mock.get_fuzz_timeout.return_value = get_fuzz_timeout(5.0)

    _, corpus_path = setup_testcase_and_corpus('empty',
                                               'corpus_with_some_files')

    engine_impl = engine.LibFuzzerEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR, 'test_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    results = engine_impl.fuzz(target_path, options, TEMP_DIR, 10)

    self.assertListEqual([
        os.path.join(DATA_DIR, 'test_fuzzer'),
        '-max_len=256',
        '-timeout=25',
        '-rss_limit_mb=2048',
        '-artifact_prefix=' + TEMP_DIR + '/',
        '-max_total_time=5',
        '-print_final_stats=1',
        os.path.join(TEMP_DIR, 'temp-1337/new'),
        os.path.join(TEMP_DIR, 'temp-1337/subset'),
    ], results.command)

    self.assert_has_stats(results.stats)

  def test_minimize(self):
    """Tests minimize."""
    testcase_path, _ = setup_testcase_and_corpus('aaaa', 'empty_corpus')
    minimize_output_path = os.path.join(TEMP_DIR, 'minimized_testcase')

    engine_impl = engine.LibFuzzerEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'crash_with_A_fuzzer')
    result = engine_impl.minimize_testcase(target_path, [], testcase_path,
                                           minimize_output_path, 30)
    self.assertTrue(result)
    self.assertTrue(os.path.exists(minimize_output_path))
    with open(minimize_output_path) as f:
      result = f.read()
      self.assertEqual('A', result)

  def test_cleanse(self):
    """Tests cleanse."""
    testcase_path, _ = setup_testcase_and_corpus('aaaa', 'empty_corpus')
    cleanse_output_path = os.path.join(TEMP_DIR, 'cleansed_testcase')

    engine_impl = engine.LibFuzzerEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'crash_with_A_fuzzer')
    result = engine_impl.cleanse(target_path, [], testcase_path,
                                 cleanse_output_path, 30)
    self.assertTrue(result)
    self.assertTrue(os.path.exists(cleanse_output_path))
    with open(cleanse_output_path) as f:
      result = f.read()
      self.assertFalse(all(c == 'A' for c in result))

  @mock.patch('bot.fuzzers.dictionary_manager.DictionaryManager.'
              'parse_recommended_dictionary_from_log_lines')
  def test_analyze_dict(self, mock_parse_recommended_dictionary):
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
    self.mock.get_fuzz_timeout.return_value = get_fuzz_timeout(5.0)

    _, corpus_path = setup_testcase_and_corpus('empty',
                                               'corpus_with_some_files')

    test_helpers.patch(self, [
        'bot.fuzzers.dictionary_manager.DictionaryManager.'
        'update_recommended_dictionary',
    ])

    engine_impl = engine.LibFuzzerEngine()
    target_path = engine_common.find_fuzzer_path(DATA_DIR,
                                                 'analyze_dict_fuzzer')
    options = engine_impl.prepare(corpus_path, target_path, DATA_DIR)
    engine_impl.fuzz(target_path, options, TEMP_DIR, 10)
    expected_recommended_dictionary = set([
        '"APPLE"',
        '"GINGER"',
        '"BEET"',
    ])

    self.assertIn(expected_recommended_dictionary,
                  self.mock.update_recommended_dictionary.call_args[0])

  # TODO(ochang): Move fuchsia tests here once everything is migrated.
