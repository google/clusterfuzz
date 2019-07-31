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

import mock
import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from bot.fuzzers.libFuzzer import engine
from bot.fuzzers.libFuzzer import launcher
from system import new_process
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

TEST_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'launcher_test_data')


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

    self.assertDictEqual(
        {
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
            # TODO(ochang): Move strategy stats to common place, rather than in
            # engine implementation.
            'strategy_corpus_mutations_ml_rnn': 0,
            'strategy_corpus_mutations_radamsa': 0,
            'strategy_corpus_subset': 0,
            'strategy_dataflow_tracing': 0,
            'strategy_fork': 0,
            'strategy_mutator_plugin': 0,
            'strategy_random_max_len': 0,
            'strategy_recommended_dict': 0,
            'strategy_selection_method': 'default',
            'strategy_value_profile': 0,
            'timeout_count': 0,
            'timeout_limit': 123,
        },
        result.stats)
