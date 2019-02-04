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
"""Tests for libFuzzer launcher script."""
# pylint: disable=unused-argument

import copy
import os
import shutil
from StringIO import StringIO
import unittest

import mock
import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from bot.fuzzers import engine_common
from bot.fuzzers import libfuzzer
from bot.fuzzers import strategy
from bot.fuzzers.libFuzzer import constants
from bot.fuzzers.libFuzzer import launcher
from bot.fuzzers.libFuzzer import stats
from metrics import fuzzer_stats
from system import environment
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), 'launcher_test_data')

BOT_NAME = 'test-bot'
BUILD_DIR = '/fake/build_dir'
FUZZ_INPUTS_DISK = '/fake/inputs-disk'
GSUTIL_PATH = '/fake/gsutil_path'
FAKE_ROOT_DIR = '/fake_root'


def _read_test_data(name):
  """Read test data."""
  data_path = os.path.join(TESTDATA_PATH, name)
  with open(data_path) as f:
    return f.read()


def read_data_from_file(file_path):
  """Reads data from file."""
  with open(file_path, 'rb') as file_handle:
    return file_handle.read()


def create_mock_popen(output,
                      corpus_path=None,
                      merge_corpus_path=None,
                      number_of_testcases=0,
                      return_code=0):
  """Creates a mock subprocess.Popen."""

  class MockPopen(object):
    """Mock subprocess.Popen."""
    commands = []
    testcases_written = []

    def __init__(self, command, *args, **kwargs):
      """Inits the MockPopen."""
      stdout = kwargs.pop('stdout', None)
      self.command = command
      self.commands.append(command)
      self.stdout = None
      self.return_code = return_code
      if hasattr(stdout, 'write'):
        self.stdout = stdout

    def _do_merge(self):
      """Mock merge."""
      if not corpus_path or not merge_corpus_path:
        return

      for filepath in os.listdir(corpus_path):
        shutil.copy(os.path.join(corpus_path, filepath), merge_corpus_path)

    def _write_fake_units(self):
      """Mock writing of new units."""
      for i in xrange(number_of_testcases):
        with open(os.path.join(corpus_path, str(i)), 'w') as f:
          f.write(str(i))

        self.testcases_written.append(str(i))

    def communicate(self, input_data=None):
      """Mock subprocess.Popen.communicate."""
      if self.command[0].endswith('_fuzzer'):
        if '-merge=1' in self.command:
          # Mock merge.
          self._do_merge()
        else:
          # Mock writing of new units.
          self._write_fake_units()

      if self.stdout:
        self.stdout.write(output)
      return None, None

    def poll(self, input_data=None):
      """Mock subprocess.Popen.poll."""
      return self.return_code

  return MockPopen


def mock_create_tmp_mount(base_dir):
  """Mock minijail._create_tmp_mount."""
  path = os.path.join(base_dir, 'TEMP')
  os.mkdir(path)
  return path


def mock_create_chroot_dir(base_dir):
  """Mock minijail._create_chroot_dir."""
  path = os.path.join(base_dir, 'CHROOT')
  os.mkdir(path)
  return path


@mock.patch('bot.fuzzers.engine_common.current_timestamp', lambda: 1337.0)
@mock.patch('system.minijail._create_tmp_mount', mock_create_tmp_mount)
@mock.patch('system.minijail._create_chroot_dir', mock_create_chroot_dir)
@mock.patch('system.minijail.os.getuid', lambda: 1000)
class LauncherTest(fake_fs_unittest.TestCase):
  """Launcher script tests."""

  def setUp(self):
    """Set up test environment."""
    self.maxDiff = None  # pylint: disable=invalid-name
    test_helpers.patch_environ(self)

    os.environ['APP_REVISION'] = '1337'
    os.environ['BOT_NAME'] = BOT_NAME
    os.environ['FUZZ_INPUTS_DISK'] = FUZZ_INPUTS_DISK
    os.environ['FUZZ_LOGS_BUCKET'] = 'fuzz-logs-bucket'
    os.environ['FUZZ_TEST_TIMEOUT'] = '4800'
    os.environ['GSUTIL_PATH'] = GSUTIL_PATH
    os.environ['JOB_NAME'] = 'job_name'
    os.environ['ROOT_DIR'] = FAKE_ROOT_DIR
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['INPUT_DIR'] = '/inputs'

    # Load test data from real filesystem.
    self.no_crash_output = _read_test_data('no_crash.txt')
    self.no_crash_output_with_strategies = _read_test_data(
        'no_crash_with_strategies.txt')
    self.crash_output = _read_test_data('crash.txt')
    self.startup_crash_output = _read_test_data('startup_crash.txt')
    self.corpus_crash_output = _read_test_data('corpus_crash.txt')
    self.corpus_crash_with_corpus_subset_output = _read_test_data(
        'corpus_crash_with_corpus_subset.txt')
    self.corrupted_stats_output = _read_test_data('corrupted_stats.txt')
    self.oom_output = _read_test_data('oom.txt')
    self.expected_oom_output = _read_test_data('oom_expected.txt')
    self.timeout_output = _read_test_data('timeout.txt')

    self.options_data = _read_test_data('fake_fuzzer.options')
    self.dictionary_data = _read_test_data('fake_fuzzer.dict')

    self.analyze_dict_log = _read_test_data('log_for_dictionary_analysis.txt')
    self.analyze_dict_output = _read_test_data('dictionary_analysis_output.txt')

    # Set up fake filesystem.
    test_utils.set_up_pyfakefs(self)

    self.fs.CreateDirectory(FUZZ_INPUTS_DISK)
    self.fs.CreateDirectory(GSUTIL_PATH)

    os.environ['BUILD_DIR'] = BUILD_DIR

    self.fs.CreateFile(os.path.join(BUILD_DIR, 'fake_fuzzer'))
    self.fs.CreateFile('/dev/null')
    self.fs.CreateFile('/bin/sh')
    self.fs.CreateDirectory('/lib')
    self.fs.CreateDirectory('/lib64')
    self.fs.CreateDirectory('/proc')
    self.fs.CreateDirectory('/usr/lib')
    self.fs.CreateDirectory(FAKE_ROOT_DIR)
    self.fs.CreateDirectory(os.path.join(FAKE_ROOT_DIR, 'bot', 'logs'))
    self.fs.CreateFile(
        os.path.join(FAKE_ROOT_DIR, 'resources', 'platform',
                     environment.platform().lower(), 'llvm-symbolizer'))

    test_helpers.patch(self, [
        'atexit.register',
        'base.utils.default_project_name',
        'bot.fuzzers.engine_common.do_corpus_subset',
        'bot.fuzzers.libFuzzer.launcher.do_ml_rnn_generator',
        'bot.fuzzers.libFuzzer.launcher.do_radamsa_generator',
        'bot.fuzzers.libFuzzer.launcher.do_random_max_length',
        'bot.fuzzers.libFuzzer.launcher.do_recommended_dictionary',
        'bot.fuzzers.libFuzzer.launcher.do_value_profile',
        'os.getpid',
    ])

    # Prevent errors from occurring after tests complete by preventing the
    # launcher script from registering exit handlers.
    self.mock.register.side_effect = lambda func, *args, **kwargs: func

    environment.set_value('PROJECT_NAME', 'default-proj')
    self.mock.default_project_name.return_value = 'default-proj'
    self.mock.getpid.return_value = 1337

    self.mock.do_corpus_subset.return_value = False
    self.mock.do_ml_rnn_generator.return_value = False
    self.mock.do_radamsa_generator.return_value = False
    self.mock.do_random_max_length.return_value = False
    self.mock.do_recommended_dictionary.return_value = False
    self.mock.do_value_profile.return_value = False

  @mock.patch('google_cloud_utils.storage.exists', lambda x: None)
  @mock.patch('google_cloud_utils.storage.read_data', lambda x: None)
  @mock.patch('google_cloud_utils.storage.write_data', lambda x, y: None)
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_analyze_recommended_dictionary(self, mock_stdout):
    """Test analysis of recommended dictionary."""
    self.fs.CreateDirectory('/fake/inputs-disk/temp-1337')
    log_lines = self.analyze_dict_log.splitlines()

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.analyze_dict_output)) as mock_popen:
      runner = libfuzzer.get_runner('fuzzer_path')
      result = launcher.analyze_and_update_recommended_dictionary(
          runner, 'fuzzer_name', log_lines, 'corpus_dir', ['arg1', 'arg2'])

      self.assertEqual(mock_popen.commands, [[
          'fuzzer_path',
          'arg1',
          'arg2',
          '-analyze_dict=1',
          '-dict=/fake/inputs-disk/temp-1337/fuzzer_name.dict.tmp',
          'corpus_dir',
      ]])

      expected_dictionary = set([
          '"\\x00\\x00\\x00\\x00"',
          '"\\x00\\x00"',
          '"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"',
      ])
      self.assertEqual(result, expected_dictionary)

  @mock.patch('sys.stdout', new_callable=StringIO)
  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  def test_basic_fuzz(self, mock_stdout):
    """Test a basic fuzzing run."""
    self.fs.CreateDirectory('/fake/corpus_basic')
    self.fs.CreateFile('/fake/testcase_basic')

    self.fs.CreateFile(
        os.path.join(BUILD_DIR, 'fake_fuzzer.options'),
        contents=self.options_data)
    os.environ['ASAN_OPTIONS'] = 'blah=1:foo=0'
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_basic'

    # The value below differs from the value in no_crash_output (44). We expect
    # to see this number of new_unit_added in stats, not the parsed value.
    new_units_added = 11
    with mock.patch(
        'subprocess.Popen',
        create_mock_popen(self.no_crash_output_with_strategies,
                          '/fake/inputs-disk/temp-1337/new',
                          '/fake/corpus_basic', new_units_added)) as mock_popen:

      launcher.main([
          'launcher.py',
          '/fake/testcase_basic',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/fake/', '-max_total_time=2650',
          '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_basic'
      ], [
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/fake/corpus_basic',
          '/fake/inputs-disk/temp-1337/new'
      ]])

      # Check new testcases added.
      self.assertEqual(
          sorted(os.listdir('/fake/corpus_basic')),
          sorted(mock_popen.testcases_written))

      for corpus_file in os.listdir('/fake/corpus_basic'):
        with open(os.path.join('/fake/corpus_basic', corpus_file)) as f:
          self.assertEqual(f.read(), corpus_file)

      # Check stats.
      stats_data = fuzzer_stats.TestcaseRun.read_from_disk(
          '/fake/testcase_basic')
      self.assertDictEqual(
          stats_data.data,
          {
              'actual_duration':
                  0,
              'average_exec_per_sec':
                  97,
              'bad_instrumentation':
                  0,
              'build_revision':
                  1337,
              'command': [
                  '/fake/build_dir/fake_fuzzer', '-max_len=80',
                  '-rss_limit_mb=2048', '-timeout=25',
                  '-artifact_prefix=/fake/', '-max_total_time=2650',
                  '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
                  '/fake/corpus_basic'
              ],
              'corpus_crash_count':
                  0,
              'crash_count':
                  0,
              'corpus_size':
                  11,
              # No corpus_rss_mb due to corpus subset strategy.
              'dict_used':
                  1,
              'edge_coverage':
                  1769,
              'edges_total':
                  398408,
              'feature_coverage':
                  4958,
              'initial_edge_coverage':
                  1769,
              'initial_feature_coverage':
                  4958,
              'expected_duration':
                  2650,
              'fuzzer':
                  u'libfuzzer_fake_fuzzer',
              'fuzzing_time_percent':
                  0.0,
              'job':
                  u'job_name',
              'kind':
                  u'TestcaseRun',
              'leak_count':
                  0,
              'log_lines_from_engine':
                  65,
              'log_lines_ignored':
                  8,
              'log_lines_unwanted':
                  0,
              'manual_dict_size':
                  0,
              'max_len':
                  80,
              'merge_edge_coverage':
                  1769,
              'merge_new_features':
                  0,
              'merge_new_files':
                  0,
              'new_units_added':
                  11,
              'new_units_generated':
                  55,
              'number_of_executed_units':
                  258724,
              'oom_count':
                  0,
              'peak_rss_mb':
                  103,
              'recommended_dict_size':
                  0,
              'slow_unit_count':
                  0,
              'slow_units_count':
                  0,
              'slowest_unit_time_sec':
                  0,
              'startup_crash_count':
                  0,
              'strategy_corpus_mutations_radamsa':
                  1,
              'strategy_corpus_mutations_ml_rnn':
                  0,
              'strategy_corpus_subset':
                  50,
              'strategy_random_max_len':
                  1,
              'strategy_recommended_dict':
                  0,
              'strategy_value_profile':
                  0,
              'timeout_count':
                  0,
              'timeout_limit':
                  25,
              'timestamp':
                  1337.0
          })

      # Output printed.
      self.assertIn(self.no_crash_output_with_strategies,
                    mock_stdout.getvalue())
      expected_command = (
          'Command: /fake/build_dir/fake_fuzzer '
          '-max_len=80 -rss_limit_mb=2048 -timeout=25 -artifact_prefix=/fake/ '
          '-max_total_time=2650 -print_final_stats=1 '
          '/fake/inputs-disk/temp-1337/new /fake/corpus_basic')
      self.assertIn(expected_command, mock_stdout.getvalue())
      self.assertIn('Bot: test-bot', mock_stdout.getvalue())
      self.assertIn('Time ran:', mock_stdout.getvalue())
      self.assertIn('detect_leaks=0', os.environ['ASAN_OPTIONS'])
      self.assertIn('fake_option=1', os.environ['ASAN_OPTIONS'])
      self.assertIn('foo=0', os.environ['ASAN_OPTIONS'])
      self.assertIn('blah=1', os.environ['ASAN_OPTIONS'])

      os.remove(os.path.join(BUILD_DIR, 'fake_fuzzer.options'))

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: True)
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_basic_fuzz_with_custom_options(self, mock_stdout):
    """Test a basic fuzzing run with custom options provided."""
    self.mock.do_recommended_dictionary.return_value = True

    self.fs.CreateDirectory('/fake/corpus_basic')
    self.fs.CreateFile('/fake/testcase_basic')

    self.fs.CreateFile(
        os.path.join(BUILD_DIR, 'fake_fuzzer.options'),
        contents=self.options_data)
    self.fs.CreateFile(
        os.path.join(BUILD_DIR, 'fake_fuzzer.dict'),
        contents=self.dictionary_data)
    os.environ['ASAN_OPTIONS'] = 'blah=1:foo=0'
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_basic'

    # The value below differs from the value in no_crash_output (44). We expect
    # to see this number of new_unit_added in stats, not the parsed value.
    new_units_added = 11
    with mock.patch(
        'subprocess.Popen',
        create_mock_popen(self.no_crash_output,
                          '/fake/inputs-disk/temp-1337/new',
                          '/fake/corpus_basic', new_units_added)) as mock_popen:

      launcher.main([
          'launcher.py',
          '/fake/testcase_basic',
          'fake_fuzzer',
          '-max_len=80',
          '-timeout=33',
          '-only_ascii=1',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-timeout=33',
          '-only_ascii=1',
          '-rss_limit_mb=2048',
          '-dict=/fake/build_dir/fake_fuzzer.dict',
          '-artifact_prefix=/fake/',
          '-max_total_time=2650',
          '-print_final_stats=1',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_basic',
      ], [
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-timeout=33',
          '-only_ascii=1',
          '-rss_limit_mb=2048',
          '-dict=/fake/build_dir/fake_fuzzer.dict',
          '-merge=1',
          '/fake/corpus_basic',
          '/fake/inputs-disk/temp-1337/new',
      ]])

      # Check new testcases added.
      self.assertEqual(
          sorted(os.listdir('/fake/corpus_basic')),
          sorted(mock_popen.testcases_written))

      for corpus_file in os.listdir('/fake/corpus_basic'):
        with open(os.path.join('/fake/corpus_basic', corpus_file)) as f:
          self.assertEqual(f.read(), corpus_file)

      # Check stats.
      stats_data = fuzzer_stats.TestcaseRun.read_from_disk(
          '/fake/testcase_basic')
      self.assertDictEqual(
          stats_data.data, {
              'actual_duration':
                  0,
              'average_exec_per_sec':
                  97,
              'bad_instrumentation':
                  0,
              'build_revision':
                  1337,
              'command': [
                  '/fake/build_dir/fake_fuzzer', '-max_len=80', '-timeout=33',
                  '-only_ascii=1', '-rss_limit_mb=2048',
                  '-dict=/fake/build_dir/fake_fuzzer.dict',
                  '-artifact_prefix=/fake/', '-max_total_time=2650',
                  '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
                  '/fake/corpus_basic'
              ],
              'corpus_crash_count':
                  0,
              'corpus_size':
                  11,
              'corpus_rss_mb':
                  56,
              'crash_count':
                  0,
              'dict_used':
                  1,
              'edge_coverage':
                  1769,
              'edges_total':
                  398408,
              'feature_coverage':
                  4958,
              'initial_edge_coverage':
                  1769,
              'initial_feature_coverage':
                  4958,
              'expected_duration':
                  2650,
              'fuzzer':
                  u'libfuzzer_fake_fuzzer',
              'fuzzing_time_percent':
                  0.0,
              'job':
                  u'job_name',
              'kind':
                  u'TestcaseRun',
              'leak_count':
                  0,
              'log_lines_from_engine':
                  65,
              'log_lines_ignored':
                  8,
              'log_lines_unwanted':
                  0,
              'manual_dict_size':
                  4,
              'max_len':
                  80,
              'merge_edge_coverage':
                  1769,
              'merge_new_features':
                  0,
              'merge_new_files':
                  0,
              'new_units_added':
                  11,
              'new_units_generated':
                  55,
              'number_of_executed_units':
                  258724,
              'oom_count':
                  0,
              'peak_rss_mb':
                  103,
              'recommended_dict_size':
                  5,
              'slow_unit_count':
                  0,
              'slow_units_count':
                  0,
              'slowest_unit_time_sec':
                  0,
              'startup_crash_count':
                  0,
              'strategy_corpus_mutations_radamsa':
                  0,
              'strategy_corpus_mutations_ml_rnn':
                  0,
              'strategy_corpus_subset':
                  0,
              'strategy_random_max_len':
                  0,
              'strategy_recommended_dict':
                  1,
              'strategy_value_profile':
                  0,
              'timeout_count':
                  0,
              'timeout_limit':
                  33,
              'timestamp':
                  1337.0
          })

      # Output printed.
      self.assertIn(self.no_crash_output, mock_stdout.getvalue())
      expected_command = (
          'Command: /fake/build_dir/fake_fuzzer '
          '-max_len=80 -timeout=33 -only_ascii=1 '
          '-rss_limit_mb=2048 -dict=/fake/build_dir/fake_fuzzer.dict '
          '-artifact_prefix=/fake/ -max_total_time=2650 -print_final_stats=1 '
          '/fake/inputs-disk/temp-1337/new /fake/corpus_basic')
      self.assertIn(expected_command, mock_stdout.getvalue())
      self.assertIn('Bot: test-bot', mock_stdout.getvalue())
      self.assertIn('Time ran:', mock_stdout.getvalue())
      self.assertIn('detect_leaks=0', os.environ['ASAN_OPTIONS'])
      self.assertIn('fake_option=1', os.environ['ASAN_OPTIONS'])
      self.assertIn('foo=0', os.environ['ASAN_OPTIONS'])
      self.assertIn('blah=1', os.environ['ASAN_OPTIONS'])

      os.remove(os.path.join(BUILD_DIR, 'fake_fuzzer.options'))

  def test_parse_log_stats(self):
    """Test pure stats parsing without applying of stat_overrides."""
    log_lines = self.no_crash_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    expected_stats = {
        'average_exec_per_sec': 97,
        'new_units_added': 55,
        'new_units_generated': 55,
        'number_of_executed_units': 258724,
        'peak_rss_mb': 103,
        'slowest_unit_time_sec': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_no_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.no_crash_output_with_strategies.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 97,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'crash_count': 0,
        'corpus_size': 0,
        # No corpus_rss_mb due to corpus subset strategy.
        'dict_used': 1,
        'edge_coverage': 1769,
        'edges_total': 398408,
        'feature_coverage': 4958,
        'initial_edge_coverage': 1769,
        'initial_feature_coverage': 4958,
        'leak_count': 0,
        'log_lines_from_engine': 65,
        'log_lines_ignored': 8,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 741802,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 55,
        'new_units_generated': 55,
        'number_of_executed_units': 258724,
        'oom_count': 0,
        'peak_rss_mb': 103,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 1,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 50,
        'strategy_random_max_len': 1,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.crash_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(
        stats.parse_performance_features(log_lines, [], ['-max_len=1337']))
    expected_stats = {
        'average_exec_per_sec': 21,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_rss_mb': 56,
        'corpus_size': 0,
        'crash_count': 1,
        'dict_used': 1,
        'edge_coverage': 1603,
        'edges_total': 398467,
        'feature_coverage': 3572,
        'initial_edge_coverage': 1603,
        'initial_feature_coverage': 3572,
        'leak_count': 0,
        'log_lines_from_engine': 2,
        'log_lines_ignored': 67,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 1337,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'number_of_executed_units': 1249,
        'oom_count': 0,
        'peak_rss_mb': 1197,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_startup_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.startup_crash_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(
        stats.parse_performance_features(log_lines, [], ['-max_len=1337']))
    expected_stats = {
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_rss_mb': 0,
        'corpus_size': 0,
        'crash_count': 0,
        'dict_used': 0,
        'edge_coverage': 0,
        'edges_total': 0,
        'feature_coverage': 0,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 0,
        'log_lines_ignored': 1,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 1337,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'oom_count': 0,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'startup_crash_count': 1,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_corpus_crash(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.corpus_crash_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 0,
        'bad_instrumentation': 0,
        'corpus_crash_count': 1,
        'corpus_rss_mb': 109,
        'corpus_size': 0,
        'crash_count': 1,
        'dict_used': 0,
        'edge_coverage': 0,
        'edges_total': 544079,
        'feature_coverage': 0,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 0,
        'log_lines_ignored': 22,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 4096,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'number_of_executed_units': 2,
        'oom_count': 0,
        'peak_rss_mb': 111,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_corpus_crash_with_corpus_subset(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.corpus_crash_with_corpus_subset_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 0,
        'bad_instrumentation': 0,
        'corpus_crash_count': 1,
        'corpus_size': 0,
        'crash_count': 1,
        'dict_used': 0,
        'edge_coverage': 0,
        'edges_total': 544079,
        'feature_coverage': 0,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 0,
        'log_lines_ignored': 23,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 4096,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'number_of_executed_units': 2,
        'oom_count': 0,
        'peak_rss_mb': 111,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 1,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_oom(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.oom_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 53,
        'bad_instrumentation': 0,
        'corpus_crash_count': 0,
        'corpus_rss_mb': 58,
        'corpus_size': 0,
        'crash_count': 0,
        'dict_used': 1,
        'edge_coverage': 2367,
        'edges_total': 398435,
        'feature_coverage': 6401,
        'initial_edge_coverage': 2239,
        'initial_feature_coverage': 4321,
        'leak_count': 0,
        'log_lines_from_engine': 11,
        'log_lines_ignored': 54,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 0,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 1513,
        'new_units_generated': 1513,
        'number_of_executed_units': 90667,
        'oom_count': 1,
        'peak_rss_mb': 2184,
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_from_corrupted_output(self):
    """Test stats parsing from a log with corrupted libFuzzer stats."""
    log_lines = self.corrupted_stats_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 40,
        'bad_instrumentation': 0,
        'corpus_crash_count': 1,
        'corpus_rss_mb': 93,
        'corpus_size': 0,
        'crash_count': 0,
        'dict_used': 0,
        'edge_coverage': 7736,
        'edges_total': 685270,
        'feature_coverage': 12666,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 0,
        'log_lines_ignored': 58,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 1048576,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'number_of_executed_units': 1142,
        'oom_count': 1,
        # We intentionally do not have 'peak_rss_mb' here as it was corrupted.
        'recommended_dict_size': 0,
        'slow_unit_count': 0,
        'slow_units_count': 0,
        'slowest_unit_time_sec': 0,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 0,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 0
    }

    self.assertEqual(parsed_stats, expected_stats)

  def test_parse_log_and_stats_timeout(self):
    """Test stats parsing and additional performance features extraction
    without applying of stat_overrides."""
    log_lines = self.timeout_output.splitlines()
    parsed_stats = launcher.parse_log_stats(log_lines)
    parsed_stats.update(stats.parse_performance_features(log_lines, [], []))
    expected_stats = {
        'average_exec_per_sec': 16,
        'bad_instrumentation': 0,
        'corpus_crash_count': 1,
        'corpus_rss_mb': 103,
        'corpus_size': 0,
        'crash_count': 0,
        'dict_used': 0,
        'edge_coverage': 1321,
        'edges_total': 52747,
        'feature_coverage': 6306,
        'initial_edge_coverage': 0,
        'initial_feature_coverage': 0,
        'leak_count': 0,
        'log_lines_from_engine': 0,
        'log_lines_ignored': 50,
        'log_lines_unwanted': 0,
        'manual_dict_size': 0,
        'max_len': 978798,
        'merge_edge_coverage': 0,
        'merge_new_features': 0,
        'merge_new_files': 0,
        'new_units_added': 0,
        'new_units_generated': 0,
        'number_of_executed_units': 5769,
        'oom_count': 0,
        'peak_rss_mb': 301,
        'recommended_dict_size': 0,
        'slow_unit_count': 1,
        'slow_units_count': 4,
        'slowest_unit_time_sec': 19,
        'startup_crash_count': 0,
        'strategy_corpus_mutations_radamsa': 1,
        'strategy_corpus_mutations_ml_rnn': 0,
        'strategy_corpus_subset': 0,
        'strategy_random_max_len': 0,
        'strategy_recommended_dict': 0,
        'strategy_value_profile': 0,
        'timeout_count': 1
    }

    self.assertEqual(parsed_stats, expected_stats)

  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_single_input(self, mock_stdout):
    """Tests a run for a single input."""
    self.fs.CreateFile('/fake/testcase', contents='fake')
    self.fs.CreateDirectory('/fake/corpus')

    with mock.patch('subprocess.Popen',
                    create_mock_popen('OUTPUT')) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase',
          'fake_fuzzer',
          '-dict=/fake/dictionary',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-rss_limit_mb=2048', '-timeout=25',
          '-runs=100', '/fake/testcase'
      ]])

      # Output should be printed.
      self.assertIn('OUTPUT', mock_stdout.getvalue())

  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_single_input_with_custom_options(self, mock_stdout):
    """Tests a run for a single input with custom options."""
    self.fs.CreateFile('/fake/testcase', contents='fake')
    self.fs.CreateDirectory('/fake/corpus')

    with mock.patch('subprocess.Popen',
                    create_mock_popen('OUTPUT')) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase',
          'fake_fuzzer',
          '-dict=/fake/dictionary',
          '-timeout=13',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-timeout=13', '-rss_limit_mb=2048',
          '-runs=100', '/fake/testcase'
      ]])

      # Output should be printed.
      self.assertIn('OUTPUT', mock_stdout.getvalue())

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_fuzz_crash(self, mock_stdout):
    """Tests a fuzzing run with a crash found."""
    self.fs.CreateFile('/fake/testcase_crash')
    self.fs.CreateFile(
        '/fake/crash-1e15825e6f0b2240a5af75d84214adda1b6b5340',
        contents='crasher')
    self.fs.CreateDirectory('/fake/corpus_crash')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_crash'

    with mock.patch(
        'subprocess.Popen',
        create_mock_popen(self.crash_output, '/fake/inputs-disk/temp-1337/new',
                          10)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_crash',
          'fake_fuzzer',
          '-max_len=80',
      ])

      # Test that the crasher got written.
      with open('/fake/testcase_crash') as f:
        self.assertEqual(f.read(), 'crasher')

      # Test that the output includes the process output.
      self.assertIn(self.crash_output, mock_stdout.getvalue())
      self.assertIn('Bot: test-bot', mock_stdout.getvalue())
      self.assertIn('Time ran:', mock_stdout.getvalue())

      # Tests that no merge command is run here.
      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/fake/', '-max_total_time=2650',
          '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_crash'
      ]])

  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_oom_crash(self, mock_stdout):
    """Tests a fuzzing run with a OOM."""
    self.fs.CreateFile('/fake/testcase_oom')
    self.fs.CreateFile(
        '/fake/oom-755e18dc1b20912de7556d11380e540231dc292c',
        contents='oom_crasher')
    self.fs.CreateDirectory('/fake/corpus_oom')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_oom'

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.oom_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_oom',
          'fake_fuzzer',
          '-max_len=80',
      ])

      # Check stats.
      stats_data = fuzzer_stats.TestcaseRun.read_from_disk('/fake/testcase_oom')
      self.assertDictEqual(
          stats_data.data, {
              'actual_duration':
                  0,
              'average_exec_per_sec':
                  53,
              'bad_instrumentation':
                  0,
              'build_revision':
                  1337,
              'command': [
                  '/fake/build_dir/fake_fuzzer', '-max_len=80',
                  '-rss_limit_mb=2048', '-timeout=25',
                  '-artifact_prefix=/fake/', '-max_total_time=2650',
                  '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
                  '/fake/corpus_oom'
              ],
              'corpus_crash_count':
                  0,
              'corpus_rss_mb':
                  58,
              'corpus_size':
                  0,
              'crash_count':
                  0,
              'dict_used':
                  1,
              'edge_coverage':
                  2367,
              'edges_total':
                  398435,
              'feature_coverage':
                  6401,
              'initial_edge_coverage':
                  2239,
              'initial_feature_coverage':
                  4321,
              'expected_duration':
                  2650,
              'fuzzer':
                  u'libfuzzer_fake_fuzzer',
              'fuzzing_time_percent':
                  0.0,
              'job':
                  u'job_name',
              'kind':
                  u'TestcaseRun',
              'leak_count':
                  0,
              'log_lines_from_engine':
                  11,
              'log_lines_ignored':
                  54,
              'log_lines_unwanted':
                  0,
              'manual_dict_size':
                  0,
              'max_len':
                  80,
              'merge_edge_coverage':
                  2367,
              'merge_new_features':
                  0,
              'merge_new_files':
                  0,
              'new_units_added':
                  0,
              'new_units_generated':
                  1513,
              'number_of_executed_units':
                  90667,
              'oom_count':
                  1,
              'peak_rss_mb':
                  2184,
              'recommended_dict_size':
                  0,
              'slow_unit_count':
                  0,
              'slow_units_count':
                  0,
              'slowest_unit_time_sec':
                  0,
              'startup_crash_count':
                  0,
              'strategy_corpus_mutations_radamsa':
                  0,
              'strategy_corpus_mutations_ml_rnn':
                  0,
              'strategy_corpus_subset':
                  0,
              'strategy_random_max_len':
                  0,
              'strategy_recommended_dict':
                  0,
              'strategy_value_profile':
                  0,
              'timeout_count':
                  0,
              'timeout_limit':
                  25,
              'timestamp':
                  1337.0
          })

      # Test that the crasher got written.
      with open('/fake/testcase_oom') as f:
        self.assertEqual(f.read(), 'oom_crasher')

      # Test that the output includes the process output and custom crash state.
      self.assertIn(self.expected_oom_output, mock_stdout.getvalue())

      # Tests that merge command is run here.
      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/fake/', '-max_total_time=2650',
          '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_oom'
      ], [
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/fake/corpus_oom',
          '/fake/inputs-disk/temp-1337/new'
      ]])

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_fuzz_from_subset(self, _):
    """Tests fuzzing with corpus subset."""
    self.mock.do_corpus_subset.return_value = True

    self.fs.CreateFile('/fake/testcase_subset')
    self.fs.CreateDirectory('/fake/main_corpus_dir')

    # Intentionally put testcases into a subsir, as the main corpus directory
    # should be parsed recursively by both libFuzzer and CF code.
    self.fs.CreateDirectory('/fake/main_corpus_dir/sub')

    # To use corpus subset, there should be enough files in the main corpus.
    for i in xrange(1 + max(strategy.CORPUS_SUBSET_NUM_TESTCASES)):
      self.fs.CreateFile('/fake/main_corpus_dir/sub/%d' % i)

    os.environ['FUZZ_CORPUS_DIR'] = '/fake/main_corpus_dir'

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_subset',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/fake/', '-max_total_time=2650',
          '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
          '/fake/inputs-disk/temp-1337/subset'
      ], [
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/fake/main_corpus_dir',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/inputs-disk/temp-1337/subset'
      ]])

  @mock.patch('metrics.logs.log_error')
  def test_engine_error(self, mock_log_error):
    """Tests that we appropriately log when libFuzzer's fuzzing engine
    encounters an error."""
    testcase_path = '/fake/engine_error_testcase'
    corpus_path = '/fake/engine_error_corpus'
    os.environ['FUZZ_CORPUS_DIR'] = corpus_path
    self.fs.CreateDirectory(corpus_path)
    mocked_popen = create_mock_popen(
        '', return_code=constants.LIBFUZZER_ERROR_EXITCODE)

    with mock.patch('subprocess.Popen', mocked_popen):
      launcher.main([
          'launcher.py',
          testcase_path,
          'fake_fuzzer',
          '-max_len=80',
      ])
    self.assertEqual(1, mock_log_error.call_count)

  def test_set_sanitizer_options_exitcode(self):
    """Tests that set_sanitizer_options sets the exitcode correctly."""
    testcase_path = '/fake/engine_error_testcase'
    corpus_path = '/fake/engine_error_corpus'
    self.fs.CreateDirectory(corpus_path)
    environment.set_value('ASAN_OPTIONS', 'exitcode=99')
    environment.set_value('JOB_NAME', 'libfuzzer_chrome_asan')
    launcher.set_sanitizer_options(testcase_path)
    asan_options = environment.get_value('ASAN_OPTIONS')
    expected = 'exitcode=%s' % constants.TARGET_ERROR_EXITCODE
    self.assertEqual(expected, asan_options)

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_fuzz_from_subset_without_enough_corpus(self, _):
    """Tests fuzzing with corpus subset without enough files in the corpus."""
    self.mock.do_corpus_subset.return_value = True

    self.fs.CreateFile('/fake/testcase_subset')
    self.fs.CreateDirectory('/fake/main_corpus_dir')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/main_corpus_dir'
    # Main corpus directory is empty, we should fall back to regular fuzzing.

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_subset',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/fake/', '-max_total_time=2650',
          '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
          '/fake/main_corpus_dir'
      ], [
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/fake/main_corpus_dir',
          '/fake/inputs-disk/temp-1337/new'
      ]])

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  @mock.patch('system.minijail.tempfile.NamedTemporaryFile')
  def test_fuzz_from_subset_minijail(self, mock_tempfile, _):
    """Tests fuzzing with corpus subset."""
    self.mock.do_corpus_subset.return_value = True
    os.environ['USE_MINIJAIL'] = 'True'

    mock_tempfile.return_value.__enter__.return_value.name = '/tmppath'
    mock_tempfile.return_value.name = '/tmpfile'

    self.fs.CreateFile('/fake/testcase_subset')
    self.fs.CreateDirectory('/fake/main_corpus_dir')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/main_corpus_dir'

    # Intentionally put testcases into a subsir, as the main corpus directory
    # should be parsed recursively by both libFuzzer and CF code.
    self.fs.CreateDirectory('/fake/main_corpus_dir/sub')

    # To use corpus subset, there should be enough files in the main corpus.
    for i in xrange(1 + max(strategy.CORPUS_SUBSET_NUM_TESTCASES)):
      self.fs.CreateFile('/fake/main_corpus_dir/sub/%d' % i)

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_subset',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          'sudo',
          '-S',
          'mknod',
          '-m',
          '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/null',
          'c',
          '1',
          '3',
      ], [
          'sudo', '-S', 'mknod', '-m', '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/random', 'c', '1', '8'
      ], [
          'sudo',
          '-S',
          'mknod',
          '-m',
          '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/urandom',
          'c',
          '1',
          '9',
      ], [
          '/fake_root/resources/platform/{}/minijail0'.format(
              environment.platform().lower()), '-f', '/tmpfile', '-U', '-m',
          '0 1000 1', '-T', 'static', '-c', '0', '-n', '-v', '-p', '-l', '-I',
          '-k', 'proc,/proc,proc,1', '-P', '/fake/inputs-disk/temp-1337/CHROOT',
          '-b', '/fake/inputs-disk/temp-1337/TEMP,/tmp,1', '-b', '/lib,/lib,0',
          '-b', '/lib64,/lib64,0', '-b', '/usr/lib,/usr/lib,0', '-b',
          '/fake/build_dir,/fake/build_dir,0', '-b', '/fake/build_dir,/out,0',
          '-b', '/fake/main_corpus_dir,/main_corpus_dir,1', '-b',
          '/fake/inputs-disk/temp-1337/new,/new,1', '-b',
          '/fake/inputs-disk/temp-1337/subset,/subset,1',
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/', '-max_total_time=2650',
          '-print_final_stats=1', '/new', '/subset'
      ], [
          '/fake_root/resources/platform/{}/minijail0'.format(
              environment.platform().lower()), '-f', '/tmpfile', '-U', '-m',
          '0 1000 1', '-T', 'static', '-c', '0', '-n', '-v', '-p', '-l', '-I',
          '-k', 'proc,/proc,proc,1', '-P', '/fake/inputs-disk/temp-1337/CHROOT',
          '-b', '/fake/inputs-disk/temp-1337/TEMP,/tmp,1', '-b', '/lib,/lib,0',
          '-b', '/lib64,/lib64,0', '-b', '/usr/lib,/usr/lib,0', '-b',
          '/fake/build_dir,/fake/build_dir,0', '-b', '/fake/build_dir,/out,0',
          '-b', '/fake/main_corpus_dir,/main_corpus_dir,1', '-b',
          '/fake/inputs-disk/temp-1337/new,/new,1', '-b',
          '/fake/inputs-disk/temp-1337/subset,/subset,1',
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/main_corpus_dir', '/new', '/subset'
      ]])

    del os.environ['USE_MINIJAIL']

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  @mock.patch('system.minijail.tempfile.NamedTemporaryFile')
  def test_fuzz_from_subset_without_enough_corpus_minijail(
      self, mock_tempfile, _):
    """Tests fuzzing with corpus subset without enough files in the corpus."""
    self.mock.do_corpus_subset.return_value = True
    os.environ['USE_MINIJAIL'] = 'True'

    mock_tempfile.return_value.__enter__.return_value.name = '/tmppath'
    mock_tempfile.return_value.name = '/tmpfile'

    self.fs.CreateFile('/fake/testcase_subset')

    # Main corpus directory is empty, we should fall back to regular fuzzing.
    self.fs.CreateDirectory('/fake/main_corpus_dir')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/main_corpus_dir'

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_subset',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          'sudo',
          '-S',
          'mknod',
          '-m',
          '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/null',
          'c',
          '1',
          '3',
      ], [
          'sudo', '-S', 'mknod', '-m', '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/random', 'c', '1', '8'
      ], [
          'sudo',
          '-S',
          'mknod',
          '-m',
          '666',
          '/fake/inputs-disk/temp-1337/CHROOT/dev/urandom',
          'c',
          '1',
          '9',
      ], [
          '/fake_root/resources/platform/{}/minijail0'.format(
              environment.platform().lower()), '-f', '/tmpfile', '-U', '-m',
          '0 1000 1', '-T', 'static', '-c', '0', '-n', '-v', '-p', '-l', '-I',
          '-k', 'proc,/proc,proc,1', '-P', '/fake/inputs-disk/temp-1337/CHROOT',
          '-b', '/fake/inputs-disk/temp-1337/TEMP,/tmp,1', '-b', '/lib,/lib,0',
          '-b', '/lib64,/lib64,0', '-b', '/usr/lib,/usr/lib,0', '-b',
          '/fake/build_dir,/fake/build_dir,0', '-b', '/fake/build_dir,/out,0',
          '-b', '/fake/inputs-disk/temp-1337/new,/new,1', '-b',
          '/fake/main_corpus_dir,/main_corpus_dir,1',
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-artifact_prefix=/', '-max_total_time=2650',
          '-print_final_stats=1', '/new', '/main_corpus_dir'
      ], [
          '/fake_root/resources/platform/{}/minijail0'.format(
              environment.platform().lower()), '-f', '/tmpfile', '-U', '-m',
          '0 1000 1', '-T', 'static', '-c', '0', '-n', '-v', '-p', '-l', '-I',
          '-k', 'proc,/proc,proc,1', '-P', '/fake/inputs-disk/temp-1337/CHROOT',
          '-b', '/fake/inputs-disk/temp-1337/TEMP,/tmp,1', '-b', '/lib,/lib,0',
          '-b', '/lib64,/lib64,0', '-b', '/usr/lib,/usr/lib,0', '-b',
          '/fake/build_dir,/fake/build_dir,0', '-b', '/fake/build_dir,/out,0',
          '-b', '/fake/inputs-disk/temp-1337/new,/new,1', '-b',
          '/fake/main_corpus_dir,/main_corpus_dir,1',
          '/fake/build_dir/fake_fuzzer', '-max_len=80', '-rss_limit_mb=2048',
          '-timeout=25', '-merge=1', '/main_corpus_dir', '/new'
      ]])

    del os.environ['USE_MINIJAIL']

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('bot.fuzzers.libFuzzer.launcher.'
              'generate_new_testcase_mutations_using_radamsa')
  @mock.patch('sys.stdout', new_callable=StringIO)
  def test_fuzz_with_mutations_using_radamsa(self, *_):
    """Tests fuzzing with mutations using radamsa."""
    self.mock.do_radamsa_generator.return_value = True

    self.fs.CreateFile('/fake/testcase_mutations')
    self.fs.CreateDirectory('/fake/corpus_mutations')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_mutations'

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_mutations',
          'fake_fuzzer',
          '-max_len=80',
      ])

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-rss_limit_mb=2048',
          '-timeout=25',
          '-artifact_prefix=/fake/',
          '-max_total_time=2050',
          '-print_final_stats=1',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_mutations',
          '/fake/inputs-disk/temp-1337/mutations',
      ], [
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-rss_limit_mb=2048',
          '-timeout=25',
          '-merge=1',
          '/fake/corpus_mutations',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/inputs-disk/temp-1337/mutations',
      ]])

  @mock.patch('bot.fuzzers.libFuzzer.launcher.add_recommended_dictionary',
              lambda x, y, z: False)
  @mock.patch('sys.stdout', new_callable=StringIO)
  @mock.patch('bot.fuzzers.ml.rnn.generator.execute')
  def test_fuzz_with_mutations_using_ml_rnn(self, mock_execute, *_):
    """Tests fuzzing with mutations using ml rnn."""
    self.mock.do_ml_rnn_generator.return_value = True

    self.fs.CreateFile('/fake/testcase_mutations')
    self.fs.CreateDirectory('/fake/corpus_mutations')
    os.environ['FUZZ_CORPUS_DIR'] = '/fake/corpus_mutations'

    with mock.patch('subprocess.Popen',
                    create_mock_popen(self.no_crash_output)) as mock_popen:
      launcher.main([
          'launcher.py',
          '/fake/testcase_mutations',
          'fake_fuzzer',
          '-max_len=80',
      ])

      # Check if ml generator is called.
      self.assertTrue(mock_execute.called)

      self.assertEqual(mock_popen.commands, [[
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-rss_limit_mb=2048',
          '-timeout=25',
          '-artifact_prefix=/fake/',
          '-max_total_time=2050',
          '-print_final_stats=1',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/corpus_mutations',
          '/fake/inputs-disk/temp-1337/mutations',
      ], [
          '/fake/build_dir/fake_fuzzer',
          '-max_len=80',
          '-rss_limit_mb=2048',
          '-timeout=25',
          '-merge=1',
          '/fake/corpus_mutations',
          '/fake/inputs-disk/temp-1337/new',
          '/fake/inputs-disk/temp-1337/mutations',
      ]])


class RecommendedDictionaryTest(fake_fs_unittest.TestCase):
  """Tests for dictionary processing."""

  def assert_compare_dictionaries(self, dict1, dict2):
    """Asserts that two given dictionaries contain the same elements."""
    # Order of elements in a merged dictionary is not guaranteed. Due to that,
    # we verify sizes of dictionaries and sets of their elements.
    self.assertEqual(len(dict1), len(dict2))
    self.assertEqual(set(dict1.splitlines()), set(dict2.splitlines()))

  def mock_download_recommended_dictionary_from_gcs(self, _,
                                                    local_dictionary_path):
    """Mock for DictionaryManager.download_recommended_dictionary_from_gcs."""
    engine_common.write_data_to_file(self.fake_gcs_dictionary_data,
                                     local_dictionary_path)
    return True

  def setUp(self):
    # FIXME: Add support for Windows.
    if not environment.is_posix():
      self.skipTest('Process tests are only applicable for posix platforms.')

    self.data_directory = os.path.join(os.path.dirname(__file__), 'data')
    dictionaries_directory = os.path.join(self.data_directory, 'dictionaries')
    self.dictionary_from_repository_data = read_data_from_file(
        os.path.join(dictionaries_directory, 'dictionary_from_repository.dict'))
    self.expected_merged_dictionary_data = read_data_from_file(
        os.path.join(dictionaries_directory, 'expected_merged_dictionary.dict'))
    self.expected_gcs_only_merged_dictionary_data = read_data_from_file(
        os.path.join(dictionaries_directory,
                     'expected_gcs_only_merged_dictionary.dict'))
    self.fake_gcs_dictionary_data = read_data_from_file(
        os.path.join(dictionaries_directory, 'fake_gcs_dictionary.dict'))

    test_helpers.patch(self, [
        'bot.fuzzers.dictionary_manager.DictionaryManager.'
        'download_recommended_dictionary_from_gcs',
        'os.getpid',
    ])
    self.mock.download_recommended_dictionary_from_gcs.side_effect = (
        self.mock_download_recommended_dictionary_from_gcs)
    self.mock.getpid.return_value = 1337

    test_utils.set_up_pyfakefs(self)
    self.work_directory_path = '/fake/fuzzers/'
    self.fuzz_inputs_path = '/fake/fuzzers/inputs'
    self.fuzz_inputs_disk_path = '/fake/fuzzers/inputs-disk'
    self.fs.CreateDirectory(self.work_directory_path)
    self.fs.CreateDirectory(self.fuzz_inputs_path)
    self.fs.CreateDirectory(self.fuzz_inputs_disk_path)
    self.local_dictionaries_dir = os.path.join(self.work_directory_path,
                                               'dicts')
    self.fs.CreateDirectory(self.local_dictionaries_dir)
    self.fuzzer_name = 'test_fuzzer'
    self.fuzzer_path = os.path.join(self.work_directory_path, self.fuzzer_name)

    test_helpers.patch_environ(self)
    environment.set_value('FAIL_RETRIES', '1')
    environment.set_value('FUZZ_INPUTS', self.fuzz_inputs_path)
    environment.set_value('FUZZ_INPUTS_DISK', self.fuzz_inputs_disk_path)

  def test_add_recommended_dictionary_no_merge(self):
    """Test dictionary processing when there is no local dictionary."""
    arguments = [
        '-max_len=80', '-rss_limit_mb=2048', '-timeout=25',
        '-artifact_prefix=/fake/', '-max_total_time=2950',
        '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
        '/fake/corpus_basic'
    ]

    launcher.add_recommended_dictionary(arguments, self.fuzzer_name,
                                        self.fuzzer_path)

    expected_dictionary_path = '%s.dict.merged' % self.fuzzer_path

    # Check '-dict' argument that should be added by
    # add_recommended_dictionary().
    expected_dictionary_argument = '-dict=%s' % expected_dictionary_path
    self.assertTrue(expected_dictionary_argument in arguments)

    # Check the dictionary contents.
    dictionary_data = read_data_from_file(expected_dictionary_path)
    self.assert_compare_dictionaries(
        dictionary_data, self.expected_gcs_only_merged_dictionary_data)

  def test_add_recommended_dictionary_with_merge(self):
    """Test dictionary processing when there is a local dictionary."""
    dictionary_path = os.path.join(self.work_directory_path,
                                   'dictionary_from_repository.dict')
    self.fs.CreateFile(
        dictionary_path, contents=self.dictionary_from_repository_data)

    dictionary_argument = '-dict=%s' % dictionary_path
    expected_arguments = [
        '-max_len=80', '-rss_limit_mb=2048', '-timeout=25', dictionary_argument,
        '-artifact_prefix=/fake/', '-max_total_time=2950',
        '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
        '/fake/corpus_basic'
    ]

    actual_arguments = copy.deepcopy(expected_arguments)

    # The function call below is expected to modify actual_arguments list.
    launcher.add_recommended_dictionary(actual_arguments, self.fuzzer_name,
                                        self.fuzzer_path)

    # The dictionary argument is expected to be removed and added to the end.
    expected_arguments.remove(dictionary_argument)
    expected_arguments.append(dictionary_argument + '.merged')
    self.assertEqual(actual_arguments, expected_arguments)

    # The dictionary should content merged data.
    updated_dictionary_data = read_data_from_file(dictionary_path + '.merged')
    self.assert_compare_dictionaries(updated_dictionary_data,
                                     self.expected_merged_dictionary_data)

  def test_download_recommended_dictionary_with_merge(self):
    """Test downloading of recommended dictionary."""
    arguments = [
        '-max_len=80', '-rss_limit_mb=2048', '-timeout=25',
        '-artifact_prefix=/fake/', '-max_total_time=2950',
        '-print_final_stats=1', '/fake/inputs-disk/temp-1337/new',
        '/fake/corpus_basic'
    ]

    launcher.add_recommended_dictionary(arguments, self.fuzzer_name,
                                        self.fuzzer_path)
    self.assertIn(
        '/fake/fuzzers/inputs-disk/temp-1337/recommended_dictionary.dict',
        self.mock.download_recommended_dictionary_from_gcs.call_args[0])


if __name__ == '__main__':
  unittest.main()
