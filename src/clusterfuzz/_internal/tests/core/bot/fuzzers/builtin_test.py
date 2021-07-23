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
"""Tests fuzzers.builtin."""

import os
import unittest

import parameterized
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.fuzzers import builtin
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class TestEngineFuzzer(builtin.EngineFuzzer):
  """A test engine fuzzer."""

  def generate_arguments(self, *_):  # pylint: disable=arguments-differ
    return '-arg1 -arg2'


class BaseEngineFuzzerTest(fake_filesystem_unittest.TestCase):
  """Engine fuzzer tests."""

  def setUp(self):
    """Setup for base engine fuzzer test."""
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.default_project_name',
        'clusterfuzz._internal.bot.fuzzers.builtin.fuzzers_utils.get_fuzz_targets'
    ])

    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/input')
    self.fs.create_dir('/output')

    environment.set_value('BUILD_DIR', '/build_dir')
    environment.set_value('FAIL_RETRIES', 1)

    environment.set_value('PROJECT_NAME', 'proj')
    self.mock.default_project_name.return_value = 'default-proj'

    self.mock.get_fuzz_targets.return_value = [
        '/build_dir/target',
    ]
    self.fs.create_file(
        '/build_dir/target.owners',
        contents='dev1@example1.com\ndev2@example2.com')


class EngineFuzzerTest(BaseEngineFuzzerTest):
  """Engine fuzzer tests."""

  def test_run(self):
    """Test running an engine fuzzer."""
    fuzzer = TestEngineFuzzer()
    result = fuzzer.run('/input', '/output', 1)

    self.assertEqual(
        'Generated 1 testcase for fuzzer target.\n'
        'metadata::fuzzer_binary_name: target\n'
        'metadata::issue_owners: dev1@example1.com,dev2@example2.com\n',
        result.output)
    self.assertEqual('/input/proj_target', result.corpus_directory)

    self.assertTrue(os.path.exists('/output/fuzz-0'))
    self.assertTrue(os.path.exists('/output/flags-0'))

    with open('/output/fuzz-0') as f:
      self.assertEqual(' ', f.read())

    with open('/output/flags-0') as f:
      self.assertEqual('%TESTCASE% target -arg1 -arg2', f.read())

  def test_run_with_labels(self):
    """Test running an engine fuzzer with a labels file."""
    self.fs.create_file('/build_dir/target.labels', contents='label1\nlabel2\n')

    fuzzer = TestEngineFuzzer()
    result = fuzzer.run('/input', '/output', 1)
    self.assertEqual(
        'Generated 1 testcase for fuzzer target.\n'
        'metadata::fuzzer_binary_name: target\n'
        'metadata::issue_owners: dev1@example1.com,dev2@example2.com\n'
        'metadata::issue_labels: label1,label2\n', result.output)

  def test_run_no_build_dir(self):
    """Test running without a build dir."""
    environment.set_value('BUILD_DIR', '')
    fuzzer = TestEngineFuzzer()
    with self.assertRaisesRegex(builtin.BuiltinFuzzerException, 'BUILD_DIR'):
      fuzzer.run('/input', '/output', 1)

  def test_run_no_fuzzers(self):
    """Test running without fuzzers."""
    self.mock.get_fuzz_targets.return_value = []
    fuzzer = TestEngineFuzzer()
    with self.assertRaises(builtin.BuiltinFuzzerException):
      fuzzer.run('/input', '/output', 1)

  def _generate_targets_list(self, count):
    """Generate a targets list."""
    fake_targets_list = []
    for i in range(count):
      fake_targets_list.append('/build_dir/target' + str(i))

    return fake_targets_list

  def test_run_chosen_fuzz_target(self):
    """Test running with chosen fuzz target."""
    os.environ['FUZZ_TARGET'] = 'chosen_target'

    fake_targets_list = self._generate_targets_list(100)
    fake_targets_list.append('/build_dir/chosen_target')

    self.mock.get_fuzz_targets.return_value = fake_targets_list

    fuzzer = TestEngineFuzzer()
    result = fuzzer.run('/input', '/output', 1)

    self.assertEqual(
        'Generated 1 testcase for fuzzer chosen_target.\n'
        'metadata::fuzzer_binary_name: chosen_target\n', result.output)
    self.assertEqual('/input/proj_chosen_target', result.corpus_directory)

  def test_sanitizer_options_from_options_file(self):
    """Tests that sanitizer options are set in *SAN_OPTIONS using the overrides
    provided in .options file."""
    environment.set_value('ASAN_OPTIONS', 'fake_option1=1')
    with open('/build_dir/target.options', 'w') as f:
      f.write('[asan]\nfake_option2=1\n[msan]\nfake_options3=1')

    fuzzer = TestEngineFuzzer()
    fuzzer.run('/input', '/output', 1)

    self.assertEqual('fake_option1=1:fake_option2=1',
                     environment.get_value('ASAN_OPTIONS'))
    self.assertEqual(None, environment.get_value('MSAN_OPTIONS'))


class GetFuzzerPath(unittest.TestCase):
  """_get_fuzzer_path Tests."""

  @parameterized.parameterized.expand([('fuzzer', 'LINUX'), ('fuzzer.exe',
                                                             'WINDOWS')])
  def test_get_fuzzer_path(self, target_name, mock_platform):
    """Test that get_fuzzer_path returns the path of a fuzzer."""
    target_path = os.path.join('path', 'to', target_name)
    helpers.patch(self, ['clusterfuzz._internal.system.environment.platform'])
    self.mock.platform.return_value = mock_platform
    result = builtin._get_fuzzer_path(['a', target_path], 'fuzzer')  # pylint: disable=protected-access
    self.assertEqual(result, target_path)
