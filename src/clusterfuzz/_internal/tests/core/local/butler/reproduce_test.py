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
"""Reproduce tool tests."""
# pylint: disable=protected-access
import os
import tempfile
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import \
    FakeConfig
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import \
    FakeResponse
from local.butler import reproduce
from local.butler.reproduce_tool import errors


def _fake_get_echo_testcase(*_):
  """Fake test case output intended to run "echo -n"."""
  testcase_map = {
      'crash_state': 'state',
      'security_flag': False,
      'gestures': [],
      'flaky_stack': False,
      'job_type': 'test_job',
      'redzone': 32,
      'disable_ubsan': False,
      'additional_metadata': '{}',
      'fuzzer_name': 'fuzzer',
      'job_definition': 'APP_NAME = echo\nAPP_ARGS = -n\n',
      'overridden_fuzzer_name': 'fuzzer',
      'platform': environment.platform().lower(),
      'minimized_arguments': '',
      'window_argument': '',
      'timeout_multiplier': 1.0,
      'serialized_fuzz_target': None,
      'one_time_crasher_flag': False,
  }

  return reproduce.SerializedTestcase(testcase_map)


def _fake_get_libfuzzer_testcase(*_):
  """Fake test case output intended to run "echo -n"."""
  testcase_map = {
      'crash_state': 'state',
      'security_flag': False,
      'gestures': [],
      'flaky_stack': False,
      'job_type': 'test_job',
      'redzone': 32,
      'disable_ubsan': False,
      'additional_metadata': '{}',
      'fuzzer_name': 'libFuzzer',
      'job_definition': 'APP_NAME = launcher.py\n',
      'overridden_fuzzer_name': 'libFuzzer_test_fuzzer',
      'platform': environment.platform().lower(),
      'minimized_arguments': '',
      'window_argument': '',
      'timeout_multiplier': 1.0,
      'serialized_fuzz_target': {
          'binary': 'test_fuzzer',
          'engine': 'libFuzzer',
          'project': 'test_project',
      },
      'one_time_crasher_flag': False,
  }

  return reproduce.SerializedTestcase(testcase_map)


@test_utils.reproduce_tool
@test_utils.with_cloud_emulators('datastore')
class ReproduceTest(unittest.TestCase):
  """Tests for the full reproduce tool."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.testcase_manager.engine_reproduce',
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        'clusterfuzz.fuzz.engine.get',
        'local.butler.reproduce._download_testcase',
        'local.butler.reproduce._get_testcase',
        'local.butler.reproduce._setup_x',
        'local.butler.reproduce._verify_target_exists',
        'local.butler.reproduce_tool.config.ReproduceToolConfiguration',
        'local.butler.reproduce_tool.prompts.get_boolean',
        'clusterfuzz._internal.system.process_handler.run_process',
        'clusterfuzz._internal.system.process_handler.'
        'terminate_stale_application_instances',
    ])
    helpers.patch_environ(self)

    self.mock._setup_x.return_value = []
    self.mock.get_boolean.return_value = True
    self.mock._download_testcase.return_value = '/tmp/testcase'
    self.mock.run_process.return_value = (0, 0, '/tmp/testcase')

    self.build_directory = tempfile.mkdtemp()

  def tearDown(self):
    shell.remove_directory(self.build_directory)

  def test_reproduce_with_echo(self):
    """Ensure that the tool can run a job configured to execute "echo"."""
    self.mock.get.return_value = None
    self.mock._get_testcase.side_effect = _fake_get_echo_testcase

    binary_path = os.path.join(self.build_directory, 'echo')
    with open(binary_path, 'w') as f:
      f.write('test')

    crash_retries = 3
    disable_xvfb = False
    verbose = False
    disable_android_setup = False
    application = None
    reproduce._reproduce_crash('https://localhost/testcase-detail/1',
                               self.build_directory, crash_retries,
                               disable_xvfb, verbose, disable_android_setup,
                               application)
    reproduce._cleanup()
    self.mock.run_process.assert_called_with(
        binary_path + ' -n /tmp/testcase',
        current_working_directory=self.build_directory,
        gestures=[],
        timeout=10)

    # The tool does an initial run before running |crash_retries| times.
    self.assertEqual(self.mock.run_process.call_count, crash_retries + 1)

  def test_reproduce_with_libfuzzer(self):
    """Ensure that the tool can run on a libFuzzer target."""
    self.mock.get.return_value = 'fake engine object'
    self.mock._get_testcase.side_effect = _fake_get_libfuzzer_testcase

    crash_retries = 3
    disable_xvfb = False
    verbose = False
    disable_android_setup = False
    application = None
    reproduce._reproduce_crash('https://localhost/testcase-detail/1',
                               self.build_directory, crash_retries,
                               disable_xvfb, verbose, disable_android_setup,
                               application)
    reproduce._cleanup()
    self.mock.engine_reproduce.assert_called_with(
        'fake engine object', 'test_fuzzer', '/tmp/testcase', [], 10)

    # The tool does an initial run before running |crash_retries| times.
    self.assertEqual(self.mock.engine_reproduce.call_count, crash_retries + 1)


@test_utils.reproduce_tool
class DownloadTestcaseTest(unittest.TestCase):
  """Tests for _download_testcase."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.write_data_to_file',
        'local.butler.reproduce_tool.http_utils.request',
        'clusterfuzz._internal.system.archive.unpack',
        'clusterfuzz._internal.system.archive.get_file_list',
    ])
    helpers.patch_environ(self)

    self.config = FakeConfig()

  def test_initial_request_failed(self):
    """Ensure that we bail out if the initial request fails."""
    self.mock.request.return_value = (FakeResponse(500), '')
    testcase = reproduce.SerializedTestcase({})
    with self.assertRaises(errors.ReproduceToolUnrecoverableError):
      reproduce._download_testcase(1, testcase, self.config)

  def test_non_archived_testcase(self):
    """Ensure that we properly unpack non-archived test cases."""
    self.mock.request.return_value = (FakeResponse(200, filename='test.html'),
                                      'html data')
    testcase = reproduce.SerializedTestcase({
        'archive_state': data_types.ArchiveStatus.NONE,
        'minimized_keys': 'key',
    })

    reproduce._download_testcase(1, testcase, self.config)
    self.mock.write_data_to_file.assert_called_once_with(
        'html data',
        os.path.join(reproduce.CONFIG_DIRECTORY, 'current-testcase',
                     'test.html'))

  def test_archived_testcase(self):
    """Ensure that we properly unpack archived test cases."""
    self.mock.request.return_value = (FakeResponse(200, filename='test.zip'),
                                      'zip data')
    self.mock.get_file_list.return_value = ['test.html', 'resource.js']
    testcase = reproduce.SerializedTestcase({
        'archive_state': data_types.ArchiveStatus.ALL,
        'absolute_path': '/path/to/test.html',
        'minimized_keys': 'key',
    })

    current_testcase_directory = os.path.join(reproduce.CONFIG_DIRECTORY,
                                              'current-testcase')
    zip_path = os.path.join(current_testcase_directory, 'test.zip')

    reproduce._download_testcase(1, testcase, self.config)
    self.mock.write_data_to_file.assert_called_once_with('zip data', zip_path)

    self.mock.unpack.assert_called_once_with(zip_path,
                                             current_testcase_directory)

  def test_archive_missing_file(self):
    """Ensure that we raise if the archive is missing an expected file."""
    self.mock.request.return_value = (FakeResponse(200, filename='test.zip'),
                                      'zip data')
    self.mock.get_file_list.return_value = []
    testcase = reproduce.SerializedTestcase({
        'archive_state': data_types.ArchiveStatus.ALL,
        'absolute_path': '/path/to/test.html',
        'minimized_keys': 'key',
    })

    with self.assertRaises(errors.ReproduceToolUnrecoverableError):
      reproduce._download_testcase(1, testcase, self.config)
