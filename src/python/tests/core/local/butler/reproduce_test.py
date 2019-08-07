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

from local.butler import reproduce
from system import environment
from system import shell
from tests.test_libs import helpers
from tests.test_libs import test_utils


def _fake_get_testcase(*_):
  """Fake test case output intended to run "echo -n"."""
  testcase_map = {
      'crash_state': 'state',
      'security_flag': False,
      'gestures': [],
      'flaky_stack': False,
      'job_type': 'test_job',
      'redzone': 32,
      'additional_metadata': '{}',
      'fuzzer_name': 'fuzzer',
      'job_definition': 'APP_NAME = echo\nAPP_ARGS = -n\n',
      'platform': environment.platform().lower(),
  }

  return reproduce.SerializedTestcase(testcase_map)


# TODO(mbarbella): This test seems to be causing a side-effect that's leading
# to issues running it in parallel with other tests. The root cause is still
# unknown, but it's not ideal to have to separate these tests out.
@unittest.skipIf(not environment.get_value('REPRODUCE_TOOL_TESTS'),
                 'Skipping reproduce tool tests.')
@test_utils.with_cloud_emulators('datastore')
class ReproduceTest(unittest.TestCase):
  """Tests for the full reproduce tool."""

  def setUp(self):
    helpers.patch(self, [
        'config.local_config.ProjectConfig',
        'local.butler.reproduce._download_testcase',
        'local.butler.reproduce._get_testcase',
        'local.butler.reproduce._setup_x',
        'local.butler.reproduce._verify_target_exists',
        'local.butler.reproduce_tool.config.ReproduceToolConfiguration',
        'system.process_handler.run_process',
        'system.process_handler.terminate_stale_application_instances',
    ])
    helpers.patch_environ(self)

    self.mock._download_testcase.return_value = '/tmp/testcase'
    self.mock._get_testcase.side_effect = _fake_get_testcase
    self.mock._setup_x.return_value = []
    self.mock.run_process.return_value = (0, 0, '/tmp/testcase')

    self.build_directory = tempfile.mkdtemp()
    self.binary_path = os.path.join(self.build_directory, 'echo')
    with open(self.binary_path, 'w') as f:
      f.write('test')

  def tearDown(self):
    shell.remove_directory(self.build_directory)

  def test_reproduce_with_echo(self):
    """See if the reproduce tool can run a job configured to execute "echo"."""
    crash_retries = 3
    disable_xvfb = False
    reproduce._reproduce_crash('https://localhost/testcase-detail/1',
                               self.build_directory, crash_retries,
                               disable_xvfb)
    reproduce._cleanup()
    self.mock.run_process.assert_called_with(
        self.binary_path + ' -n /tmp/testcase',
        current_working_directory=self.build_directory,
        gestures=[],
        timeout=10)
    self.assertEqual(self.mock.run_process.call_count, crash_retries)
