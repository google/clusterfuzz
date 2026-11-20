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
"""Run tests."""
import getpass
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from clusterfuzz._internal.tests.test_libs import helpers
from python.bot.startup import run

EXPECTED_OPEN_FILES_SOFT_LIMIT = 65535


class UpdateSourceCodeIfNeededTest(unittest.TestCase):
  """Test update_source_code_if_needed."""

  def setUp(self):
    helpers.patch(self, [
        'python.bot.startup.run.stop_heartbeat',
        'clusterfuzz._internal.bot.tasks.update_task.get_newer_source_revision',
        'clusterfuzz._internal.bot.tasks.update_task.update_source_code',
    ])

  def test_not_update(self):
    """Test newer source revision is None."""
    self.mock.get_newer_source_revision.return_value = None
    run.update_source_code_if_needed()
    self.assertEqual(0, self.mock.stop_heartbeat.call_count)
    self.assertEqual(0, self.mock.update_source_code.call_count)

  def test_update(self):
    """Test update source."""
    self.mock.get_newer_source_revision.return_value = 'revision'
    run.update_source_code_if_needed()
    self.mock.stop_heartbeat.assert_called_once_with()
    self.mock.update_source_code.assert_called_once_with()


class RunLoopTest(unittest.TestCase):
  """Test run_loop."""

  def setUp(self):
    helpers.patch(self, [
        'atexit.register',
        'python.bot.startup.run.start_bot',
        'python.bot.startup.run.start_heartbeat',
        'python.bot.startup.run.stop_heartbeat',
        'python.bot.startup.run.update_source_code_if_needed',
        'python.bot.startup.run.sleep',
        'clusterfuzz._internal.datastore.data_handler.bot_run_timed_out',
    ])

  def test_loop(self):
    """Test looping until break."""
    self.mock.bot_run_timed_out.side_effect = [False, False, True]
    self.mock.start_bot.return_value = 1

    run.run_loop('bot command', 'heartbeat command')

    self.assertEqual(3, self.mock.update_source_code_if_needed.call_count)
    self.assertEqual(3, self.mock.start_heartbeat.call_count)
    self.assertEqual(1, self.mock.register.call_count)
    self.assertEqual(0, self.mock.stop_heartbeat.call_count)  # Handled at exit.
    self.assertEqual(3, self.mock.start_bot.call_count)
    self.assertEqual(3, self.mock.bot_run_timed_out.call_count)
    self.assertEqual(2, self.mock.sleep.call_count)

    self.mock.update_source_code_if_needed.assert_has_calls(
        [mock.call(), mock.call(), mock.call()])
    self.mock.start_bot.assert_has_calls([
        mock.call('bot command'),
        mock.call('bot command'),
        mock.call('bot command'),
    ])
    self.mock.bot_run_timed_out.assert_has_calls(
        [mock.call(), mock.call(), mock.call()])
    self.mock.sleep.assert_has_calls([mock.call(3), mock.call(3)])


class MainStartupLimitTest(unittest.TestCase):
  """Tests open-file limit initialization during run.main."""

  def test_main_ensures_open_file_limit(self):
    """Test run.main calls ensure_open_file_limit after configuring logs."""
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.system.environment.set_bot_environment',
        'clusterfuzz._internal.system.environment.ensure_open_file_limit',
        'clusterfuzz._internal.system.environment.set_value',
        'clusterfuzz._internal.system.environment.get_startup_scripts_directory',
        'clusterfuzz._internal.base.persistent_cache.initialize',
        'clusterfuzz._internal.metrics.logs.configure',
        'clusterfuzz._internal.system.shell.get_interpreter',
        'python.bot.startup.run.set_start_time',
        'python.bot.startup.run.run_loop',
    ])
    self.mock.get_value.side_effect = lambda k, default=None: {
        'ROOT_DIR': '/bot',
        'LOG_DIR': '/bot/logs',}.get(k, default)
    self.mock.get_startup_scripts_directory.return_value = '/bot/startup'
    self.mock.get_interpreter.return_value = 'python3'

    run.main()

    self.mock.ensure_open_file_limit.assert_called_once_with()

  @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only script')
  def test_start_clusterfuzz_script_raises_soft_nofile_after_sudo(self):
    """Tests start_clusterfuzz.sh enforces ulimit -Sn >= 65535 across sudo."""
    current_user = getpass.getuser()
    if shutil.which('sudo') is None:
      self.skipTest('sudo binary not available')
    probe = subprocess.run(
        ['sudo', '-n', '-u', current_user, 'true'],
        capture_output=True,
        check=False)
    if probe.returncode != 0:
      self.skipTest('Non-interactive sudo to current user is not permitted')

    _, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard_limit != resource.RLIM_INFINITY and hard_limit < EXPECTED_OPEN_FILES_SOFT_LIMIT:
      self.skipTest(f'Host hard RLIMIT_NOFILE ({hard_limit}) is below 65535')

    repo_root = Path(__file__).resolve().parents[7]
    script_path = repo_root / 'docker' / 'base' / 'start_clusterfuzz.sh'
    env = os.environ.copy()
    env['USER'] = current_user
    env['RUN_CMD'] = 'ulimit -Sn'
    proc = subprocess.run(
        ['bash', str(script_path)],
        env=env,
        capture_output=True,
        text=True,
        check=True)
    soft_limit = int(proc.stdout.strip().splitlines()[-1])
    self.assertGreaterEqual(soft_limit, EXPECTED_OPEN_FILES_SOFT_LIMIT)
