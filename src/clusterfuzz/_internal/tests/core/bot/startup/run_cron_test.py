# Copyright 2026 Google LLC
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
"""run_cron tests."""
import contextlib
import os
import sys
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.tests.test_libs import helpers
from python.bot.startup import run_cron


@contextlib.contextmanager
def _noop_context():
  yield


class RunCronTest(unittest.TestCase):
  """Tests for run_cron.main."""

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp_dir.cleanup)
    # Use an empty ROOT_DIR so no config module_init is picked up.
    helpers.patch_environ(self, {'ROOT_DIR': self.temp_dir.name})
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        'clusterfuzz._internal.datastore.ndb_init.context',
        'clusterfuzz._internal.metrics.logs.configure',
        'clusterfuzz._internal.metrics.monitor.wrap_with_monitoring',
        'python.bot.startup.run_cron.importlib',
    ])
    self.mock.context.side_effect = _noop_context
    self.mock.wrap_with_monitoring.side_effect = _noop_context

    self.task_module = mock.Mock()
    self.task_module.main.return_value = True
    self.mock.import_module = self.mock.importlib.import_module
    self.mock.import_module.return_value = self.task_module

  def _run(self, argv):
    with mock.patch.object(sys, 'argv', argv):
      return run_cron.main()

  def test_no_extra_args(self):
    """Tests that main() is called without arguments when none are given."""
    self.assertEqual(0, self._run(['run_cron.py', 'some_cron']))
    self.mock.import_module.assert_called_once_with(
        'clusterfuzz._internal.cron.some_cron')
    self.task_module.main.assert_called_once_with()

  def test_extra_args_forwarded(self):
    """Tests that extra arguments are forwarded to the cron's main()."""
    self.assertEqual(
        0,
        self._run(
            ['run_cron.py', 'load_bigquery_stats', '--date', '2026-11-08']))
    self.mock.import_module.assert_called_once_with(
        'clusterfuzz._internal.cron.load_bigquery_stats')
    self.task_module.main.assert_called_once_with(['--date', '2026-11-08'])

  def test_failure_return_code(self):
    """Tests that a falsy main() result maps to exit code 1."""
    self.task_module.main.return_value = False
    self.assertEqual(1, self._run(['run_cron.py', 'some_cron', '--flag']))
    self.task_module.main.assert_called_once_with(['--flag'])

  def test_exception_return_code(self):
    """Tests that an exception in main() maps to exit code 1."""
    self.task_module.main.side_effect = Exception('boom')
    self.assertEqual(1, self._run(['run_cron.py', 'some_cron']))

  def test_missing_root_dir(self):
    """Tests that a missing ROOT_DIR exits early."""
    del os.environ['ROOT_DIR']
    self.assertEqual(1, self._run(['run_cron.py', 'some_cron']))
    self.mock.import_module.assert_not_called()
