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
import mock
import unittest

from internal.bot.startup import run
from tests.test_libs import helpers


class UpdateSourceCodeIfNeededTest(unittest.TestCase):
  """Test update_source_code_if_needed."""

  def setUp(self):
    helpers.patch(self, [
        'internal.bot.startup.run.stop_heartbeat',
        'internal.bot.tasks.update_task.get_newer_source_revision',
        'internal.bot.tasks.update_task.update_source_code',
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
        'internal.bot.startup.run.start_bot',
        'internal.bot.startup.run.start_heartbeat',
        'internal.bot.startup.run.stop_heartbeat',
        'internal.bot.startup.run.update_source_code_if_needed',
        'internal.bot.startup.run.sleep',
        'internal.datastore.data_handler.bot_run_timed_out',
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
