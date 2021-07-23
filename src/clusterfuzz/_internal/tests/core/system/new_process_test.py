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
"""Tests for process."""
# pylint: disable=unused-argument

import queue
import time
import unittest

import mock

from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class Signal(object):
  TERM = 0
  KILL = 1


def mock_kill(self):
  self._popen.kill()  # pylint: disable=protected-access


def mock_popen_factory(execute_time,
                       output,
                       sigterm_handler_time,
                       return_code=0):
  """Create a mock popen."""

  class MockPopen(object):
    """Mock subprocess.Popen."""
    received_signals = []

    def __init__(self, *args, **kwargs):
      """Inits the MockPopen."""
      self.start_time = time.time()
      self.signal_queue = queue.Queue()

    def poll(self):
      """Mock subprocess.Popen.poll."""
      if time.time() >= self.start_time + execute_time:
        return return_code

      return None

    def kill(self):
      """Mock subprocess.Popen.kill."""
      self.signal_queue.put(Signal.KILL)

    def terminate(self):
      """Mock subprocess.Popen.terminate."""
      self.signal_queue.put(Signal.TERM)

    def communicate(self, input_data=None):
      """Mock subprocess.Popen.communicate."""
      for i in range(2):
        timeout = execute_time if i == 0 else sigterm_handler_time
        try:
          received_signal = self.signal_queue.get(block=True, timeout=timeout)
        except queue.Empty:
          continue

        self.received_signals.append((received_signal,
                                      time.time() - self.start_time))
        if received_signal == Signal.KILL:
          break

      return output, None

  return MockPopen


class PosixProcessTest(unittest.TestCase):
  """Posix Process tests."""

  # Allowed error for time calculations.
  TIME_ERROR = 0.3

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.new_process.ChildProcess.kill'
    ])
    self.mock.platform.return_value = 'LINUX'
    self.mock.kill.side_effect = mock_kill

  def test_basic(self):
    """Tests basic command line."""
    runner = new_process.ProcessRunner('/test/path')
    self.assertEqual(runner.get_command(), ['/test/path'])

  def test_default_args(self):
    """Tests basic command line with default arguments."""
    runner = new_process.ProcessRunner(
        '/test/path', default_args=['-arg1', '-arg2'])
    self.assertEqual(runner.get_command(), ['/test/path', '-arg1', '-arg2'])

  def test_additional_args(self):
    """Tests basic command line with default arguments and additional
    arguments."""
    runner = new_process.ProcessRunner(
        '/test/path', default_args=['-arg1', '-arg2'])
    self.assertEqual(
        runner.get_command(additional_args=['-arg3', '-arg4']),
        ['/test/path', '-arg1', '-arg2', '-arg3', '-arg4'])

  def test_results_no_timeout(self):
    """Test process execution results."""
    with mock.patch('subprocess.Popen', mock_popen_factory(
        1.0, 'output', 0.0, 0)):
      runner = new_process.ProcessRunner(
          '/test/path', default_args=['-arg1', '-arg2'])
      results = runner.run_and_wait()
      self.assertEqual(results.command, ['/test/path', '-arg1', '-arg2'])
      self.assertEqual(results.return_code, 0)
      self.assertEqual(results.output, 'output')
      self.assertLess(abs(results.time_executed - 1.0), self.TIME_ERROR)
      self.assertFalse(results.timed_out)

  def test_results_timeout(self):
    """Test process execution results with timeout."""
    with mock.patch('subprocess.Popen', mock_popen_factory(
        1.0, 'output', 0.0, 0)):
      runner = new_process.ProcessRunner(
          '/test/path', default_args=['-arg1', '-arg2'])
      results = runner.run_and_wait(timeout=0.5)
      self.assertEqual(results.command, ['/test/path', '-arg1', '-arg2'])
      self.assertEqual(results.return_code, None)
      self.assertEqual(results.output, 'output')
      self.assertLess(abs(results.time_executed - 0.5), self.TIME_ERROR)
      self.assertTrue(results.timed_out)

  def test_timeout(self):
    """Tests timeout signals."""
    with mock.patch('subprocess.Popen', mock_popen_factory(1.0, '',
                                                           0.0)) as mock_popen:
      runner = new_process.ProcessRunner('/test/path')
      runner.run_and_wait(timeout=0.5)

      # Single signal (SIGKILL) should arrive in 0.5 seconds.
      self.assertEqual(len(mock_popen.received_signals), 1)
      self.assertLess(
          abs(mock_popen.received_signals[0][1] - 0.5), self.TIME_ERROR)
      self.assertEqual(mock_popen.received_signals[0][0], Signal.KILL)

  def test_no_timeout(self):
    """Tests process exiting before timeout."""
    with mock.patch('subprocess.Popen', mock_popen_factory(0.5, '',
                                                           0.0)) as mock_popen:
      runner = new_process.ProcessRunner('/test/path')
      runner.run_and_wait(timeout=5.0)

      # No signals should be sent.
      self.assertEqual(len(mock_popen.received_signals), 0)

  def test_terminate_before_kill_no_sigterm_timeout(self):
    """Tests process sigterm handler completing before terminate_wait_time."""
    with mock.patch('subprocess.Popen', mock_popen_factory(1.0, '',
                                                           0.5)) as mock_popen:
      runner = new_process.ProcessRunner('/test/path')
      runner.run_and_wait(
          timeout=0.5, terminate_before_kill=True, terminate_wait_time=1.0)

      # Single signal (SIGTERM) in 0.5 seconds.
      self.assertEqual(len(mock_popen.received_signals), 1)
      self.assertLess(
          abs(mock_popen.received_signals[0][1] - 0.5), self.TIME_ERROR)
      self.assertEqual(mock_popen.received_signals[0][0], Signal.TERM)

  def test_terminate_before_kill_timeout(self):
    """Tests process sigterm handler timing out."""
    with mock.patch('subprocess.Popen', mock_popen_factory(1.0, '',
                                                           1.0)) as mock_popen:
      runner = new_process.ProcessRunner('/test/path')
      runner.run_and_wait(
          timeout=0.5, terminate_before_kill=True, terminate_wait_time=0.5)

      # First signal (SIGTERM) should arrive in 0.5 seconds.
      self.assertEqual(len(mock_popen.received_signals), 2)
      self.assertLess(
          abs(mock_popen.received_signals[0][1] - 0.5), self.TIME_ERROR)
      self.assertEqual(mock_popen.received_signals[0][0], Signal.TERM)

      # First signal (SIGKILL) should arrive in 1.0 (0.5 + 0.5) seconds.
      self.assertLess(
          abs(mock_popen.received_signals[1][1] - 1.0), self.TIME_ERROR)
      self.assertEqual(mock_popen.received_signals[1][0], Signal.KILL)


class WindowsProcessTest(unittest.TestCase):
  """Windows Process tests."""

  # Allowed error for time calculations.
  TIME_ERROR = 0.3

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.new_process.ChildProcess.kill'
    ])
    self.mock.kill.side_effect = mock_kill
    self.mock.platform.return_value = 'WINDOWS'

  def test_terminate_before_kill_timeout(self):
    """Tests process kill handler called on timeout."""
    with mock.patch('subprocess.Popen', mock_popen_factory(1.0, '',
                                                           1.0)) as mock_popen:
      runner = new_process.ProcessRunner('/test/path')
      runner.run_and_wait(
          timeout=0.5, terminate_before_kill=True, terminate_wait_time=0.5)

      # Single signal (SIGKILL) should arrive in 0.5 seconds.
      self.assertEqual(len(mock_popen.received_signals), 1)
      self.assertLess(
          abs(mock_popen.received_signals[0][1] - 0.5), self.TIME_ERROR)
      self.assertEqual(mock_popen.received_signals[0][0], Signal.KILL)


@test_utils.integration
class MaxStdoutLenTest(unittest.TestCase):
  """Test max_stdout_len."""

  def test_over_limit(self):
    """Test stdout over limit."""
    runner = new_process.ProcessRunner('python')
    result = runner.run_and_wait(
        ['-c', 'print("A" + "B"*499 + "C"*499 + "D")'], max_stdout_len=64)
    self.assertEqual(
        b'A' + b'B' * 31 + b'\n...truncated 937 bytes...\n' + b'C' * 30 + b'D' +
        b'\n', result.output)

  def test_under_limit(self):
    """Test stdout under limit."""
    runner = new_process.ProcessRunner('python')
    result = runner.run_and_wait(['-c', 'print("A"*62)'], max_stdout_len=64)
    self.assertEqual(b'A' * 62 + b'\n', result.output)


if __name__ == '__main__':
  unittest.main()
