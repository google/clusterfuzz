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
"""Tests for the stack symbolizer module."""

import os
import unittest
from unittest import mock

from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer

TEST_STACK_TRACE = ("    #0 0x0001 (/lib/foo.so+0x1000)\n"
                    "    #1 0x0002 (/lib/foo.so+0x2000)\n"
                    "    #2 0x0003 (/lib/foo.so+0x3000)\n")

TEST_STACK_TRACE_INLINE = ("    #0 0x0001 (/lib/foo.so+0x1000)\n"
                           "    #1 0x0002 (/lib/foo.so+0x2000)\n")

# Expected inputs and outputs for LLVM symbolizer (3 frames).
UNSYMBOLIZED_LLVM_FRAMES = [
    b'"/lib/foo.so" 0x1000\n',
    b'"/lib/foo.so" 0x2000\n',
    b'"/lib/foo.so" 0x3000\n',
]

SYMBOLIZED_LLVM_FRAMES = [
    # Frame 0
    b'llvm_func0\n',
    b'llvm_file0:10\n',
    b'\n',
    # Frame 1
    b'llvm_func1\n',
    b'llvm_file1:20\n',
    b'\n',
    # Frame 2
    b'llvm_func2\n',
    b'llvm_file2:30\n',
    b'\n'
]

# Expected inputs and outputs for addr2line symbolizer (3 frames).
UNSYMBOLIZED_ADDR2LINE_FRAMES = [
    b'0x1000\n',
    b'0x2000\n',
    b'0x3000\n',
]

SYMBOLIZED_ADDR2LINE_FRAMES = [
    # Frame 0
    b'addr2line_func0\n',
    b'addr2line_file0:1\n',
    # Frame 1
    b'addr2line_func1\n',
    b'addr2line_file1:1\n',
    # Frame 2
    b'addr2line_func2\n',
    b'addr2line_file2:1\n',
]

# In practice, both symbolizers format their output the same way, but we use
# distinct mocked function names (e.g. 'llvm_func0' vs 'addr2line_func0')
# in our tests to verify which symbolizer was actually used.
EXPECTED_LLVM_OUTPUT = ("    #0 0x0001 in llvm_func0 llvm_file0:10\n"
                        "    #1 0x0002 in llvm_func1 llvm_file1:20\n"
                        "    #2 0x0003 in llvm_func2 llvm_file2:30\n")

EXPECTED_ADDR2LINE_OUTPUT = (
    "    #0 0x0001 in addr2line_func0 addr2line_file0:1\n"
    "    #1 0x0002 in addr2line_func1 addr2line_file1:1\n"
    "    #2 0x0003 in addr2line_func2 addr2line_file2:1\n")

# Expected inputs and outputs for LLVM inline frames test.
UNSYMBOLIZED_LLVM_INLINE_FRAMES = [
    b'"/lib/foo.so" 0x1000\n',
    b'"/lib/foo.so" 0x2000\n',
]

SYMBOLIZED_LLVM_INLINE_FRAMES = [
    # Frame 0 (Inline)
    b'llvm_inline_func\n',
    b'llvm_inline_file:5\n',
    # Frame 0 (Caller)
    b'llvm_caller_func\n',
    b'llvm_caller_file:10\n',
    b'\n',
    # Frame 1
    b'llvm_func1\n',
    b'llvm_file1:20\n',
    b'\n'
]

EXPECTED_LLVM_INLINE_OUTPUT = (
    "    #0 0x0001 in llvm_inline_func llvm_inline_file:5\n"
    "    #1 0x0001 in llvm_caller_func llvm_caller_file:10\n"
    "    #2 0x0002 in llvm_func1 llvm_file1:20\n")


class ChromeDsymHintsTests(unittest.TestCase):
  """Tests chrome_dsym_hints."""

  def test_standalone_executable(self):
    """Tests that standalone executable work as expected."""
    self.assertEqual([], stack_symbolizer.chrome_dsym_hints('/build/binary'))

  def test_standalone_framework_or_app(self):
    """Tests that standalone frame or app bundle work as expected."""
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.app'))
    self.assertEqual(
        ['/build/Content Shell.dSYM'],
        stack_symbolizer.chrome_dsym_hints('/build/Content Shell.framework'))

  def test_nested_bundles(self):
    """Tests that two or three nested bundles work as expected."""
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Frameworks/Content Shell Framework.framework/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))
    self.assertEqual(
        ['/build/Content Shell Helper.dSYM'],
        stack_symbolizer.chrome_dsym_hints(
            '/build/Content Shell.app/Contents'
            '/Versions/C/Helpers'
            '/Content Shell Helper.app/Contents/MacOS/Content Shell Helper'))


class LLVMSymbolizerTest(unittest.TestCase):
  """Tests for llvm-symbolizer."""

  def setUp(self):
    super().setUp()
    get_llvm_symbolizer_path_patcher = mock.patch(
        'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path',
        return_value='llvm-symbolizer')
    get_llvm_symbolizer_path_patcher.start()
    self.addCleanup(get_llvm_symbolizer_path_patcher.stop)

    original_exists = os.path.exists
    exists_patcher = mock.patch(
        'os.path.exists',
        side_effect=
        lambda path: path == 'llvm-symbolizer' or original_exists(path))
    exists_patcher.start()
    self.addCleanup(exists_patcher.stop)

  def _get_called_binaries(self, mock_popen):
    """Returns the list of binary paths called by mock_popen, in order."""
    # Each call in call_args_list is (args, kwargs).
    # args[0] is the 'cmd' list, and cmd[0] is the binary path.
    return [args[0][0] for args, _ in mock_popen.call_args_list]

  def _mock_successful_llvm_process(self):
    """Mocks a successful llvm-symbolizer process.

    This mock expects to be called with UNSYMBOLIZED_LLVM_FRAMES and returns
    SYMBOLIZED_LLVM_FRAMES.
    """
    mock_llvm_stdin = mock.Mock()
    num_writes = 0

    def write_side_effect(data):
      nonlocal num_writes
      self.assertEqual(UNSYMBOLIZED_LLVM_FRAMES[num_writes], data)
      num_writes += 1

    mock_llvm_stdin.write.side_effect = write_side_effect

    mock_llvm_process = mock.Mock()
    mock_llvm_process.stdin = mock_llvm_stdin
    mock_llvm_process.stdout = mock.Mock()
    mock_llvm_process.stdout.readline.side_effect = list(SYMBOLIZED_LLVM_FRAMES)
    mock_llvm_process.stderr = mock.Mock()
    mock_llvm_process.stderr.readline.return_value = b''
    # return None to indicate the process is still running.
    mock_llvm_process.poll.return_value = None

    return mock_llvm_process

  def _mock_llvm_inline_process(self):
    """Mocks an llvm-symbolizer process returning inline frames.

    This mock expects to be called with UNSYMBOLIZED_LLVM_INLINE_FRAMES and
    returns SYMBOLIZED_LLVM_INLINE_FRAMES.
    """
    mock_llvm_stdin = mock.Mock()
    num_writes = 0

    def write_side_effect(data):
      nonlocal num_writes
      self.assertEqual(UNSYMBOLIZED_LLVM_INLINE_FRAMES[num_writes], data)
      num_writes += 1

    mock_llvm_stdin.write.side_effect = write_side_effect

    mock_llvm_process = mock.Mock()
    mock_llvm_process.stdin = mock_llvm_stdin
    mock_llvm_process.stdout = mock.Mock()
    mock_llvm_process.stdout.readline.side_effect = list(
        SYMBOLIZED_LLVM_INLINE_FRAMES)
    mock_llvm_process.stderr = mock.Mock()
    mock_llvm_process.stderr.readline.return_value = b''
    # return None to indicate the process is still running.
    mock_llvm_process.poll.return_value = None

    return mock_llvm_process

  def _mock_addr2line_process(self, starting_frame=0):
    """Mocks a working addr2line process.

    This mock expects to be called with UNSYMBOLIZED_ADDR2LINE_FRAMES and
    returns SYMBOLIZED_ADDR2LINE_FRAMES.
    """
    mock_addr2line_stdin = mock.Mock()
    num_writes = starting_frame

    def write_side_effect(data):
      nonlocal num_writes
      self.assertEqual(UNSYMBOLIZED_ADDR2LINE_FRAMES[num_writes], data)
      num_writes += 1

    mock_addr2line_stdin.write.side_effect = write_side_effect

    mock_addr2line_process = mock.Mock()
    mock_addr2line_process.stdin = mock_addr2line_stdin
    mock_addr2line_process.stdout = mock.Mock()
    start_readline_index = starting_frame * 2
    mock_addr2line_process.stdout.readline.side_effect = list(
        SYMBOLIZED_ADDR2LINE_FRAMES[start_readline_index:])
    mock_addr2line_process.poll.return_value = 0
    return mock_addr2line_process

  def _mock_crashing_llvm_symbolizer(self, return_code=-11, stderr_content=''):
    """Mocks a llvm-symbolizer that crashes on the second write."""
    mock_llvm_stdin = mock.Mock()
    mock_llvm_stdin.write.side_effect = [
        None,
        BrokenPipeError(32, 'Broken pipe'),
        BrokenPipeError(32, 'Broken pipe')
    ]
    mock_llvm_stdin.flush.side_effect = [
        None,
        BrokenPipeError(32, 'Broken pipe'),
        BrokenPipeError(32, 'Broken pipe')
    ]
    mock_llvm_stdin.close.side_effect = BrokenPipeError(32, 'Broken pipe')

    mock_llvm_process = mock.Mock()
    mock_llvm_process.stdin = mock_llvm_stdin
    mock_llvm_process.stdout = mock.Mock()
    # Symbolize the first frame successfully, then return EOF the same way a
    # crashing symbolizer would.
    mock_llvm_process.stdout.readline.side_effect = list(
        SYMBOLIZED_LLVM_FRAMES[:3]) + [b'']
    mock_llvm_process.stderr = mock.Mock()

    if stderr_content:
      bytes_lines = [
          line.encode('utf-8') + b'\n' for line in stderr_content.splitlines()
      ]
      bytes_lines.append(b'')
      mock_llvm_process.stderr.readline.side_effect = bytes_lines
    else:
      mock_llvm_process.stderr.readline.return_value = b''

    mock_llvm_process.poll.return_value = return_code
    return mock_llvm_process

  def _check_logging(self, return_code, stderr_content, expected_log_msgs,
                     mock_popen, mock_log_error):
    """Helper to check logging behavior under different crash scenarios."""

    # Set up mock for llvm-symbolizer process that exits after the first write.
    mock_llvm_process = self._mock_crashing_llvm_symbolizer(
        return_code=return_code, stderr_content=stderr_content)

    # Setup fallback addr2line symbolizer.
    mock_addr2line_process = self._mock_addr2line_process(starting_frame=1)

    mock_popen.side_effect = [mock_llvm_process, mock_addr2line_process]

    stack_symbolizer.symbolize_stacktrace(TEST_STACK_TRACE)

    expected_calls = [mock.call(msg) for msg in expected_log_msgs]
    mock_log_error.assert_has_calls(expected_calls)

    # Verify Popen calls
    self.assertEqual(['llvm-symbolizer', 'addr2line'],
                     self._get_called_binaries(mock_popen))

  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_successful_llvm_symbolization(self, mock_popen):
    """Test successful symbolization using llvm-symbolizer."""
    mock_successful_llvm_process = self._mock_successful_llvm_process()
    mock_popen.return_value = mock_successful_llvm_process

    actual_output = stack_symbolizer.symbolize_stacktrace(TEST_STACK_TRACE)
    self.assertEqual(EXPECTED_LLVM_OUTPUT, actual_output)

    # Verify Popen calls
    self.assertEqual(['llvm-symbolizer'], self._get_called_binaries(mock_popen))

  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_llvm_inline_frames(self, mock_popen):
    """Test that llvm-symbolizer inline frames are correctly parsed and numbered."""
    mock_llvm_process = self._mock_llvm_inline_process()
    mock_popen.return_value = mock_llvm_process

    actual_output = stack_symbolizer.symbolize_stacktrace(
        TEST_STACK_TRACE_INLINE)
    self.assertEqual(EXPECTED_LLVM_INLINE_OUTPUT, actual_output)

    # Verify Popen calls
    self.assertEqual(['llvm-symbolizer'], self._get_called_binaries(mock_popen))

  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_symbolizer_crash(self, mock_popen):
    """Test that a crash in llvm-symbolizer is handled and falls back to system symbolizer."""

    # Set up mock for llvm-symbolizer process (crashes with SIGSEGV)
    mock_llvm_process = self._mock_crashing_llvm_symbolizer(return_code=-11)

    # Set up mock for addr2line process (fallback)
    mock_addr2line_process = self._mock_addr2line_process(starting_frame=1)

    mock_popen.side_effect = [mock_llvm_process, mock_addr2line_process]

    actual_output = stack_symbolizer.symbolize_stacktrace(TEST_STACK_TRACE)

    # Frame 0 is symbolized by LLVM, Frame 1 & 2 fallback to addr2line
    expected_output = ("    #0 0x0001 in llvm_func0 llvm_file0:10\n"
                       "    #1 0x0002 in addr2line_func1 addr2line_file1:1\n"
                       "    #2 0x0003 in addr2line_func2 addr2line_file2:1\n")
    self.assertEqual(expected_output, actual_output)

    # Verify Popen calls
    self.assertEqual(['llvm-symbolizer', 'addr2line'],
                     self._get_called_binaries(mock_popen))

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_return_code_neg11_no_stderr(self, mock_popen, mock_log_error):
    self._check_logging(
        return_code=-11,
        stderr_content='',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x2000".',
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x3000".'
        ],
        mock_popen=mock_popen,
        mock_log_error=mock_log_error)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_return_code_neg11_with_stderr(self, mock_popen, mock_log_error):
    self._check_logging(
        return_code=-11,
        stderr_content='some error info',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x2000". Stderr: some error info',
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x3000". Stderr: some error info'
        ],
        mock_popen=mock_popen,
        mock_log_error=mock_log_error)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  def test_return_code_none_no_stderr(self, mock_popen, mock_log_error):
    self._check_logging(
        return_code=None,
        stderr_content='',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed for: ""/lib/foo.so" 0x2000".',
            'Symbolization using llvm-symbolizer failed for: ""/lib/foo.so" 0x3000".'
        ],
        mock_popen=mock_popen,
        mock_log_error=mock_log_error)
