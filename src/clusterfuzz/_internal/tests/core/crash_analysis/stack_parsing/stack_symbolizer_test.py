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
from clusterfuzz._internal.tests.test_libs import helpers

TEST_STACK_TRACE = ("    #0 0x1234 (/lib/foo.so+0x5678)\n"
                    "    #1 0x5678 (/lib/foo.so+0x9abc)\n")


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


class LLVMSymbolizerCrashTest(unittest.TestCase):
  """Tests handling of llvm-symbolizer crashes."""

  def _mock_addr2line(self):
    """Mocks a working addr2line binary symbolizing TEST_STACK_TRACE."""
    mock_addr2line_stdin = mock.Mock()
    mock_addr2line_process = mock.Mock()
    mock_addr2line_process.stdin = mock_addr2line_stdin
    mock_addr2line_process.stdout = mock.Mock()
    mock_addr2line_process.stdout.readline.side_effect = [
        b'mock_func0\n', b'mock_file0:1\n', b'mock_func1\n', b'mock_file1:1\n'
    ]
    mock_addr2line_process.poll.return_value = 0
    return mock_addr2line_process

  def _mock_llvm_symbolizer(self, return_code=-11, stderr_content=''):
    """Mocks a llvm-symbolizer that crashes after the first write."""
    mock_llvm_stdin = mock.Mock()
    mock_llvm_stdin.write.side_effect = [
        None, BrokenPipeError(32, 'Broken pipe')
    ]
    mock_llvm_stdin.flush.side_effect = BrokenPipeError(32, 'Broken pipe')
    mock_llvm_stdin.close.side_effect = BrokenPipeError(32, 'Broken pipe')

    mock_llvm_process = mock.Mock()
    mock_llvm_process.stdin = mock_llvm_stdin
    mock_llvm_process.stdout = mock.Mock()
    mock_llvm_process.stdout.readline.return_value = b''
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
                     mock_exists, mock_popen, mock_get_symbolizer_path,
                     mock_log_error):
    """Helper to check logging behavior under different crash scenarios."""
    mock_get_symbolizer_path.return_value = '/path/to/llvm-symbolizer'
    mock_exists.side_effect = lambda path: path == '/path/to/llvm-symbolizer' or os.path.exists(path)

    # Set up mock for llvm-symbolizer process that exits after the first write.
    mock_llvm_process = self._mock_llvm_symbolizer(
        return_code=return_code, stderr_content=stderr_content)

    # Setup fallback addr2line symbolizer.
    mock_addr2line_process = self._mock_addr2line()

    def popen_side_effect(cmd, *_args, **_kwargs):
      if 'llvm-symbolizer' in cmd[0]:
        return mock_llvm_process
      if 'addr2line' in cmd[0]:
        return mock_addr2line_process
      raise AssertionError(f'Unexpected Popen call: {cmd}')

    mock_popen.side_effect = popen_side_effect

    stack_symbolizer.symbolize_stacktrace(TEST_STACK_TRACE)

    expected_calls = [mock.call(msg) for msg in expected_log_msgs]
    mock_log_error.assert_has_calls(expected_calls)

  @mock.patch(
      'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  @mock.patch('os.path.exists')
  def test_symbolizer_crash(self, mock_exists, mock_popen,
                            mock_get_symbolizer_path):
    """Test that a crash in llvm-symbolizer is handled and falls back to system symbolizer."""
    mock_get_symbolizer_path.return_value = '/path/to/llvm-symbolizer'
    mock_exists.side_effect = lambda path: path == '/path/to/llvm-symbolizer' or os.path.exists(path)

    # Set up mock for llvm-symbolizer process (crashes with SIGSEGV)
    mock_llvm_process = self._mock_llvm_symbolizer(return_code=-11)

    # Set up mock for addr2line process (fallback)
    mock_addr2line_process = self._mock_addr2line()

    def popen_side_effect(cmd, *_args, **_kwargs):
      if 'llvm-symbolizer' in cmd[0]:
        return mock_llvm_process
      if 'addr2line' in cmd[0]:
        return mock_addr2line_process
      raise AssertionError(f'Unexpected Popen call: {cmd}')

    mock_popen.side_effect = popen_side_effect

    expected_output = ("    #0 0x1234 in mock_func0 mock_file0:1\n"
                       "    #1 0x5678 in mock_func1 mock_file1:1\n")
    actual_output = stack_symbolizer.symbolize_stacktrace(TEST_STACK_TRACE)
    self.assertEqual(expected_output, actual_output)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch(
      'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  @mock.patch('os.path.exists')
  def test_return_code_neg11_no_stderr(
      self, mock_exists, mock_popen, mock_get_symbolizer_path, mock_log_error):
    self._check_logging(
        return_code=-11,
        stderr_content='',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x5678".',
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x9abc".'
        ],
        mock_exists=mock_exists,
        mock_popen=mock_popen,
        mock_get_symbolizer_path=mock_get_symbolizer_path,
        mock_log_error=mock_log_error)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch(
      'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  @mock.patch('os.path.exists')
  def test_return_code_neg11_with_stderr(
      self, mock_exists, mock_popen, mock_get_symbolizer_path, mock_log_error):
    self._check_logging(
        return_code=-11,
        stderr_content='some error info',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x5678". Stderr: some error info',
            'Symbolization using llvm-symbolizer failed (exit code -11) for: ""/lib/foo.so" 0x9abc". Stderr: some error info'
        ],
        mock_exists=mock_exists,
        mock_popen=mock_popen,
        mock_get_symbolizer_path=mock_get_symbolizer_path,
        mock_log_error=mock_log_error)

  @mock.patch('clusterfuzz._internal.metrics.logs.error')
  @mock.patch(
      'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path')
  @mock.patch('subprocess.Popen')
  @mock.patch('sys.platform', 'linux')
  @mock.patch('os.path.exists')
  def test_return_code_none_no_stderr(self, mock_exists, mock_popen,
                                      mock_get_symbolizer_path, mock_log_error):
    self._check_logging(
        return_code=None,
        stderr_content='',
        expected_log_msgs=[
            'Symbolization using llvm-symbolizer failed for: ""/lib/foo.so" 0x5678".',
            'Symbolization using llvm-symbolizer failed for: ""/lib/foo.so" 0x9abc".'
        ],
        mock_exists=mock_exists,
        mock_popen=mock_popen,
        mock_get_symbolizer_path=mock_get_symbolizer_path,
        mock_log_error=mock_log_error)


class ProcessTrustyStacktraceTest(unittest.TestCase):
  """Tests that process_trusty_stacktrace returns early without downloading symbols 
  when required Trusty metadata is missing."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.symbols_downloader.download_trusty_symbols_if_needed',
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.system.environment.is_uworker',
    ])
    self.mock.is_uworker.return_value = False
    self.loop = stack_symbolizer.SymbolizationLoop()

  def test_early_return_when_missing_app_and_bid(self):
    """Tests that we avoid processing the Trusty stacktrace and downloading 
    symbols when both trusty_app and trusty_bid are missing."""
    stacktrace = 'Some standard crash without trusty metadata\n#0 0x1234'
    self.assertEqual(stacktrace,
                     self.loop.process_trusty_stacktrace(stacktrace))
    self.mock.download_trusty_symbols_if_needed.assert_not_called()

  def test_early_return_when_missing_app(self):
    """Tests that we avoid processing the Trusty stacktrace and downloading symbols
    when trusty_app is missing (even if trusty_bid is present)."""
    stacktrace = ', Build: 1234567, Built:\n#0 0x1234'
    self.assertEqual(stacktrace,
                     self.loop.process_trusty_stacktrace(stacktrace))
    self.mock.download_trusty_symbols_if_needed.assert_not_called()

  def test_early_return_when_missing_bid(self):
    """Tests that we avoid processing the Trusty stacktrace and downloading symbols 
    when trusty_bid is missing (even if trusty_app is present)."""
    stacktrace = '(app: keymaster)\n#0 0x1234'
    self.assertEqual(stacktrace,
                     self.loop.process_trusty_stacktrace(stacktrace))
    self.mock.download_trusty_symbols_if_needed.assert_not_called()

  def test_early_return_on_uworker_without_symbols_dir(self):
    """Tests that we avoid processing the Trusty stacktrace and downloading symbols when on a uworker without a SYMBOLS_DIR (even if both trusty_app and trusty_bid are present)."""
    self.mock.is_uworker.return_value = True
    self.mock.get_value.return_value = None

    stacktrace = '(app: keymaster), Build: 1234567, Built:\n#0 0x1234'
    self.assertEqual(stacktrace,
                     self.loop.process_trusty_stacktrace(stacktrace))
    self.mock.download_trusty_symbols_if_needed.assert_not_called()


class SymbolizeStacktraceChainTest(unittest.TestCase):
  """Tests that symbolize_stacktrace correctly chains Trusty and standard stacktrace symbolization workflows based on the environment."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.SymbolizationLoop',
        'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path',
        'clusterfuzz._internal.system.environment.is_android_emulator',
        'clusterfuzz._internal.system.environment.is_trusted_host',
        'clusterfuzz._internal.system.environment.platform',
    ])
    self.mock.is_trusted_host.return_value = False
    self.mock.platform.return_value = 'LINUX'
    self.mock.get_llvm_symbolizer_path.return_value = '/path/to/llvm-symbolizer'
    self.mock_loop = self.mock.SymbolizationLoop.return_value
    self.mock_loop.process_stacktrace.return_value = 'final_symbolized_output'

  def test_symbolize_stacktrace_chaining_on_android_emulator(self):
    """Tests that on an Android emulator, both process_trusty_stacktrace and process_stacktrace 
    execute sequentially and preserve intermediate results."""
    self.mock.is_android_emulator.return_value = True
    self.mock_loop.process_trusty_stacktrace.return_value = (
        'trusty_symbolized_output')

    result = stack_symbolizer.symbolize_stacktrace('unsymbolized_input')

    self.mock_loop.process_trusty_stacktrace.assert_called_once_with(
        'unsymbolized_input')
    self.mock_loop.process_stacktrace.assert_called_once_with(
        'trusty_symbolized_output')
    self.assertEqual('final_symbolized_output', result)

  def test_symbolize_stacktrace_no_trusty_on_non_emulator(self):
    """Tests that on non-emulator environments, process_trusty_stacktrace is bypassed and process_stacktrace 
    receives the raw unsymbolized stacktrace directly."""
    self.mock.is_android_emulator.return_value = False

    result = stack_symbolizer.symbolize_stacktrace('unsymbolized_input')

    self.mock_loop.process_trusty_stacktrace.assert_not_called()
    self.mock_loop.process_stacktrace.assert_called_once_with(
        'unsymbolized_input')
    self.assertEqual('final_symbolized_output', result)
