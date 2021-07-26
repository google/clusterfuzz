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
"""environment tests."""
import os
import unittest

import parameterized

from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class EnvironmentTest(unittest.TestCase):
  """Tests for environment module."""

  def setUp(self):
    test_helpers.patch_environ(self)
    environment.reset_environment()

  def test_reset_environment(self):
    """Tests that reset_environment() works as intended."""
    variable = 'NEW_VARIABLE'
    # Check that the test's assumptions are correct.
    self.assertNotIn(variable, os.environ)
    # Test that reset_environment() works properly.
    environment.set_value(variable, 1)
    environment.reset_environment()
    self.assertNotIn(variable, os.environ)

  def test_set_bot_environment_default_variables(self):
    """Tests that set_bot_environment() sets default variables as
    intended."""
    self.assertNotIn('TEST_TIMEOUT', os.environ)
    self.assertNotIn('VERSION_PATTERN', os.environ)
    self.assertNotIn('WATCH_FOR_PROCESS_EXIT', os.environ)

    # Now test that setting default variables works properly.
    environment.set_bot_environment()
    self.assertEqual(environment.get_value('TEST_TIMEOUT'), 10)
    self.assertEqual(environment.get_value('VERSION_PATTERN'), '')
    self.assertEqual(environment.get_value('WATCH_FOR_PROCESS_EXIT'), False)


class GetExecutableFileNameTest(unittest.TestCase):
  """Tests for get_executable_filename."""

  EXECUTABLE = 'fuzzer_executable'

  def setUp(self):
    test_helpers.patch(self,
                       ['clusterfuzz._internal.system.environment.platform'])

  @parameterized.parameterized.expand(['MAC', 'LINUX'])
  def test_non_windows(self, platform):
    """Tests that it behaves as intended on platforms that aren't Windows."""
    self.mock.platform.return_value = platform
    self.assertEqual(self.EXECUTABLE,
                     environment.get_executable_filename(self.EXECUTABLE))

  def test_windows(self):
    """Tests that it behaves as intended on Windows."""
    self.mock.platform.return_value = 'WINDOWS'
    executable_with_extension = self.EXECUTABLE + '.exe'
    # Test that it adds an extension if needed.
    self.assertEqual(executable_with_extension,
                     environment.get_executable_filename(self.EXECUTABLE))

    # Now test that it doesn't add an extension when not needed.
    self.assertEqual(
        executable_with_extension,
        environment.get_executable_filename(executable_with_extension))


class ParseMemoryToolOptionsTest(unittest.TestCase):
  """Tests for _parse_memory_tool_options."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.log_warn',
        'clusterfuzz._internal.metrics.logs.log_error'
    ])

    self.windows_expected = {
        'redzone':
            64,
        'strict_string_check':
            1,
        'print_suppressions':
            0,
        'strict_memcmp':
            1,
        'allow_user_segv_handler':
            0,
        'handle_sigfpe':
            1,
        'handle_sigbus':
            1,
        'detect_stack_use_after_return':
            0,
        'alloc_dealloc_mismatch':
            0,
        'print_scariness':
            1,
        'allocator_may_return_null':
            1,
        'quarantine_size_mb':
            256,
        'detect_odr_violation':
            0,
        'external_symbolizer_path':
            r'"c:\clusterfuzz\resources\platform\windows\llvm-symbolizer.exe"',
        'handle_sigill':
            1,
        'allocator_release_to_os_interval_ms':
            500,
        'use_sigaltstack':
            1,
        'fast_unwind_on_fatal':
            1,
        'detect_leaks':
            0,
        'handle_segv':
            1,
        'handle_abort':
            1,
        'check_malloc_usable_size':
            0,
        'detect_container_overflow':
            0,
        'symbolize':
            1,
        'print_summary':
            1
    }

    self.windows_options_str = (
        'redzone=64:print_summary=1:external_symbolizer_path='
        r'"c:\clusterfuzz\resources\platform\windows\llvm-symbolizer.exe"'
        ':handle_sigill=1:strict_string_check=1:allocator_release_to_os_interva'
        'l_ms=500:print_suppressions=0:strict_memcmp=1:allow_user_segv_handler='
        '0:use_sigaltstack=1:handle_sigfpe=1:handle_sigbus=1:detect_stack_use_a'
        'fter_return=0:alloc_dealloc_mismatch=0:detect_leaks=0:print_scariness='
        '1:allocator_may_return_null=1:handle_abort=1:check_malloc_usable_size='
        '0:detect_container_overflow=0:quarantine_size_mb=256:detect_odr_violat'
        'ion=0:symbolize=1:handle_segv=1:fast_unwind_on_fatal=1')

  def _helper(self, options_str, expected):
    """Helper function to parse |options_str| and assert parsing was successful
    had |expected| result."""
    parsed_options = environment._parse_memory_tool_options(options_str)  # pylint: disable=protected-access
    self.assertEqual(expected, parsed_options)
    self.assertEqual(0, self.mock.log_error.call_count)
    self.assertEqual(0, self.mock.log_warn.call_count)

  def test_non_windows(self):
    """Test that a non-Windows options string is parsed correctly."""
    options_str = (
        'redzone=64:strict_string_check=1:print_suppressions=0:strict_memcmp=1:'
        'allow_user_segv_handler=0:allocator_may_return_null=1:handle_sigfpe=1:'
        'handle_sigbus=1:detect_stack_use_after_return=1:alloc_dealloc_mismatch'
        '=0:print_scariness=1:max_uar_stack_size_log=16:quarantine_size_mb=256:'
        'detect_odr_violation=0:handle_sigill=1:allocator_release_to_os_interva'
        'l_ms=500:use_sigaltstack=1:fast_unwind_on_fatal=1:detect_leaks=1:print'
        '_summary=1:handle_abort=1:check_malloc_usable_size=0:detect_container'
        '_overflow=1:symbolize=0:handle_segv=1')

    expected = {
        'redzone': 64,
        'strict_string_check': 1,
        'print_suppressions': 0,
        'strict_memcmp': 1,
        'allow_user_segv_handler': 0,
        'max_uar_stack_size_log': 16,
        'handle_sigfpe': 1,
        'handle_sigbus': 1,
        'detect_stack_use_after_return': 1,
        'alloc_dealloc_mismatch': 0,
        'print_scariness': 1,
        'allocator_may_return_null': 1,
        'quarantine_size_mb': 256,
        'detect_odr_violation': 0,
        'handle_sigill': 1,
        'allocator_release_to_os_interval_ms': 500,
        'use_sigaltstack': 1,
        'fast_unwind_on_fatal': 1,
        'detect_leaks': 1,
        'handle_segv': 1,
        'handle_abort': 1,
        'check_malloc_usable_size': 0,
        'detect_container_overflow': 1,
        'symbolize': 0,
        'print_summary': 1
    }
    self._helper(options_str, expected)

  def test_windows_double_quotes(self):
    """Test that a Windows options string with double quotes is parsed
    correctly."""
    self._helper(self.windows_options_str, self.windows_expected)

  def test_windows_single_quotes(self):
    """Test that a Windows options string with single quotes is parsed
    correctly."""
    self.windows_options_str = self.windows_options_str.replace('"', '\'')
    self.windows_expected['external_symbolizer_path'] = (
        self.windows_expected['external_symbolizer_path'].replace('"', '\''))
    self._helper(self.windows_options_str, self.windows_expected)


class EvalValueTest(unittest.TestCase):
  """Tests for _eval_value."""

  @parameterized.parameterized.expand([
      # Test normal evaling.
      ('1', 1),
      ('-1.0', -1.0),
      ('"string"', 'string'),
      ("'string'", 'string'),

      # Test handling of strings that can't be evaled.
      ('1..', '1..')
  ])
  def test_eval_value(self, value_string, expected_result):
    """Test that evaluating a value string produces the expected result."""
    actual_result = environment._eval_value(value_string)  # pylint: disable=protected-access
    self.assertEqual(expected_result, actual_result)


class ResetCurrentMemoryToolOptionsTest(unittest.TestCase):
  """Tests for reset_current_memory_tool_options."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_windows_symbolizer(self):
    """Test that the reset_current_memory_tool_options returns the expected path
    to the llvm symbolizer on Windows."""
    os.environ['JOB_NAME'] = 'windows_libfuzzer_chrome_asan'
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path'
    ])
    self.mock.platform.return_value = 'WINDOWS'
    windows_symbolizer_path = (
        r'c:\clusterfuzz\resources\platform\windows\llvm-symbolizer.exe')
    self.mock.get_llvm_symbolizer_path.return_value = windows_symbolizer_path
    environment.reset_current_memory_tool_options()
    self.assertIn('external_symbolizer_path="%s"' % windows_symbolizer_path,
                  os.environ['ASAN_OPTIONS'])

  def test_ubsan_enabled(self):
    """Test reset_current_memory_tool_options when ubsan is enabled."""
    os.environ['JOB_NAME'] = 'libfuzzer_chrome_asan'
    os.environ['UBSAN'] = 'True'
    environment.reset_current_memory_tool_options(disable_ubsan=False)
    self.assertDictEqual({
        'halt_on_error': 1,
        'handle_abort': 1,
        'handle_segv': 1,
        'handle_sigbus': 1,
        'handle_sigfpe': 1,
        'handle_sigill': 1,
        'print_stacktrace': 1,
        'print_summary': 1,
        'print_suppressions': 0,
        'silence_unsigned_overflow': 1,
        'use_sigaltstack': 1
    }, environment.get_memory_tool_options('UBSAN_OPTIONS'))

  def test_ubsan_disabled(self):
    """Test reset_current_memory_tool_options when ubsan is disabled."""
    os.environ['JOB_NAME'] = 'libfuzzer_chrome_asan'
    os.environ['UBSAN'] = 'True'
    environment.reset_current_memory_tool_options(disable_ubsan=True)
    self.assertDictEqual({
        'halt_on_error': 0,
        'print_stacktrace': 0,
        'print_suppressions': 0
    }, environment.get_memory_tool_options('UBSAN_OPTIONS'))


class MaybeConvertToIntTest(unittest.TestCase):
  """Tests for _maybe_convert_to_int."""

  @parameterized.parameterized.expand([
      # Test int deserializing.
      ('1', 1),
      ('-9', -9),

      # Test that other types are not deserialized
      ('C:\\path.exe', 'C:\\path.exe'),
      ('1.0', '1.0'),
      ('True', 'True'),
      ('true', 'true'),
  ])
  def test_maybe_convert_to_int(self, literal_value, expected_result):
    """Test calling _maybe_convert_to_int on a string produces the expected
    result."""
    actual_result = environment._maybe_convert_to_int(literal_value)  # pylint: disable=protected-access
    self.assertEqual(expected_result, actual_result)


class GetMemoryToolOptionsTest(unittest.TestCase):
  """Tests for get_memory_tool_options."""

  def test_doesnt_mutate_options(self):
    """Test that calling get_memory_tool_options followed by
    set_memory_tool_options does not mutate sanitizer options unless we
    do so explicitly."""
    # Make environment module use the Windows symbolizer, since its path is
    # hard to get right.
    test_helpers.patch_environ(self)
    os.environ['JOB_NAME'] = 'windows_libfuzzer_chrome_asan'
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.system.environment.get_llvm_symbolizer_path'
    ])
    self.mock.platform.return_value = 'WINDOWS'
    windows_symbolizer_path = (
        r'c:\clusterfuzz\resources\platform\windows\llvm-symbolizer.exe')

    self.mock.get_llvm_symbolizer_path.return_value = windows_symbolizer_path
    environment.reset_current_memory_tool_options()
    memory_tool_var = 'ASAN_OPTIONS'
    first_asan_options_dict = environment.get_memory_tool_options(
        memory_tool_var)
    environment.set_memory_tool_options(memory_tool_var,
                                        first_asan_options_dict)
    second_asan_options_dict = environment.get_memory_tool_options(
        memory_tool_var)
    self.assertDictEqual(first_asan_options_dict, second_asan_options_dict)


class AppEngineNoopTest(unittest.TestCase):
  """Tests for appengine_noop."""

  def setUp(self):
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.system.environment.is_running_on_app_engine'])

  def test_appengine(self):
    """Test calling function in App Engine environment."""
    self.mock.is_running_on_app_engine.return_value = True

    @environment.appengine_noop
    def test_function():
      return 10

    self.assertEqual(None, test_function())

  def test_bot(self):
    """Test calling function in bot environment."""
    self.mock.is_running_on_app_engine.return_value = False

    @environment.appengine_noop
    def test_function():
      return 10

    self.assertEqual(10, test_function())


class BotNoopTest(unittest.TestCase):
  """Tests for bot_noop."""

  def setUp(self):
    test_helpers.patch(
        self,
        ['clusterfuzz._internal.system.environment.is_running_on_app_engine'])

  def test_appengine(self):
    """Test calling function in App Engine environment."""
    self.mock.is_running_on_app_engine.return_value = True

    @environment.bot_noop
    def test_function():
      return 10

    self.assertEqual(10, test_function())

  def test_bot(self):
    """Test calling function in bot environment."""
    self.mock.is_running_on_app_engine.return_value = False

    @environment.bot_noop
    def test_function():
      return 10

    self.assertEqual(None, test_function())


class LocalNoopTest(unittest.TestCase):
  """Tests for local_noop."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.system.environment.is_running_on_app_engine_development'
    ])

  def test_prod(self):
    """Test calling function in production environment."""
    self.mock.is_running_on_app_engine_development.return_value = False

    @environment.local_noop
    def test_function():
      return 10

    self.assertEqual(10, test_function())

  def test_local_appengine(self):
    """Test calling function in local environment."""
    self.mock.is_running_on_app_engine_development.return_value = True

    @environment.local_noop
    def test_function():
      return 10

    self.assertEqual(None, test_function())

  def test_local_bot(self):
    """Test calling function in local environment."""
    environment.set_value('LOCAL_DEVELOPMENT', True)
    environment.set_value('PY_UNITTESTS', False)
    self.mock.is_running_on_app_engine_development.return_value = False

    @environment.local_noop
    def test_function():
      return 10

    self.assertEqual(None, test_function())
