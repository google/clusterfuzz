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
"""shell tests."""
import os
import sys
import unittest

import mock
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class RemoveEmptyFilesTest(fake_filesystem_unittest.TestCase):
  """Tests for remove_empty_files."""

  def setUp(self):
    # FIXME: Add support for Windows.
    if not environment.is_posix():
      self.skipTest('Process tests are only applicable for posix platforms.')

    test_utils.set_up_pyfakefs(self)

  def test_remove(self):
    """Test remove."""
    self.fs.create_file('/test/aa/bb.txt', contents='s')
    self.fs.create_file('/test/aa/cc.txt', contents='')
    self.fs.create_file('/test/aa/aa/dd.txt', contents='s')
    self.fs.create_file('/test/aa/aa/aa.txt', contents='')

    shell.remove_empty_files('/test')

    self.assertTrue(os.path.exists('/test/aa/bb.txt'))
    self.assertTrue(os.path.exists('/test/aa/aa/dd.txt'))
    self.assertFalse(os.path.exists('/test/aa/cc.txt'))
    self.assertFalse(os.path.exists('/test/aa/aa/aa.txt'))

  def test_ignore_file(self):
    self.fs.create_file('/test/aa/cc.txt', contents='')
    shell.remove_empty_files('/test/aa/cc.txt')
    self.assertTrue(os.path.exists('/test/aa/cc.txt'))

  @mock.patch('os.remove', autospec=True)
  def test_exception(self, mock_remove):
    # bypass pyfakefs's os.remove.
    os.remove = mock_remove
    mock_remove.side_effect = OSError()

    self.fs.create_file('/test/aa/cc.txt', contents='')
    shell.remove_empty_files('/test')
    self.assertTrue(os.path.exists('/test/aa/cc.txt'))


class RemoveDirectoryTest(unittest.TestCase):
  """Tests for remove_directory."""

  def setUp(self):
    test_helpers.patch(self, [
        'os.chmod',
        'os.makedirs',
        'os.path.exists',
        'os.system',
        'clusterfuzz._internal.system.environment.platform',
        'clusterfuzz._internal.metrics.logs.log_error',
        'clusterfuzz._internal.metrics.logs.log_warn',
        'shutil.rmtree',
    ])

  def _test_remove_os_specific(self, platform, recreate, raise_makedirs_error):
    """Helper for testing removing dir with os-specific command."""
    self.mock.platform.return_value = platform
    self.mock.exists.side_effect = [True, False, False]
    if raise_makedirs_error:
      self.mock.makedirs.side_effect = OSError()

    result = shell.remove_directory('dir', recreate=recreate)

    if recreate:
      self.assertEqual(not raise_makedirs_error, result)
    else:
      self.assertTrue(result)

    self.mock.rmtree.assert_has_calls([])
    if recreate:
      self.mock.makedirs.assert_has_calls([mock.call('dir')])
    else:
      self.mock.makedirs.assert_has_calls([])

  def test_remove_os_specific_windows(self):
    """Test remove with os-specific command on windows."""
    self._test_remove_os_specific('WINDOWS', True, False)
    self.mock.system.assert_has_calls([mock.call('rd /s /q "dir" > nul 2>&1')])

  def test_remove_os_specific_non_windows(self):
    """Test remove with os-specific command on non-windows."""
    self._test_remove_os_specific('LINUX', True, False)
    self.mock.system.assert_has_calls(
        [mock.call('rm -rf "dir" > /dev/null 2>&1')])

  def test_remove_without_recreate(self):
    """Test remove without recreate."""
    self._test_remove_os_specific('LINUX', False, True)

  def test_remove_with_makedirs_error(self):
    """Test remove when makedirs errors."""
    self._test_remove_os_specific('LINUX', True, True)

  def test_remove_shutil_success(self):
    """Test remove with shutil."""
    self.mock.exists.side_effect = [True, True, False]
    self.assertTrue(shell.remove_directory('dir'))
    self.mock.system.assert_has_calls(
        [mock.call('rm -rf "dir" > /dev/null 2>&1')])
    self.mock.rmtree.assert_has_calls([mock.call('dir', onerror=mock.ANY)])

  def test_remove_shutil_failure(self):
    """Test remove with shutil but fails."""
    self.mock.exists.side_effect = [True, True, True]
    self.assertFalse(shell.remove_directory('dir'))
    self.mock.log_error.assert_has_calls(
        [mock.call('Failed to clear directory dir.')])
    self.assertEqual(0, self.mock.log_warn.call_count)
    self.mock.system.assert_has_calls(
        [mock.call('rm -rf "dir" > /dev/null 2>&1')])
    self.mock.rmtree.assert_has_calls([mock.call('dir', onerror=mock.ANY)])

  def test_remove_shutil_failure_ignore_errors(self):
    self.mock.exists.side_effect = [True, True, True]
    self.assertFalse(shell.remove_directory('dir', ignore_errors=True))
    self.mock.log_warn.assert_has_calls(
        [mock.call('Failed to clear directory dir.')])
    self.assertEqual(0, self.mock.log_error.call_count)
    self.mock.system.assert_has_calls(
        [mock.call('rm -rf "dir" > /dev/null 2>&1')])
    self.mock.rmtree.assert_has_calls([mock.call('dir', onerror=mock.ANY)])

  def test_remove_shutil_onerror(self):
    """Test shutil invoking onerror."""
    self.mock.exists.side_effect = [True, True, False]
    self.assertTrue(shell.remove_directory('dir'))
    self.mock.system.assert_has_calls(
        [mock.call('rm -rf "dir" > /dev/null 2>&1')])
    self.mock.rmtree.assert_has_calls([mock.call('dir', onerror=mock.ANY)])

    onerror = self.mock.rmtree.call_args[1]['onerror']
    fake_fn = mock.MagicMock()
    fake_fn.side_effect = OSError()

    onerror(fake_fn, 'dir/child', ImportError())

    self.mock.chmod.assert_has_calls([mock.call('dir/child', 0o750)])
    fake_fn.assert_has_calls([mock.call('dir/child')])


class GetDirectoryFileCount(fake_filesystem_unittest.TestCase):
  """Tests for get_directory_file_count."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)

  def test(self):
    """Test get_directory_file_count."""
    self.fs.create_file('/test/aa/bb.txt', contents='abc')
    self.fs.create_file('/test/aa/cc.txt', contents='def')
    self.fs.create_file('/test/aa/aa/aa.txt', contents='ghi')
    self.fs.create_file('/test/aa/aa/dd.txt', contents='t')

    self.assertEqual(shell.get_directory_file_count('/test/aa'), 4)


class GetDirectorySizeTest(fake_filesystem_unittest.TestCase):
  """Tests for get_directory_size."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)

  def test(self):
    """Test get_directory_size."""
    self.fs.create_file('/test/aa/bb.txt', contents='abc')
    self.fs.create_file('/test/aa/cc.txt', contents='def')
    self.fs.create_file('/test/aa/aa/aa.txt', contents='ghi')
    self.fs.create_file('/test/aa/aa/dd.txt', contents='t')

    self.assertEqual(shell.get_directory_size('/test/aa'), 10)


class WhichTest(fake_filesystem_unittest.TestCase):
  """Tests for which (shutil.which)."""

  def setUp(self):
    # FIXME: Add support for Windows.
    if not environment.is_posix():
      self.skipTest('Which test is only supported on posix platforms.')

  def test(self):
    self.assertTrue(shell.which('ls') in ['/bin/ls', '/usr/bin/ls'])


class ClearSystemTempDirectoryTest(fake_filesystem_unittest.TestCase):
  """Tests for clear_system_temp_directory."""

  def setUp(self):
    test_helpers.patch(self, [
        'tempfile.gettempdir',
    ])
    self.mock.gettempdir.return_value = '/tmp'

    test_utils.set_up_pyfakefs(self)

  def test(self):
    """Test clear_system_temp_directory works as expected."""
    self.fs.create_file('/tmp/aa/bb.txt', contents='abc')
    self.fs.create_file('/tmp/cc/dd/ee.txt', contents='def')
    self.fs.create_dir('/tmp/ff/gg')
    self.fs.create_dir('/tmp/hh')
    self.fs.create_dir('/unrelated')
    self.fs.create_file('/unrelated/zz.txt', contents='zzz')
    os.symlink('/unrelated/zz.txt', '/tmp/hh/gg.txt')
    os.symlink('/unrelated', '/tmp/ii')

    shell.clear_system_temp_directory()

    self.assertTrue(os.path.exists('/tmp'))
    self.assertTrue(os.path.exists('/unrelated'))
    self.assertEqual(shell.get_directory_file_count('/tmp'), 0)
    self.assertEqual(shell.get_directory_file_count('/unrelated'), 1)
    self.assertFalse(os.path.exists('/tmp/aa/bb.txt'))
    self.assertFalse(os.path.exists('/tmp/cc/dd/ee.txt'))
    self.assertFalse(os.path.exists('/tmp/ff/gg'))
    self.assertFalse(os.path.exists('/tmp/hh'))


class GetExecuteCommand(unittest.TestCase):
  """Test that the correct commands to run files are returned."""

  def call_and_assert_helper(self, expected_command, file_to_execute):
    """Call get_execute_command on |file_to_execute| and assert result equal to
    |expected_command|."""
    self.assertEqual(expected_command,
                     shell.get_execute_command(file_to_execute))

  def test_standard_script(self):
    """Test correct command returned for python script."""
    script_name = 'script.py'
    expected_command = sys.executable + ' ' + script_name
    self.call_and_assert_helper(expected_command, script_name)

  def test_java(self):
    """Test correct launch command returned for Java class."""
    script_name = 'javaclassfile.class'
    expected_command = 'java javaclassfile'
    self.call_and_assert_helper(expected_command, script_name)

  def test_binary(self):
    """Test correct launch command returned for a binary (executable) file."""
    executable_name = 'executable'
    self.call_and_assert_helper(executable_name, executable_name)

    executable_name += '.exe'
    self.call_and_assert_helper(executable_name, executable_name)


class GetInterpreter(object):
  """Test that the correct interpreters to execute a file are returned."""

  def get_interpreted_file_test(self):
    """Test correct interpreter is returned for a file that needs one."""
    self.assertEqual('python', shell.get_interpreter('run.py'))

  def get_non_interpreter_file_test(self):
    """Test that None is returned for a file that doesn't need one. We don't
    want empty string since this is easier to than None. """
    self.assertIsNone(shell.get_interpreter('executable'))
