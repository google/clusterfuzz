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
import mock
import os
import unittest

from pyfakefs import fake_filesystem_unittest

from system import environment
from system import shell
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class RemoveEmptyFilesTest(fake_filesystem_unittest.TestCase):
  """Tests for remove_empty_files."""

  def setUp(self):
    # FIXME: Add support for Windows.
    if not environment.is_posix():
      self.skipTest('Process tests are only applicable for posix platforms.')

    test_utils.set_up_pyfakefs(self)

  def test_remove(self):
    """Test remove."""
    self.fs.CreateFile('/test/aa/bb.txt', contents='s')
    self.fs.CreateFile('/test/aa/cc.txt', contents='')
    self.fs.CreateFile('/test/aa/aa/dd.txt', contents='s')
    self.fs.CreateFile('/test/aa/aa/aa.txt', contents='')

    shell.remove_empty_files('/test')

    self.assertTrue(os.path.exists('/test/aa/bb.txt'))
    self.assertTrue(os.path.exists('/test/aa/aa/dd.txt'))
    self.assertFalse(os.path.exists('/test/aa/cc.txt'))
    self.assertFalse(os.path.exists('/test/aa/aa/aa.txt'))

  def test_ignore_file(self):
    self.fs.CreateFile('/test/aa/cc.txt', contents='')
    shell.remove_empty_files('/test/aa/cc.txt')
    self.assertTrue(os.path.exists('/test/aa/cc.txt'))

  @mock.patch('os.remove', autospec=True)
  def test_exception(self, mock_remove):
    # bypass pyfakefs's os.remove.
    os.remove = mock_remove
    mock_remove.side_effect = OSError()

    self.fs.CreateFile('/test/aa/cc.txt', contents='')
    shell.remove_empty_files('/test')
    self.assertTrue(os.path.exists('/test/aa/cc.txt'))


class RemoveDirectoryTest(unittest.TestCase):
  """Tests for remove_directory."""

  def setUp(self):
    test_helpers.patch(self, [
        'os.chmod',
        'os.mkdir',
        'os.path.exists',
        'os.system',
        'system.environment.platform',
        'metrics.logs.log_error',
        'metrics.logs.log_warn',
        'shutil.rmtree',
    ])

  def _test_remove_os_specific(self, platform, recreate, raise_mkdir_error):
    """Helper for testing removing dir with os-specific command."""
    self.mock.platform.return_value = platform
    self.mock.exists.side_effect = [True, False, False]
    if raise_mkdir_error:
      self.mock.mkdir.side_effect = OSError()

    result = shell.remove_directory('dir', recreate=recreate)

    if recreate:
      self.assertEqual(not raise_mkdir_error, result)
    else:
      self.assertTrue(result)

    self.mock.rmtree.assert_has_calls([])
    if recreate:
      self.mock.mkdir.assert_has_calls([mock.call('dir')])
    else:
      self.mock.mkdir.assert_has_calls([])

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

  def test_remove_with_mkdir_error(self):
    """Test remove when mkdir errors."""
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
    self.fs.CreateFile('/test/aa/bb.txt', contents='abc')
    self.fs.CreateFile('/test/aa/cc.txt', contents='def')
    self.fs.CreateFile('/test/aa/aa/aa.txt', contents='ghi')
    self.fs.CreateFile('/test/aa/aa/dd.txt', contents='t')

    self.assertEqual(shell.get_directory_file_count('/test/aa'), 4)


class GetDirectorySizeTest(fake_filesystem_unittest.TestCase):
  """Tests for get_directory_size."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)

  def test(self):
    """Test get_directory_size."""
    self.fs.CreateFile('/test/aa/bb.txt', contents='abc')
    self.fs.CreateFile('/test/aa/cc.txt', contents='def')
    self.fs.CreateFile('/test/aa/aa/aa.txt', contents='ghi')
    self.fs.CreateFile('/test/aa/aa/dd.txt', contents='t')

    self.assertEqual(shell.get_directory_size('/test/aa'), 10)


class WhichTest(fake_filesystem_unittest.TestCase):
  """Tests for which (shutil.which)."""

  def setUp(self):
    # FIXME: Add support for Windows.
    if not environment.is_posix():
      self.skipTest('Which test is only supported on posix platforms.')

  def test(self):
    self.assertEqual('/bin/ls', shell.which('ls'))


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
    self.fs.CreateFile('/tmp/aa/bb.txt', contents='abc')
    self.fs.CreateFile('/tmp/cc/dd/ee.txt', contents='def')
    self.fs.CreateDirectory('/tmp/ff/gg')
    self.fs.CreateDirectory('/tmp/hh')
    self.fs.CreateDirectory('/unrelated')
    self.fs.CreateFile('/unrelated/zz.txt', contents='zzz')
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
