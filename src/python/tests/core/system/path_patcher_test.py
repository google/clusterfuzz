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
"""path_patcher tests."""
import __builtin__
import ctypes
import mock
import os
import tempfile
import unittest

from system import path_patcher
from tests.test_libs import helpers


class MockedBuffer(object):
  """mock buffer."""

  def __init__(self, value):
    self.value = value


class MetadataTest(unittest.TestCase):
  """Metadata test."""

  def setUp(self):
    helpers.patch(self, [
        'system.path_patcher._is_windows',
        'system.path_patcher._short_name_modifier'
    ])
    self.mock._is_windows.return_value = True  # pylint: disable=protected-access
    self.mock._short_name_modifier.side_effect = lambda v: v + '_mod'  # pylint: disable=protected-access
    self.original_file = file
    path_patcher.patch()

  def tearDown(self):
    path_patcher.unpatch()

  def test_name(self):
    """Test __name__s are the same."""
    self.assertEqual('listdir', os.listdir.__name__)
    self.assertEqual('makedirs', os.makedirs.__name__)
    self.assertEqual('mkdir', os.mkdir.__name__)
    self.assertEqual('stat', os.stat.__name__)
    self.assertEqual('exists', os.path.exists.__name__)
    self.assertEqual('isfile', os.path.isfile.__name__)
    self.assertEqual('isdir', os.path.isdir.__name__)
    self.assertEqual('open', open.__name__)
    self.assertEqual('file', file.__name__)

    self.assertTrue(os.listdir.__path_patcher__)
    self.assertTrue(os.makedirs.__path_patcher__)
    self.assertTrue(os.mkdir.__path_patcher__)
    self.assertTrue(os.stat.__path_patcher__)
    self.assertTrue(os.path.exists.__path_patcher__)
    self.assertTrue(os.path.isfile.__path_patcher__)
    self.assertTrue(os.path.isdir.__path_patcher__)
    self.assertTrue(open.__path_patcher__)
    self.assertTrue(file.__path_patcher__)

  def test_open(self):
    """Test the returned value of open(..)."""
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
      with open(tmp.name, 'wb') as file_handle:
        self.assertEqual(type(file_handle).__name__, 'file')
        self.assertListEqual(
            dir(file_handle.__class__), dir(self.original_file(tmp.name, 'wb')))

        # The filename is the new name.
        self.assertEqual('%s_mod' % tmp.name, file_handle.name)

        # FIXME(unassigned): The below expectation is NOT what we want. But we
        # can't find a way to fix it. This can create an error in the logic
        # if we check for the type of the object directly.
        # Please use this approach to check for a file-like object:
        # http://stackoverflow.com/a/1661354
        self.assertNotIsInstance(file_handle, file)
        self.assertNotEqual(file, type(file_handle))


class PatcherTest(object):
  """Patcher tests."""

  def setUp(self):
    """Set up."""
    if not hasattr(ctypes, 'windll'):
      ctypes.windll = mock.Mock()

    if not hasattr(ctypes, 'wintypes'):
      ctypes.wintypes = mock.Mock()

    if not hasattr(ctypes.windll, 'kernel32'):
      ctypes.windll.kernel32 = mock.Mock()

    if not hasattr(ctypes.windll.kernel32, 'GetShortPathNameW'):
      ctypes.windll.kernel32.GetShortPathNameW = mock.Mock()

    helpers.patch(self, [
        'system.path_patcher._is_windows',
        'ctypes.windll.kernel32.GetShortPathNameW',
        'ctypes.create_unicode_buffer'
    ])
    self.path = r'c:\test/test2/test3'
    self.prepared_path = r'\\?\c:\test\test2\test3'
    self.short_path = r'\\?\c:\shortpath'
    self.mock.create_unicode_buffer.return_value = (
        MockedBuffer(self.short_path))

    self.path_lengths = []

    def _GetShortPathNameW(path, *unused_args, **unused_kwargs):
      if self.prepared_path == path and self.path_lengths:
        return self.path_lengths.pop(0)

      return 0

    self.mock.GetShortPathNameW.side_effect = _GetShortPathNameW

  def tearDown(self):
    path_patcher.unpatch()

  def call(self, path):
    """Main call to the tested method. We need it because different method has
      different signatures (but they all take path as their first
      arguments)."""
    raise NotImplementedError()

  def expected_call(self, path):
    """Expected call on the wrapped method."""
    raise NotImplementedError()

  def test_modify(self):
    """Test modifying."""
    self.path_lengths = [10, 9]
    self.mock._is_windows.return_value = True  # pylint: disable=protected-access

    path_patcher.patch()
    self.call(self.path)

    self.mock.GetShortPathNameW.assert_has_calls([
        mock.call(self.prepared_path, None, 0),
        mock.call(self.prepared_path, mock.ANY, 10)
    ])
    self.underlying_mock.assert_has_calls([self.expected_call(self.short_path)])

  def test_no_short_path(self):
    """Test modifying."""
    self.mock._is_windows.return_value = True  # pylint: disable=protected-access

    path_patcher.patch()
    self.call(self.path)

    self.mock.GetShortPathNameW.assert_has_calls(
        [mock.call(self.prepared_path, None, 0)])
    self.underlying_mock.assert_has_calls(
        [self.expected_call(self.prepared_path)])

  def test_fail(self):
    """Test failing."""
    self.path_lengths = [10, 12]
    self.mock._is_windows.return_value = True  # pylint: disable=protected-access

    path_patcher.patch()
    with self.assertRaises(Exception):
      self.call(self.path)

    self.mock.GetShortPathNameW.assert_has_calls([
        mock.call(self.prepared_path, None, 0),
        mock.call(self.prepared_path, mock.ANY, 10)
    ])
    self.underlying_mock.assert_has_calls([])

  def test_other_platform(self):
    """Test not modifying when it's on other platform."""
    self.mock._is_windows.return_value = False  # pylint: disable=protected-access

    path_patcher.patch()
    self.call(self.path)

    self.underlying_mock.assert_has_calls([self.expected_call(self.path)])


class ListdirTest(PatcherTest, unittest.TestCase):
  """Listdir test."""

  def setUp(self):
    helpers.patch(self, ['os.listdir'])
    super(ListdirTest, self).setUp()

    self.underlying_mock = self.mock.listdir

  def call(self, path):
    os.listdir(path)

  def expected_call(self, path):
    return mock.call(path)


class StatTest(PatcherTest, unittest.TestCase):
  """Stat test."""

  def setUp(self):
    helpers.patch(self, ['os.stat'])
    super(StatTest, self).setUp()

    self.underlying_mock = self.mock.stat

  def call(self, path):
    os.stat(path)

  def expected_call(self, path):
    return mock.call(path)


class MakedirsTest(PatcherTest, unittest.TestCase):
  """Makedirs test."""

  def setUp(self):
    helpers.patch(self, ['os.makedirs'])
    super(MakedirsTest, self).setUp()

    self.underlying_mock = self.mock.makedirs

  def call(self, path):
    os.makedirs(path)

  def expected_call(self, path):
    return mock.call(path)


class FileTest(PatcherTest, unittest.TestCase):
  """File test."""

  def setUp(self):
    self.underlying_mock = mock.MagicMock()

    class MockFile(file):

      # pylint: disable=no-self-argument,super-init-not-called
      def __init__(_, name, *args, **kwargs):
        self.underlying_mock(name, *args, **kwargs)

    # We extends `file`. Therefore, we cannot use mock.patch(..).
    self.original_file = file
    __builtin__.file = MockFile
    super(FileTest, self).setUp()

  def tearDown(self):
    super(FileTest, self).tearDown()
    __builtin__.file = self.original_file

  def call(self, path):
    file(path, 'wb')

  def expected_call(self, path):
    return mock.call(path, 'wb')


class OpenTest(PatcherTest, unittest.TestCase):
  """Open test."""

  def setUp(self):
    helpers.patch(self, ['__builtin__.open'])
    super(OpenTest, self).setUp()

    self.underlying_mock = self.mock.open

  def call(self, path):
    open(path, 'wb')

  def expected_call(self, path):
    return mock.call(path, 'wb')


class OsPathExistsTest(PatcherTest, unittest.TestCase):
  """os.path.exists test."""

  def setUp(self):
    helpers.patch(self, ['os.path.exists'])
    super(OsPathExistsTest, self).setUp()

    self.underlying_mock = self.mock.exists

  def call(self, path):
    os.path.exists(path)

  def expected_call(self, path):
    return mock.call(path)


class OsPathIsfileTest(PatcherTest, unittest.TestCase):
  """os.path.isfile test."""

  def setUp(self):
    helpers.patch(self, ['os.path.isfile'])
    super(OsPathIsfileTest, self).setUp()

    self.underlying_mock = self.mock.isfile

  def call(self, path):
    os.path.isfile(path)

  def expected_call(self, path):
    return mock.call(path)


class OsPathIsdirTest(PatcherTest, unittest.TestCase):
  """os.path.isdir test."""

  def setUp(self):
    helpers.patch(self, ['os.path.isdir'])
    super(OsPathIsdirTest, self).setUp()

    self.underlying_mock = self.mock.isdir

  def call(self, path):
    os.path.isdir(path)

  def expected_call(self, path):
    return mock.call(path)


class OsMkdirTest(PatcherTest, unittest.TestCase):
  """mkdir test."""

  def setUp(self):
    helpers.patch(self, ['os.mkdir'])
    super(OsMkdirTest, self).setUp()

    self.underlying_mock = self.mock.mkdir

  def call(self, path):
    os.mkdir(path)

  def expected_call(self, path):
    return mock.call(path)
