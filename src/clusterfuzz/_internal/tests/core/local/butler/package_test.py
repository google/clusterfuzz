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
"""Package tests."""
import os
import tempfile
import unittest
import zipfile

from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler import package


class IsNodeUpToDateTest(unittest.TestCase):
  """is_nodejs_up_to_date tests."""

  def setUp(self):
    helpers.patch(self, ['local.butler.common.execute'])

  def test_succeed(self):
    """Test when succeed."""
    self.mock.execute.return_value = (0, b'v5.3.11')
    self.assertTrue(package._is_nodejs_up_to_date())  # pylint: disable=protected-access
    self.mock.execute.assert_called_once_with('node -v')

  def test_fail_return_code(self):
    """Test return code is non-zero."""
    self.mock.execute.return_value = (1, b'v5.3.11')
    self.assertFalse(package._is_nodejs_up_to_date())  # pylint: disable=protected-access
    self.mock.execute.assert_called_once_with('node -v')

  def test_fail_parse(self):
    """Test when output cannot be parse."""
    self.mock.execute.return_value = (0, b'sdafsadf')
    self.assertFalse(package._is_nodejs_up_to_date())  # pylint: disable=protected-access
    self.mock.execute.assert_called_once_with('node -v')

  def test_fail_version(self):
    """Test version is less than 4."""
    self.mock.execute.return_value = (0, b'v3.2.1')
    self.assertFalse(package._is_nodejs_up_to_date())  # pylint: disable=protected-access
    self.mock.execute.assert_called_once_with('node -v')


@test_utils.slow
@test_utils.integration
class PackageTest(unittest.TestCase):
  """Package tests."""

  def setUp(self):
    if os.getenv('PARALLEL_TESTS'):
      self.skipTest('Package testing is disabled when running in parallel.')

    self.temp_directory = tempfile.mkdtemp()
    self.zip_directory = os.path.join(self.temp_directory, 'packages')
    self.manifest_filename = os.path.join(self.temp_directory, 'test.manifest')

    helpers.patch(self, ['local.butler.common.is_git_dirty'])
    self.mock.is_git_dirty.return_value = False

  def tearDown(self):
    shell.remove_directory(self.temp_directory)

  def test_package(self):
    """Test package."""
    package.package(
        'revision',
        self.zip_directory,
        self.manifest_filename,
        platform_name='linux')

    zip_filename = os.path.join(self.zip_directory, 'linux.zip')
    with zipfile.ZipFile(zip_filename, 'r') as f:
      files = f.namelist()

      manifest_file = os.path.join('clusterfuzz', 'src', 'appengine',
                                   'resources', 'clusterfuzz-source.manifest')

      self.assertIn(manifest_file, files)

      self.assertEqual(b'revision\n', f.read(manifest_file))

      self.assertIn(
          os.path.join('clusterfuzz', 'src', 'third_party', 'googleapiclient',
                       '__init__.py'), files)
      self.assertIn(
          os.path.join('clusterfuzz', 'src', 'appengine', 'config', 'gae',
                       'auth.yaml'), files)
      self.assertNotIn(
          os.path.join('clusterfuzz', 'configs', 'test', 'gae', 'auth.yaml'),
          files)
      self.assertNotIn(
          os.path.join('clusterfuzz', 'local', '__init__.py'), files)
      self.assertNotIn(
          os.path.join('clusterfuzz', 'src', 'appengine', 'app.yaml'), files)
