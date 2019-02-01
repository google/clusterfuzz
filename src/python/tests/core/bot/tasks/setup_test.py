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
"""Tests for setup."""

import unittest

from bot.tasks import setup
from system import environment


class IsDirectoryOnNfsTest(unittest.TestCase):
  """Tests for the is_directory_on_nfs function."""

  def setUp(self):
    environment.set_value('NFS_ROOT', '/nfs')

  def tearDown(self):
    environment.remove_key('NFS_ROOT')

  def test_is_directory_on_nfs_without_nfs(self):
    """Test is_directory_on_nfs without nfs."""
    environment.remove_key('NFS_ROOT')
    self.assertFalse(setup.is_directory_on_nfs('/nfs/dir1'))

  def test_is_directory_on_nfs_with_nfs_and_data_bundle_on_nfs(self):
    """Test is_directory_on_nfs with nfs and data bundle on nfs."""
    self.assertTrue(setup.is_directory_on_nfs('/nfs/dir1'))

  def test_is_directory_on_nfs_with_nfs_and_data_bundle_on_local(self):
    """Test is_directory_on_nfs with nfs and data bundle on local."""
    self.assertFalse(setup.is_directory_on_nfs('/tmp/dir1'))
