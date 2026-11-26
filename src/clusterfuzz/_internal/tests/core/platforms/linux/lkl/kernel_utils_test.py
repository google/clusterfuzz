# Copyright 2026 Google LLC
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
"""Tests for LKL kernel_utils."""

# pylint: disable=protected-access

import os
import tempfile
import unittest

from clusterfuzz._internal.platforms.linux.lkl import kernel_utils
from clusterfuzz._internal.tests.test_libs import helpers


class GetLklRepoPropDataTest(unittest.TestCase):
  """Tests for LKL _get_repo_prop_data."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
    ])

  def test_returns_existing_local_repo_prop_in_local_development(self):
    """Returns local repo.prop contents even when LOCAL_DEVELOPMENT is enabled."""
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    with tempfile.TemporaryDirectory() as symbols_dir:
      os.environ['SYMBOLS_DIR'] = symbols_dir
      target_dir = os.path.join(symbols_dir, 'kernel_lkl')
      os.makedirs(target_dir)
      expected_path = os.path.join(target_dir, 'kernel_lkl-99999-repo.prop')
      with open(expected_path, 'w') as repo_file:
        repo_file.write('kernel/private/lkl u\'abc123\'\n')

      result = kernel_utils._get_repo_prop_data('99999', 'kernel_lkl')

      self.assertEqual(result, 'kernel/private/lkl u\'abc123\'\n')
      self.mock.get.assert_not_called()

  def test_downloads_repo_prop_when_missing_locally(self):
    """Downloads repo.prop and returns its decoded contents when absent locally."""
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    with tempfile.TemporaryDirectory() as symbols_dir:
      os.environ['SYMBOLS_DIR'] = symbols_dir

      def fake_fetch(build_id, target, artifact_name, output_dir,
                     output_filename):
        del build_id, target, artifact_name
        output_path = os.path.join(output_dir, output_filename)
        with open(output_path, 'w') as repo_file:
          repo_file.write('kernel/private/lkl u\'abc123\'\n')
        return [output_path]

      self.mock.get.side_effect = fake_fetch

      result = kernel_utils._get_repo_prop_data('99999', 'kernel_lkl')

      self.assertEqual(result, 'kernel/private/lkl u\'abc123\'\n')
      expected_path = os.path.join(symbols_dir, 'kernel_lkl',
                                   'kernel_lkl-99999-repo.prop')
      self.assertTrue(os.path.isfile(expected_path))

  def test_returns_none_in_local_development_when_missing_locally(self):
    """Returns None without fetching in LOCAL_DEVELOPMENT when absent."""
    os.environ['LOCAL_DEVELOPMENT'] = 'True'
    with tempfile.TemporaryDirectory() as symbols_dir:
      os.environ['SYMBOLS_DIR'] = symbols_dir

      result = kernel_utils._get_repo_prop_data('99999', 'kernel_lkl')

      self.assertIsNone(result)
      self.mock.get.assert_not_called()

  def test_returns_none_when_download_fails(self):
    """Returns None when downloading repo.prop fails."""
    os.environ.pop('LOCAL_DEVELOPMENT', None)
    self.mock.get.return_value = []
    with tempfile.TemporaryDirectory() as symbols_dir:
      os.environ['SYMBOLS_DIR'] = symbols_dir

      result = kernel_utils._get_repo_prop_data('99999', 'kernel_lkl')

      self.assertIsNone(result)
