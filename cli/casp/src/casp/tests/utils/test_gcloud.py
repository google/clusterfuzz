# Copyright 2025 Google LLC
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
"""Tests for the gcloud utility functions.
  For running all the tests, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -v 
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from google.auth import exceptions as auth_exceptions

from casp.utils import gcloud


class GcloudUtilsTest(unittest.TestCase):
  """Test gcloud utility functions."""

  @patch('os.path.exists')
  @patch('google.oauth2.credentials.Credentials.from_authorized_user_file')
  def test_is_valid_credentials_valid(self, mock_from_file, mock_exists):
    """Test _is_valid_credentials with a valid path."""
    mock_exists.return_value = True
    mock_from_file.return_value = MagicMock()
    self.assertTrue(gcloud._is_valid_credentials('valid/path'))

  @patch('os.path.exists')
  def test_is_valid_credentials_not_exists(self, mock_exists):
    """Test _is_valid_credentials with a non-existent path."""
    mock_exists.return_value = False
    self.assertFalse(gcloud._is_valid_credentials('invalid/path'))

  @patch('os.path.exists')
  @patch('google.oauth2.credentials.Credentials.from_authorized_user_file')
  def test_is_valid_credentials_auth_error(self, mock_from_file, mock_exists):
    """Test _is_valid_credentials with an auth exception."""
    mock_exists.return_value = True
    mock_from_file.side_effect = auth_exceptions.DefaultCredentialsError
    self.assertFalse(gcloud._is_valid_credentials('path'))

  @patch('os.path.exists')
  @patch('google.oauth2.credentials.Credentials.from_authorized_user_file')
  def test_is_valid_credentials_value_error(self, mock_from_file, mock_exists):
    """Test _is_valid_credentials with a ValueError."""
    mock_exists.return_value = True
    mock_from_file.side_effect = ValueError
    self.assertFalse(gcloud._is_valid_credentials('path'))

  @patch('os.path.exists')
  @patch('google.oauth2.credentials.Credentials.from_authorized_user_file')
  def test_is_valid_credentials_key_error(self, mock_from_file, mock_exists):
    """Test _is_valid_credentials with a KeyError."""
    mock_exists.return_value = True
    mock_from_file.side_effect = KeyError
    self.assertFalse(gcloud._is_valid_credentials('path'))

  @patch('casp.utils.gcloud._is_valid_credentials')
  @patch('subprocess.run')
  def test_run_gcloud_login_success(self, mock_run, mock_is_valid):
    """Test _run_gcloud_login successful."""
    mock_run.return_value = MagicMock()
    mock_is_valid.return_value = True
    self.assertTrue(gcloud._run_gcloud_login())
    mock_run.assert_called_with(
        ['gcloud', 'auth', 'application-default', 'login'], check=True)
    mock_is_valid.assert_called_with(gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)

  @patch('subprocess.run')
  def test_run_gcloud_login_file_not_found(self, mock_run):
    """Test _run_gcloud_login with gcloud not found."""
    mock_run.side_effect = FileNotFoundError
    self.assertFalse(gcloud._run_gcloud_login())

  @patch('subprocess.run')
  def test_run_gcloud_login_failed(self, mock_run):
    """Test _run_gcloud_login with a failed login command."""
    mock_run.side_effect = subprocess.CalledProcessError(1, 'cmd')
    self.assertFalse(gcloud._run_gcloud_login())

  @patch('click.prompt')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_prompt_for_custom_path_valid(self, mock_is_valid, mock_prompt):
    """Test _prompt_for_custom_path with a valid path."""
    mock_prompt.return_value = '/valid/path'
    mock_is_valid.return_value = True
    self.assertEqual(gcloud._prompt_for_custom_path(), '/valid/path')

  @patch('click.prompt')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_prompt_for_custom_path_invalid(self, mock_is_valid, mock_prompt):
    """Test _prompt_for_custom_path with an invalid path."""
    mock_prompt.return_value = '/invalid/path'
    mock_is_valid.return_value = False
    self.assertIsNone(gcloud._prompt_for_custom_path())

  @patch('click.prompt')
  def test_prompt_for_custom_path_empty(self, mock_prompt):
    """Test _prompt_for_custom_path with empty input."""
    mock_prompt.return_value = ''
    self.assertIsNone(gcloud._prompt_for_custom_path())

  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_get_credentials_path_default_valid(self, mock_is_valid):
    """Test get_credentials_path when default is valid."""
    mock_is_valid.return_value = True
    self.assertEqual(
        gcloud.get_credentials_path(), gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_is_valid.assert_called_with(gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)

  @patch('casp.utils.gcloud._prompt_for_custom_path')
  @patch('casp.utils.gcloud._run_gcloud_login')
  @patch('click.confirm')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_get_credentials_path_login_success(self, mock_is_valid,
                                              mock_confirm, mock_login,
                                              mock_prompt):
    """Test get_credentials_path with successful login."""
    mock_is_valid.return_value = False
    mock_confirm.return_value = True
    mock_login.return_value = True
    self.assertEqual(
        gcloud.get_credentials_path(), gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_prompt.assert_not_called()

  @patch('casp.utils.gcloud._prompt_for_custom_path')
  @patch('casp.utils.gcloud._run_gcloud_login')
  @patch('click.confirm')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_get_credentials_path_login_fail_then_custom(self, mock_is_valid,
                                                       mock_confirm,
                                                       mock_login,
                                                       mock_prompt):
    """Test get_credentials_path with failed login then custom path."""
    mock_is_valid.return_value = False
    mock_confirm.return_value = True
    mock_login.return_value = False
    mock_prompt.return_value = '/custom/path'
    self.assertEqual(gcloud.get_credentials_path(), '/custom/path')

  @patch('casp.utils.gcloud._prompt_for_custom_path')
  @patch('casp.utils.gcloud._run_gcloud_login')
  @patch('click.confirm')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_get_credentials_path_no_login_then_custom(self, mock_is_valid,
                                                     mock_confirm, mock_login,
                                                     mock_prompt):
    """Test get_credentials_path with no login then custom path."""
    mock_is_valid.return_value = False
    mock_confirm.return_value = False
    mock_prompt.return_value = '/custom/path'
    self.assertEqual(gcloud.get_credentials_path(), '/custom/path')
    mock_login.assert_not_called()

  @patch('casp.utils.gcloud._prompt_for_custom_path')
  @patch('click.confirm')
  @patch('casp.utils.gcloud._is_valid_credentials')
  def test_get_credentials_path_all_fail(self, mock_is_valid, mock_confirm,
                                         mock_prompt):
    """Test get_credentials_path when all methods fail."""
    mock_is_valid.return_value = False
    mock_confirm.return_value = False
    mock_prompt.return_value = None
    self.assertIsNone(gcloud.get_credentials_path())


if __name__ == '__main__':
  unittest.main()