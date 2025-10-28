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
from unittest.mock import Mock
from unittest.mock import patch

from casp.utils import gcloud


class IsValidCredentialsTest(unittest.TestCase):
  """Tests for _is_valid_credentials."""

  @patch('os.path.exists', return_value=True, autospec=True)
  @patch(
      'google.oauth2.credentials.Credentials.from_authorized_user_file',
      autospec=True)
  def test_valid_credentials(self, mock_from_file, mock_exists):
    """Tests with a valid credentials file."""
    mock_from_file.return_value = Mock()
    self.assertTrue(gcloud._is_valid_credentials('valid/path'))  # pylint: disable=protected-access
    mock_exists.assert_called_once_with('valid/path')
    mock_from_file.assert_called_once_with('valid/path')

  @patch('os.path.exists', return_value=False, autospec=True)
  def test_path_does_not_exist(self, mock_exists):
    """Tests with a non-existent path."""
    self.assertFalse(gcloud._is_valid_credentials('invalid/path'))  # pylint: disable=protected-access
    mock_exists.assert_called_once_with('invalid/path')

  @patch('os.path.exists', return_value=True, autospec=True)
  @patch(
      'google.oauth2.credentials.Credentials.from_authorized_user_file',
      autospec=True)
  def test_auth_error(self, mock_from_file, mock_exists):
    """Tests with an auth exception."""
    mock_from_file.side_effect = ValueError
    self.assertFalse(gcloud._is_valid_credentials('path'))  # pylint: disable=protected-access
    mock_exists.assert_called_once_with('path')
    mock_from_file.assert_called_once_with('path')

  def test_empty_path(self):
    """Tests with an empty path string."""
    self.assertFalse(gcloud._is_valid_credentials(''))  # pylint: disable=protected-access

  def test_none_path(self):
    """Tests with a None path."""
    self.assertFalse(gcloud._is_valid_credentials(None))  # pylint: disable=protected-access


class RunGcloudLoginTest(unittest.TestCase):
  """Tests for _run_gcloud_login."""

  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=True,
      autospec=True)
  @patch('subprocess.run', autospec=True)
  def test_login_success(self, mock_run, mock_is_valid):
    """Tests successful gcloud login."""
    self.assertTrue(gcloud._run_gcloud_login())  # pylint: disable=protected-access
    mock_run.assert_called_once_with(
        ['gcloud', 'auth', 'application-default', 'login'], check=True)
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)

  @patch('subprocess.run', autospec=True)
  @patch('click.secho', autospec=True)
  def test_gcloud_not_found(self, mock_secho, mock_run):
    """Tests with gcloud command not found."""
    mock_run.side_effect = FileNotFoundError
    self.assertFalse(gcloud._run_gcloud_login())  # pylint: disable=protected-access
    mock_secho.assert_called_once()
    args, _ = mock_secho.call_args
    self.assertIn('gcloud command not found', args[0])

  @patch('subprocess.run', autospec=True)
  @patch('click.secho', autospec=True)
  def test_login_failed(self, mock_secho, mock_run):
    """Tests with a failed login command."""
    mock_run.side_effect = subprocess.CalledProcessError(1, 'cmd')
    self.assertFalse(gcloud._run_gcloud_login())  # pylint: disable=protected-access
    mock_secho.assert_called_once_with('Error: gcloud login failed.', fg='red')


class PromptForCustomPathTest(unittest.TestCase):
  """Tests for _prompt_for_custom_path."""

  @patch('click.prompt', autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=True,
      autospec=True)
  def test_valid_path(self, mock_is_valid, mock_prompt):
    """Tests with a valid custom path."""
    mock_prompt.return_value = '/valid/path'
    self.assertEqual(gcloud._prompt_for_custom_path(), '/valid/path')  # pylint: disable=protected-access
    mock_is_valid.assert_called_once_with('/valid/path')

  @patch('click.prompt', autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=False,
      autospec=True)
  @patch('click.secho', autospec=True)
  def test_invalid_path(self, mock_secho, mock_is_valid, mock_prompt):
    """Tests with an invalid custom path."""
    mock_prompt.return_value = '/invalid/path'
    self.assertIsNone(gcloud._prompt_for_custom_path())  # pylint: disable=protected-access
    mock_is_valid.assert_called_once_with('/invalid/path')
    mock_secho.assert_called_once_with(
        'Error: The provided credentials file is not valid.', fg='red')

  @patch('click.prompt', autospec=True)
  def test_empty_path(self, mock_prompt):
    """Tests with empty input from prompt."""
    mock_prompt.return_value = ''
    self.assertIsNone(gcloud._prompt_for_custom_path())  # pylint: disable=protected-access


class GetCredentialsPathTest(unittest.TestCase):
  """Tests for get_credentials_path."""

  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=True,
      autospec=True)
  def test_default_path_valid(self, mock_is_valid):
    """Tests when the default credentials path is valid."""
    self.assertEqual(gcloud.get_credentials_path(),
                     gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)

  @patch('casp.utils.gcloud._prompt_for_custom_path', autospec=True)
  @patch(
      'casp.utils.gcloud._run_gcloud_login', return_value=True, autospec=True)
  @patch('click.confirm', return_value=True, autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=False,
      autospec=True)
  def test_login_success(self, mock_is_valid, mock_confirm, mock_login,
                         mock_prompt):
    """Tests successful login after default path fails."""
    self.assertEqual(gcloud.get_credentials_path(),
                     gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_confirm.assert_called_once()
    mock_login.assert_called_once()
    mock_prompt.assert_not_called()

  @patch(
      'casp.utils.gcloud._prompt_for_custom_path',
      return_value='/custom/path',
      autospec=True)
  @patch(
      'casp.utils.gcloud._run_gcloud_login', return_value=False, autospec=True)
  @patch('click.confirm', return_value=True, autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=False,
      autospec=True)
  def test_login_fail_then_custom_path(self, mock_is_valid, mock_confirm,
                                       mock_login, mock_prompt):
    """Tests providing a custom path after a failed login."""
    self.assertEqual(gcloud.get_credentials_path(), '/custom/path')
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_confirm.assert_called_once()
    mock_login.assert_called_once()
    mock_prompt.assert_called_once()

  @patch(
      'casp.utils.gcloud._prompt_for_custom_path',
      return_value='/custom/path',
      autospec=True)
  @patch('casp.utils.gcloud._run_gcloud_login', autospec=True)
  @patch('click.confirm', return_value=False, autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=False,
      autospec=True)
  def test_decline_login_then_custom_path(self, mock_is_valid, mock_confirm,
                                          mock_login, mock_prompt):
    """Tests providing a custom path after declining to log in."""
    self.assertEqual(gcloud.get_credentials_path(), '/custom/path')
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_confirm.assert_called_once()
    mock_login.assert_not_called()
    mock_prompt.assert_called_once()

  @patch(
      'casp.utils.gcloud._prompt_for_custom_path',
      return_value=None,
      autospec=True)
  @patch('click.confirm', return_value=False, autospec=True)
  @patch(
      'casp.utils.gcloud._is_valid_credentials',
      return_value=False,
      autospec=True)
  def test_all_fail(self, mock_is_valid, mock_confirm, mock_prompt):
    """Tests when all methods to get credentials fail."""
    self.assertIsNone(gcloud.get_credentials_path())
    mock_is_valid.assert_called_once_with(
        gcloud.DEFAULT_GCLOUD_CREDENTIALS_PATH)
    mock_confirm.assert_called_once()
    mock_prompt.assert_called_once()


if __name__ == '__main__':
  unittest.main()
