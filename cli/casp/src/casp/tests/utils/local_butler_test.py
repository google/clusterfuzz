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
"""Tests for local_butler utility functions.

  For running, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests 
  -p local_butler_test.py -v
"""

from pathlib import Path
import unittest
from unittest.mock import patch

from casp.utils import local_butler


class BuildCommandTest(unittest.TestCase):
  """Tests for build_command."""

  @patch('casp.utils.path_utils.get_butler_in_dir', autospec=True)
  def test_build_command_success_auto_find(self, mock_get_butler):
    """Tests successful command build finding butler automatically."""
    mock_get_butler.return_value = Path('/fake/butler.py')

    command = local_butler.build_command('format', some_arg='value')

    self.assertEqual(
        command, ['python', '/fake/butler.py', 'format', '--some-arg=value'])
    mock_get_butler.assert_called_once()

  def test_build_command_success_explicit_path(self):
    """Tests successful command build with explicit butler path."""
    butler_path = Path('/explicit/butler.py')

    command = local_butler.build_command(
        'format', butler_path=butler_path, verbose='true')

    self.assertEqual(
        command, ['python', '/explicit/butler.py', 'format', '--verbose=true'])

  @patch('casp.utils.path_utils.get_butler_in_dir', autospec=True)
  def test_build_command_flags_and_args(self, mock_get_butler):
    """Tests handling of flags (None value) and args with underscores."""
    mock_get_butler.return_value = Path('/fake/butler.py')

    command = local_butler.build_command(
        'lint',
        path='some/path',
        type_check=None,
        another_flag=None,
        complex_arg='value')

    expected_command = [
        'python', '/fake/butler.py', 'lint', '--path=some/path', '--type-check',
        '--another-flag', '--complex-arg=value'
    ]
    self.assertEqual(command, expected_command)

  @patch('casp.utils.path_utils.get_butler_in_dir', autospec=True)
  def test_butler_not_found(self, mock_get_butler):
    """Tests validation when butler.py is not found."""
    mock_get_butler.return_value = None

    with self.assertRaises(FileNotFoundError):
      local_butler.build_command('format')


if __name__ == '__main__':
  unittest.main()
