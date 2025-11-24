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
"""Tests for the lint command.

  For running all the tests, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -p test_lint.py -v
"""

from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from casp.commands import lint as lint_command
from click.testing import CliRunner


class LintCliTest(unittest.TestCase):
  """Tests for the lint command."""

  def setUp(self):
    self.runner = CliRunner()
    self.mock_local_butler = self.enterContext(
        patch('casp.commands.lint.local_butler', autospec=True))
    self.mock_subprocess_run = self.enterContext(
        patch('subprocess.run', autospec=True))

  def test_lint_success_no_args(self):
    """Tests successful execution of `casp lint` without arguments."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    result = self.runner.invoke(lint_command.cli)
    self.assertEqual(0, result.exit_code, msg=result.output)
    self.mock_local_butler.build_command.assert_called_once_with('lint')
    self.mock_subprocess_run.assert_called_once_with(['cmd'], check=True)

  def test_lint_success_with_path_arg(self):
    """Tests `casp lint <some_dir>` (positional argument)."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    with self.runner.isolated_filesystem():
      Path('test_dir').mkdir()
      result = self.runner.invoke(lint_command.cli, ['test_dir'])
      self.assertEqual(0, result.exit_code, msg=result.output)
      self.mock_local_butler.build_command.assert_called_once_with(
          'lint', path='test_dir')
      self.mock_subprocess_run.assert_called_once_with(['cmd'], check=True)

  def test_lint_success_with_path_option(self):
    """Tests `casp lint --path <some_dir>`."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    with self.runner.isolated_filesystem():
      Path('test_dir').mkdir()
      result = self.runner.invoke(lint_command.cli, ['--path', 'test_dir'])
      self.assertEqual(0, result.exit_code, msg=result.output)
      self.mock_local_butler.build_command.assert_called_once_with(
          'lint', path='test_dir')
      self.mock_subprocess_run.assert_called_once_with(['cmd'], check=True)

  def test_lint_success_with_type_check(self):
    """Tests `casp lint --type-check`."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    result = self.runner.invoke(lint_command.cli, ['--type-check'])
    self.assertEqual(0, result.exit_code, msg=result.output)
    self.mock_local_butler.build_command.assert_called_once_with(
        'lint', type_check=None)
    self.mock_subprocess_run.assert_called_once_with(['cmd'], check=True)

  def test_lint_success_with_path_and_type_check(self):
    """Tests `casp lint <some_dir> --type-check`."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    with self.runner.isolated_filesystem():
      Path('test_dir').mkdir()
      result = self.runner.invoke(lint_command.cli,
                                  ['test_dir', '--type-check'])
      self.assertEqual(0, result.exit_code, msg=result.output)
      self.mock_local_butler.build_command.assert_called_once_with(
          'lint', path='test_dir', type_check=None)
      self.mock_subprocess_run.assert_called_once_with(['cmd'], check=True)

  def test_butler_not_found(self):
    """Tests when `butler.py` is not found."""
    self.mock_local_butler.build_command.side_effect = FileNotFoundError
    result = self.runner.invoke(lint_command.cli)
    self.assertNotEqual(0, result.exit_code)
    self.assertIn('butler.py not found', result.output)
    self.mock_subprocess_run.assert_not_called()

  def test_subprocess_run_fails(self):
    """Tests when `subprocess.run` fails."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    self.mock_subprocess_run.side_effect = subprocess.CalledProcessError(
        1, 'cmd')
    result = self.runner.invoke(lint_command.cli)
    self.assertNotEqual(0, result.exit_code)
    self.assertIn('Error running butler.py lint', result.output)

  def test_python_not_found(self):
    """Tests when `python` command is not found."""
    self.mock_local_butler.build_command.return_value = ['cmd']
    self.mock_subprocess_run.side_effect = FileNotFoundError
    result = self.runner.invoke(lint_command.cli)
    self.assertNotEqual(0, result.exit_code)
    self.assertIn('python not found in PATH', result.output)


if __name__ == '__main__':
  unittest.main()
