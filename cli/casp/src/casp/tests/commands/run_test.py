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
"""Tests for the run command.

  For running all the tests, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -p run_test.py -v
"""

from pathlib import Path
import subprocess
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from casp.commands import run as run_command
from click.testing import CliRunner


class RunLocalCliTest(unittest.TestCase):
  """Tests for the local run command."""

  def setUp(self):
    self.runner = CliRunner()
    self.mock_local_butler = self.enterContext(
        patch('casp.commands.run.local_butler', autospec=True))
    self.mock_subprocess_run = self.enterContext(
        patch('subprocess.run', autospec=True))

  def test_run_local_success_basic(self):
    """Tests successful execution of `casp run local` with minimal args."""
    # mock build_command to return a list that we can inspect
    self.mock_local_butler.build_command.return_value = ['cmd', '--config-dir=test_config']
    
    with self.runner.isolated_filesystem():
      Path('test_config').mkdir()
      result = self.runner.invoke(
          run_command.cli, ['local', 'test_script', '--config-dir', 'test_config'])
      self.assertEqual(0, result.exit_code, msg=result.output)
      
      self.mock_local_butler.build_command.assert_called_once_with(
          'run', config_dir='test_config')
      
      expected_cmd = ['cmd', '--config-dir=test_config', 'test_script']
      self.mock_subprocess_run.assert_called_once_with(expected_cmd, check=True)

  def test_run_local_success_all_options(self):
    """Tests `casp run local` with all options."""
    # mock build_command behavior for flags
    self.mock_local_butler.build_command.return_value = [
        'cmd',
        '--non-dry-run',
        '--local',
        '--config-dir=test_config'
    ]
    
    with self.runner.isolated_filesystem():
      Path('test_config').mkdir()
      result = self.runner.invoke(run_command.cli, [
          'local',
          'test_script',
          '--config-dir', 'test_config',
          '--non-dry-run',
          '--local',
          '--script_args', 'arg1',
          '--script_args', 'arg2'
      ])
      self.assertEqual(0, result.exit_code, msg=result.output)
      
      self.mock_local_butler.build_command.assert_called_once_with(
          'run',
          non_dry_run=None,
          local=None,
          config_dir='test_config'
      )
      
      expected_cmd = [
          'cmd',
          '--non-dry-run',
          '--local',
          '--config-dir=test_config',
          'test_script',
          '--script_args=arg1',
          '--script_args=arg2'
      ]
      self.mock_subprocess_run.assert_called_once_with(expected_cmd, check=True)


class RunContainerCliTest(unittest.TestCase):
  """Tests for the container run command."""

  def setUp(self):
    self.runner = CliRunner()
    self.mock_config = self.enterContext(
        patch('casp.commands.run.config', autospec=True))
    self.mock_container = self.enterContext(
        patch('casp.commands.run.container', autospec=True))
    self.mock_docker_utils = self.enterContext(
        patch('casp.commands.run.docker_utils', autospec=True))
    
    # Mock config
    self.mock_config.load_and_validate_config.return_value = {}
    
    # Mock docker utils
    self.mock_docker_utils.PROJECT_TO_IMAGE = {'dev': 'test-image'}
    self.mock_docker_utils.prepare_docker_volumes.return_value = (
        {'vol': 'bind'}, Path('/container/config'))
    self.mock_docker_utils.run_command.return_value = True

    # Mock container
    self.mock_container.CONTAINER_CONFIG_PATH = Path('/data/config')
    self.mock_container.build_butler_command.return_value = ['bash', '-c', 'cmd']

  def test_run_container_success(self):
    """Tests successful execution of `casp run container`."""
    result = self.runner.invoke(run_command.cli, [
        'container',
        'test_script',
        '--project', 'dev',
        '--non-dry-run',
        '--local',
        '--script_args', 'arg1',
        '--script_args', 'arg2'
    ])
    self.assertEqual(0, result.exit_code, msg=result.output)

    self.mock_docker_utils.prepare_docker_volumes.assert_called_once()
    
    # Expect None for flags (non_dry_run, local)
    self.mock_container.build_butler_command.assert_called_once_with(
        'run test_script --script_args=arg1 --script_args=arg2',
        non_dry_run=None,
        config_dir='/container/config',
        local=None
    )
    self.mock_docker_utils.run_command.assert_called_once_with(
        ['bash', '-c', 'cmd'],
        {'vol': 'bind'},
        privileged=True,
        image='test-image'
    )

  def test_run_container_fail(self):
    """Tests `casp run container` when docker run fails."""
    self.mock_docker_utils.run_command.return_value = False
    result = self.runner.invoke(run_command.cli, [
        'container',
        'test_script',
        '--project', 'dev'
    ])
    self.assertNotEqual(0, result.exit_code)

if __name__ == '__main__':
  unittest.main()
