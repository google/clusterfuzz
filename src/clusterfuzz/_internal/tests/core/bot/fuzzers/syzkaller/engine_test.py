# Copyright 2021 Google LLC
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
"""Tests for syzkaller runner."""
# pylint: disable=protected-access
# import mock
import os
from typing import Dict
import unittest
from unittest import mock

from clusterfuzz._internal.bot.fuzzers.syzkaller import runner
from clusterfuzz._internal.bot.fuzzers.syzkaller.constants import SYZ_CRUSH
from clusterfuzz._internal.bot.fuzzers.syzkaller.constants import SYZ_REPRO
from clusterfuzz._internal.bot.fuzzers.syzkaller.engine import \
    Engine as SyzkallerEngine
from clusterfuzz._internal.bot.fuzzers.syzkaller.engine import REPRO_TIME
from clusterfuzz._internal.system import environment
from clusterfuzz.fuzz.engine import ReproduceResult

sep = os.path.sep
TEST_PATH = sep.join(os.path.abspath(os.path.dirname(__file__)).split(sep)[:-1])
BIN_DIR = os.path.join(TEST_PATH, 'syzkaller', 'bin')
TESTCASE_PATH = os.path.join(TEST_PATH, 'test_crash.log')
TEST_CONFIG_ARGS = ['-config', 'test_json_path.json']
SYZ_CRUSH_COMMAND = ('./bin/syz-crush -infinite=false -restart_time=70s '
                     f'-config ./cuttlefish_config.json {TESTCASE_PATH}')
SYZ_REPRO_COMMAND = (
    f'./bin/syz-repro -config ./cuttlefish_config.json {TESTCASE_PATH}')
ENV = {
    'BUILD_DIR': TEST_PATH,
}


class EngineTest(unittest.TestCase):
  """Tests for AndroidSyzkallerRunner."""

  def setUp(self):
    super(EngineTest, self).setUp()
    self.target = SyzkallerEngine()
    self.mock_runner_instances = self.setup_mock_runner_instances()

  def setup_mock_runner_instances(self) -> Dict[str, mock.Mock]:
    """Mock runner.get_runner()."""
    self.mock_crush_runner = mock.Mock()
    self.mock_crush_runner.repro = mock.Mock(
        return_value=ReproduceResult(
            command=SYZ_CRUSH_COMMAND,
            return_code=1,
            time_executed=None,
            output='',
        ))

    self.mock_repro_runner = mock.Mock()
    self.mock_repro_runner.repro = mock.Mock(
        return_value=ReproduceResult(
            command=SYZ_REPRO_COMMAND,
            return_code=1,
            time_executed=None,
            output='',
        ))

    return {
        f'{BIN_DIR}/{SYZ_CRUSH}': self.mock_crush_runner,
        f'{BIN_DIR}/{SYZ_REPRO}': self.mock_repro_runner,
    }

  @mock.patch.object(environment, 'get_value')
  def test_prepare_binary_path(self, mock_get_value):
    mock_get_value.side_effect = ENV.get
    self.assertEqual(BIN_DIR, self.target.prepare_binary_path())

  @mock.patch.object(runner, 'get_runner')
  @mock.patch.object(runner, 'get_config')
  @mock.patch.object(environment, 'get_value')
  def test_reproduce(self, mock_get_value, mock_get_config, mock_get_runner):
    """Test engine reproducing successfully and invoking minimization."""
    mock_get_value.side_effect = ENV.get
    mock_get_config.return_value = TEST_CONFIG_ARGS
    mock_get_runner.side_effect = self.mock_runner_instances.get

    result = self.target.reproduce(
        target_path='',
        input_path=TESTCASE_PATH,
        arguments=[],
        max_time=None,
    )

    self.assertEqual(result.command, SYZ_CRUSH_COMMAND)
    self.assertEqual(result.return_code, 1)
    self.assertEqual(result.time_executed, None)
    self.assertEqual(result.output, '')

    self.mock_crush_runner.repro.assert_called_once_with(
        None,
        repro_args=(TEST_CONFIG_ARGS + [
            '-infinite=false',
            f'-restart_time={REPRO_TIME}s',
            TESTCASE_PATH,
        ]),
    )

    self.mock_repro_runner.minimize.assert_called_once_with(TEST_CONFIG_ARGS +
                                                            [TESTCASE_PATH])
