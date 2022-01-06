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
import os
import unittest

import mock

from clusterfuzz._internal.bot.fuzzers.syzkaller import runner
from clusterfuzz._internal.bot.fuzzers.syzkaller.runner import \
    AndroidSyzkallerRunner
from clusterfuzz._internal.bot.fuzzers.syzkaller.runner import REPRO_RETRY_MAX
from clusterfuzz._internal.system import new_process

EXECUTABLE_PATH = '/usr/local/google/home/username/syzkaller'
TEST_PATH = os.path.abspath(os.path.dirname(__file__))
TEMP_DIR = os.path.join(TEST_PATH, 'temp')
BUILD_DIR = os.path.join(TEST_PATH, 'build')
INPUT_DIR = os.path.join(TEST_PATH, 'input')

SYZ_CRUSH_COMMAND = (
    './bin/syz-crush -infinite=false -restart_time=70s '
    '-config ./cuttlefish_config.json '
    '/usr/local/google/home/username/syzkaller_workdir/test_crash.log')
SYZ_CRUSH_OUTPUT_TEMPLATE = '''
  2021/12/16 13:56:38 running until crash is found or till 1m10s
  2021/12/16 13:56:39 reproducing from log file: /usr/local/google/home/username/syzkaller_workdir/test_crash.log
  2021/12/16 13:56:39 booting 1 test machines...
  2021/12/16 13:56:39 vm-0: starting
  2021/12/16 13:57:01 failed to associate adb device 0.0.0.0:6520 with console: no unassociated console devices left
  2021/12/16 13:57:01 falling back to 'adb shell dmesg -w'
  2021/12/16 13:57:01 note: some bugs may be detected as 'lost connection to test machine' with no kernel output
  2021/12/16 13:57:01 associating adb device 0.0.0.0:6520 with console adb
  2021/12/16 13:57:01 device 0.0.0.0:6520: battery level 85%, OK
  2021/12/16 13:57:02 vm-0: crushing...
  2021/12/16 13:57:16 vm-0: crash: kernel BUG in add_timer
  2021/12/16 13:57:16 vm-0: closing channel
  2021/12/16 13:57:16 vm-0: done
  2021/12/16 13:57:16 {reproduce_log}
  2021/12/16 13:57:16 instances executed: 1, crashes: {crash}
  2021/12/16 13:57:16 all done. reproduced {crash} crashes. reproduce rate 100.00%
'''
SYZ_CRUSH_LOG_LOCATION = ('saving crash \'kernel BUG in add_timer\' '
                          f'with index 11 in {TEST_PATH}')
SYZ_CRUSH_OUTPUT_NO_REPRODUCE = SYZ_CRUSH_OUTPUT_TEMPLATE.format(
    reproduce_log=SYZ_CRUSH_LOG_LOCATION,
    crash=0,
)


class RunnerTest(unittest.TestCase):
  """Tests for AndroidSyzkallerRunner."""

  def setUp(self):
    super(RunnerTest, self).setUp()
    self.target = AndroidSyzkallerRunner(EXECUTABLE_PATH)

  def test_filter_log(self):
    content = ('[  565.723853] c4   8262 BUG: KASAN: use-after-free '
               'in f2fs_register_inmem_page+0x208/0x390')
    self.assertEqual(
        self.target._filter_log(content),
        'BUG: KASAN: use-after-free in f2fs_register_inmem_page+0x208/0x390',
    )

  def test_filter_log_without_pid(self):
    content = ('[ 1850.287295] KASAN: null-ptr-deref in range '
               '[0x0000000000000088-0x000000000000008f]')
    self.assertEqual(
        self.target._filter_log(content),
        'KASAN: null-ptr-deref in range [0x0000000000000088-0x000000000000008f]',
    )

  @mock.patch('clusterfuzz._internal.system.environment.get_value')
  @mock.patch('clusterfuzz._internal.bot.fuzzers.utils.get_temp_dir')
  def test_get_config(self, mock_temp_dir, mock_get_value):
    """Test get_config generates syzkaller config correctly."""
    env = {
        'ANDROID_SERIAL': '172.18.0.2:6520',
        'FUZZ_INPUTS_DISK': INPUT_DIR,
        'BUILD_DIR': BUILD_DIR,
        'OS_OVERRIDE': 'ANDROID_X86',
        'VMLINUX_PATH': BUILD_DIR,
        'CVD_DIR': '/home/vsoc-01'
    }
    mock_temp_dir.return_value = TEMP_DIR
    mock_get_value.side_effect = env.get

    runner.get_config()
    expected_config = (
        '{"target": "linux/amd64", '
        '"reproduce": false, '
        f'"workdir": "{INPUT_DIR}/syzkaller", '
        '"http": "localhost:0", '
        f'"syzkaller": "{BUILD_DIR}/syzkaller", '
        '"suppressions": ["do_rt_sigqueueinfo", "do_rt_tgsigqueueinfo"], '
        '"vm": {"devices": ['
        '{'
        '"serial": "172.18.0.2:6520", '
        '"console": "/home/vsoc-01/cuttlefish_runtime/kernel.log"'
        '}'
        ']}, '
        f'"kernel_obj": "{BUILD_DIR}", '
        '"sandbox": "none", '
        '"ignores": ["WARNING:", "INFO:"], '
        '"type": "adb", '
        '"procs": 1, '
        '"cover": true, '
        '"disable_syscalls": ["openat$vhost_vsock"]}')
    with open(f'{TEMP_DIR}/config.json', 'r') as file:
      actual_config = file.read()
      self.assertEqual(expected_config, actual_config)

    # Check syzkaller config for physical device has correct devices format.
    env['OS_OVERRIDE'] = 'ANDROID'
    runner.get_config()
    with open(f'{TEMP_DIR}/config.json', 'r') as file:
      actual_config = file.read()
      self.assertIn('"devices": ["172.18.0.2:6520"]', actual_config)

  @mock.patch('clusterfuzz._internal.system.new_process.ProcessRunner')
  def test_repro_successful(self, mock_process_runner):
    """Repro successfully finds crash log."""
    output = SYZ_CRUSH_OUTPUT_TEMPLATE.format(
        reproduce_log=SYZ_CRUSH_LOG_LOCATION,
        crash=1,
    )

    mock_process_runner.run_and_wait = mock.Mock(
        return_value=new_process.ProcessResult(
            command=SYZ_CRUSH_COMMAND,
            return_code=1,
            output=output,
        ))

    with open(f'{TEST_PATH}/reproducer11', 'r') as file:
      actual = self.target.repro(0, [])
      self.assertEqual(actual.command, SYZ_CRUSH_COMMAND)
      self.assertEqual(actual.return_code, 1)
      self.assertEqual(actual.output, file.read())

  @mock.patch('clusterfuzz._internal.system.new_process.ProcessRunner')
  def test_repro_no_log(self, mock_process_runner):
    """Repro retries when crash log not found."""
    output = SYZ_CRUSH_OUTPUT_TEMPLATE.format(
        reproduce_log='',
        crash=1,
    )

    mock_process_runner.run_and_wait = mock.Mock(
        return_value=new_process.ProcessResult(
            command=SYZ_CRUSH_COMMAND,
            return_code=1,
            output=output,
        ))

    actual = self.target.repro(0, [])
    self.assertEqual(actual.return_code, 0)

    self.assertEqual(
        mock_process_runner.run_and_wait.call_count,
        REPRO_RETRY_MAX,
    )

  @mock.patch('clusterfuzz._internal.system.new_process.ProcessRunner')
  def test_repro_no_crash(self, mock_process_runner):
    """Repro retries when crash fails to reproduce."""
    output = SYZ_CRUSH_OUTPUT_TEMPLATE.format(
        reproduce_log=SYZ_CRUSH_LOG_LOCATION,
        crash=0,
    )

    mock_process_runner.run_and_wait = mock.Mock(
        return_value=new_process.ProcessResult(
            command=SYZ_CRUSH_COMMAND,
            return_code=1,
            output=output,
        ))

    actual = self.target.repro(0, [])
    self.assertEqual(actual.return_code, 0)

    self.assertEqual(
        mock_process_runner.run_and_wait.call_count,
        REPRO_RETRY_MAX,
    )
