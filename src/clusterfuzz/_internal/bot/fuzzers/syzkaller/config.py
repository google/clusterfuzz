# Copyright 2020 Google LLC
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
"""Generate Syzkaller fuzzer config dynamically."""

import json
import os


def generate(serial,
             work_dir_path,
             binary_path,
             vmlinux_path,
             config_path,
             kcov=True,
             reproduce=True,
             syzhub_address=None,
             syzhub_client=None,
             syzhub_key=None,
             on_cuttlefish=False):
  """Generates syzkaller config file.

  Args:
    serial: (str)serial number of the device being fuzzed.
    work_dir_path: (str) path to working directory of syzkaller.
    binary_path: (str) path to syzkaller binaries.
    vmlinux_path: (str) path to the vmlinux file.
    config_path: (str) path to write the syzkaller config to.
    kcov: (boolean) true if coverage is enabled.
    reproduce: (boolean) true if repro is enabled.
    syzhub_address: (str) ip:host of the syzhub to connect to.
    syzhub_client: (str) syzhub client name.
    syzhub_key: (str) syzhub key.
  """
  devices = {}
  devices['devices'] = [serial]
  data = {}
  data['target'] = 'linux/arm64'
  data['reproduce'] = reproduce
  data['workdir'] = work_dir_path
  data['http'] = 'localhost:0'
  data['syzkaller'] = binary_path
  #TODO(hzawawy): consider what suppressions are best for Android.
  data['suppressions'] = ['do_rt_sigqueueinfo', 'do_rt_tgsigqueueinfo']
  data['vm'] = devices
  data['kernel_obj'] = vmlinux_path
  data['sandbox'] = 'android'
  data['ignores'] = ['WARNING:', 'INFO:']
  data['type'] = 'adb'
  data['procs'] = 1
  data['cover'] = kcov

  if on_cuttlefish:
    data['target'] = 'linux/amd64'
    data['disable_syscalls'] = ['openat$vhost_vsock']
    data['sandbox'] = 'none'

  if syzhub_address and syzhub_client and syzhub_key:
    data['hub_addr'] = syzhub_address
    data['hub_client'] = syzhub_client
    data['hub_key'] = syzhub_key
    data['name'] = '{}-{}'.format(syzhub_client, serial)

  ensure_dir(config_path)
  with open(config_path, 'w') as write_file:
    json.dump(data, write_file)


def ensure_dir(file_path):
  directory = os.path.dirname(file_path)
  if not os.path.exists(directory):
    os.makedirs(directory)
