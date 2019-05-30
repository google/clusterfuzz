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
"""Helper functions for running commands on Fuchsia devices."""

# TODO(flowerhack): Re-enable this check once functions below are implemented.
# pylint: disable=unused-argument
from __future__ import print_function

import os
import socket
import subprocess

from metrics import logs
from platforms.fuchsia import errors
from platforms.fuchsia.util.device import Device
from platforms.fuchsia.util.fuzzer import Fuzzer
from platforms.fuchsia.util.host import Host
from system import environment
from system import new_process
from system import shell


def qemu_setup():
  """Sets up and runs a QEMU VM in the background.
  Returns a process.Popen object.
  Does not block the calling process, and teardown must be handled by the
  caller (use .kill()).
  Fuchsia fuzzers assume a QEMU VM is running; call this routine prior to
  beginning Fuchsia fuzzing tasks.
  This initialization routine assumes the following layout for
  fuchsia_resources_dir:

  * /qemu-for-fuchsia/*
  * /.ssh/*
  * target/x64/fvm.blk
  * target/x64/fuchsia.zbi
  * target/x64/multiboot.bin

  * build/out/default/fuzzers.json
  * build/out/default/ids.txt
  * build/out/default.zircon/tools/*
  * build/zircon/prebuilt/downloads/symbolize
  * build/buildtools/linux-x64/clang/bin/llvm-symbolizer"""

  # First download the Fuchsia resources locally.
  fuchsia_resources_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
  if not fuchsia_resources_dir:
    raise errors.FuchsiaConfigError('Could not find FUCHSIA_RESOURCES_DIR')

  # Then, save paths for necessary commands later.
  qemu_path = os.path.join(fuchsia_resources_dir, 'qemu-for-fuchsia', 'bin',
                           'qemu-system-x86_64')
  os.chmod(qemu_path, 0o550)
  kernel_path = os.path.join(fuchsia_resources_dir, 'target', 'x64',
                             'multiboot.bin')
  os.chmod(kernel_path, 0o644)
  pkey_path = os.path.join(fuchsia_resources_dir, '.ssh', 'pkey')
  os.chmod(pkey_path, 0o400)
  sharefiles_path = os.path.join(fuchsia_resources_dir, 'qemu-for-fuchsia',
                                 'share', 'qemu')
  drive_path = os.path.join(fuchsia_resources_dir, 'target', 'x64', 'fvm.blk')
  os.chmod(drive_path, 0o644)
  fuchsia_zbi = os.path.join(fuchsia_resources_dir, 'target', 'x64',
                             'fuchsia.zbi')
  initrd_path = os.path.join(fuchsia_resources_dir, 'fuchsia-ssh.zbi')

  # Perform some more initiailization steps.
  extend_fvm(fuchsia_resources_dir, drive_path)
  add_keys_to_zbi(fuchsia_resources_dir, initrd_path, fuchsia_zbi)

  # Get a free port for the VM, so we can SSH in later.
  tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  tcp.bind(('localhost', 0))
  _, port = tcp.getsockname()
  tcp.close()
  # Fuzzing jobs that SSH into the QEMU VM need access to this env var.
  environment.set_value('FUCHSIA_PORTNUM', port)
  environment.set_value('FUCHSIA_RESOURCES_DIR', fuchsia_resources_dir)

  # yapf: disable
  qemu_args = [
      '-m', '2048',
      '-nographic',
      '-kernel', kernel_path,
      '-initrd', initrd_path,
      '-smp', '4',
      '-drive', 'file=' + drive_path + ',format=raw,if=none,id=blobstore',
      '-device', 'virtio-blk-pci,drive=blobstore',
      '-monitor', 'none',
      '-append', '"kernel.serial=legacy TERM=dumb"',
      '-machine', 'q35',
      '-display', 'none',
      # Can't use host CPU since we don't necessarily have KVM on the machine.
      # Emulate a Haswell CPU with a few feature toggles. This mirrors the most
      # common configuration for Fuchsia VMs when using in-tree tools.
      '-cpu', 'Haswell,+smap,-check,-fsgsbase',
      '-netdev',
      ('user,id=net0,net=192.168.3.0/24,dhcpstart=192.168.3.9,'
       'host=192.168.3.2,hostfwd=tcp::') + str(port) + '-:22',
      '-device', 'e1000,netdev=net0,mac=52:54:00:63:5e:7b',
      '-L', sharefiles_path
  ]
  # yapf: enable

  # Get the list of fuzzers for ClusterFuzz to choose from.
  host = Host.from_dir(
      os.path.join(fuchsia_resources_dir, 'build', 'out', 'default'))
  Device(host, 'localhost', str(port))
  Fuzzer.filter(host.fuzzers, '')

  # Fuzzing jobs that SSH into the QEMU VM need access to this env var.
  environment.set_value('FUCHSIA_PKEY_PATH', pkey_path)

  # Finally, launch QEMU.
  logs.log('Running QEMU. Command: ' + qemu_path + ' ' + str(qemu_args))
  qemu_process = new_process.ProcessRunner(qemu_path, qemu_args)
  qemu_popen = qemu_process.run(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  return qemu_popen


def initialize_resources_dir():
  """Download Fuchsia QEMU resources from GCS bucket."""
  # This module depends on multiprocessing, which is not available in
  # appengine, and since appengine *imports* this file (but does not run this
  # function!), we import it here.
  from google_cloud_utils import gsutil
  resources_dir = environment.get_value('RESOURCES_DIR')
  if not resources_dir:
    raise errors.FuchsiaConfigError('Could not find RESOURCES_DIR')
  fuchsia_resources_dir = os.path.join(resources_dir, 'fuchsia')

  shell.create_directory(
      fuchsia_resources_dir, create_intermediates=True, recreate=True)

  # Bucket for QEMU resources.
  fuchsia_resources_url = environment.get_value('FUCHSIA_RESOURCES_URL')
  if not fuchsia_resources_url:
    raise errors.FuchsiaConfigError(
        'Could not find path for remote'
        'Fuchsia resources bucket (FUCHSIA_RESOURCES_URL')

  gsutil_command_arguments = [
      '-m', 'cp', '-r', fuchsia_resources_url, fuchsia_resources_dir
  ]
  logs.log("Beginning Fuchsia SDK download.")
  result = gsutil.GSUtilRunner().run_gsutil(gsutil_command_arguments)
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to download Fuchsia '
                                 'resources: ' + result.output)
  logs.log("Fuchsia SDK download complete.")

  # Bucket for build resources. Necessary for fuzzer selection.
  logs.log("Fetching Fuchsia build.")
  fuchsia_build_url = environment.get_value('FUCHSIA_BUILD_URL')
  if not fuchsia_build_url:
    raise errors.FuchsiaConfigError('Could not find path for remote'
                                    'Fuchsia build bucket (FUCHSIA BUILD URL')

  gsutil_command_arguments = [
      '-m', 'cp', '-r', fuchsia_build_url, fuchsia_resources_dir
  ]
  logs.log("Beginning Fuchsia build download.")
  result = gsutil.GSUtilRunner().run_gsutil(gsutil_command_arguments)
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to download Fuchsia '
                                 'resources: ' + result.output)

  return fuchsia_resources_dir


def extend_fvm(fuchsia_resources_dir, drive_path):
  """The FVM is minimally sized to begin with; extend it to make room for
  ephemeral packages etc."""
  fvm_tool_path = os.path.join(fuchsia_resources_dir, 'build', 'out',
                               'default.zircon', 'tools', 'fvm')
  os.chmod(fvm_tool_path, 0o500)
  process = new_process.ProcessRunner(fvm_tool_path,
                                      [drive_path, 'extend', '--length', '2G'])
  result = process.run_and_wait()
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to extend FVM: ' + result.output)


def add_keys_to_zbi(fuchsia_resources_dir, initrd_path, fuchsia_zbi):
  """Adds keys to the ZBI so we can SSH into it. See:
  fuchsia.googlesource.com/fuchsia/+/refs/heads/master/sdk/docs/ssh.md"""
  zbi_tool = os.path.join(fuchsia_resources_dir, 'build', 'out',
                          'default.zircon', 'tools', 'zbi')
  os.chmod(zbi_tool, 0o500)
  authorized_keys_path = os.path.join(fuchsia_resources_dir, '.ssh',
                                      'authorized_keys')
  process = new_process.ProcessRunner(zbi_tool, [
      '-o', initrd_path, fuchsia_zbi, '-e',
      'data/ssh/authorized_keys=' + authorized_keys_path
  ])
  result = process.run_and_wait()
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to add keys to Fuchsia ZBI: ' +
                                 result.output)
  os.chmod(initrd_path, 0o644)


def get_application_launch_command(arguments, testcase_path):
  """Prepare a command to run on the host to launch on the device."""
  # TODO(flowerhack): Implement this.
  return ''


def reset_state():
  """Reset the device to a clean state."""
  # TODO(flowerhack): Implement this.


def run_command(command_line, timeout):
  """Run the desired command on the device."""
  # TODO(flowerhack): Implement this.


def clear_testcase_directory():
  """Delete test cases stored on the device."""
  # TODO(flowerhack): Implement this.


def copy_testcase_to_device(testcase_path):
  """Copy a file to the device's test case directory."""
  # TODO(flowerhack): Implement this.
