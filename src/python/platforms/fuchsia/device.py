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

# TODO(mbarbella): Re-enable this check once functions below are implemented.
# pylint: disable=unused-argument

import os

from fuchsia import errors
from google_cloud_utils import gsutil
from metrics import logs
from system import environment
from system import new_process
from system import shell


def qemu_setup():
  """ Sets up and runs a QEMU VM in the background.
  Does not block the calling process.
  Fuchsia fuzzers assume a QEMU VM is running; call this routine prior to
  beginning Fuchsia fuzzing tasks.
  This initialization routine assumes that the GCS bucket contains the
  standard Fuchsia SDK, as well as:
  * /qemu-for-fuchsia/*
  * /.ssh/* """
  fuchsia_bucket_name = 'fuchsia_on_clusterfuzz_resources_v1'

  resources_path = os.path.join(os.getcwd(), fuchsia_bucket_name)

  shell.create_directory(resources_path)

  fuchsia_resources_url = environment.get_value('FUCHSIA_RESOURCES_URL')
  if fuchsia_resources_url is None:
    raise errors.FuchsiaConfigError(
        'Could not find path for remote'
        'Fuchsia resources bucket (FUCHSIA_RESOURCES_URL')

  gsutil_command_arguments = [
      '-m', 'cp', '-r', fuchsia_resources_url, resources_path
  ]
  logs.log("Beginning Fuchsia SDK download.")
  result = gsutil.GSUtilRunner().run_gsutil(gsutil_command_arguments)
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to download Fuchsia'
                                 'resources: ' + result.output)
  logs.log("Fuchsia SDK download complete.")

  # Save paths for necessary commands later.
  qemu_path = os.path.join(resources_path, 'qemu-for-fuchsia', 'bin',
                           'qemu-system-x86_64')
  os.chmod(qemu_path, 0o550)
  kernel_path = os.path.join(resources_path, 'target', 'x64', 'qemu-kernel.bin')
  os.chmod(kernel_path, 0o644)
  authorized_keys_path = os.path.join(resources_path, '.ssh', 'authorized_keys')
  pkey_path = os.path.join(resources_path, '.ssh', 'pkey')
  os.chmod(pkey_path, 0o400)
  sharefiles_path = os.path.join(resources_path, 'qemu-for-fuchsia', 'share',
                                 'qemu')

  # The FVM is minimally sized to begin with; extend it to make room for
  # ephemeral packages etc.
  drive_path = os.path.join(resources_path, 'target', 'x64', 'fvm.blk')
  os.chmod(drive_path, 0o644)
  fvm_tool_path = os.path.join(resources_path, 'tools', 'fvm')
  os.chmod(fvm_tool_path, 0o500)
  process = new_process.ProcessRunner(fvm_tool_path,
                                      [drive_path, 'extend', '--length', '1G'])
  result = process.run_and_wait()
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to extend FVM: ' + result.output)

  # Need to bake keys into ZBI so we can SSH into it.  See:
  # fuchsia.googlesource.com/fuchsia/+/refs/heads/master/sdk/docs/ssh.md
  zbi_tool = os.path.join(resources_path, 'tools', 'zbi')
  os.chmod(zbi_tool, 0o500)
  fuchsia_zbi = os.path.join(resources_path, 'target', 'x64', 'fuchsia.zbi')
  initrd_path = os.path.join(resources_path, 'fuchsia-ssh.zbi')
  process = new_process.ProcessRunner(zbi_tool, [
      '-o', initrd_path, fuchsia_zbi, '-e',
      'data/ssh/authorized_keys=' + authorized_keys_path
  ])
  result = process.run_and_wait()
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to add keys to Fuchsia ZBI: ' +
                                 result.output)
  os.chmod(initrd_path, 0o644)

  # TODO(flowerhack): Add a mechanism for choosing portnum dynamically.
  portnum = '56339'

  # yapf: disable
  qemu_command = [
      qemu_path,
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
      '-enable-kvm',
      '-display', 'none',
      '-cpu', 'host,migratable=no',
      '-netdev',
      ('user,id=net0,net=192.168.3.0/24,dhcpstart=192.168.3.9,'
       'host=192.168.3.2,hostfwd=tcp::') + portnum + '-:22',
      '-device', 'e1000,netdev=net0,mac=52:54:00:63:5e:7b',
      '-L', sharefiles_path
  ]
  # yapf: enable
  # Fuzzing jobs that SSH into the QEMU VM need access to these env vars.
  environment.set_value('FUCHSIA_PKEY_PATH', pkey_path)
  environment.set_value('FUCHSIA_PORTNUM', portnum)
  qemu_process = new_process.ProcessRunner(qemu_command[0], qemu_command[1:])
  qemu_process.run()


def get_application_launch_command(arguments, testcase_path):
  """Prepare a command to run on the host to launch on the device."""
  # TODO(mbarbella): Implement this.
  return ''


def reset_state():
  """Reset the device to a clean state."""
  # TODO(mbarbella): Implement this.


def run_command(command_line, timeout):
  """Run the desired command on the device."""
  # TODO(mbarbella): Implement this.


def clear_testcase_directory():
  """Delete test cases stored on the device."""
  # TODO(mbarbella): Implement this.


def copy_testcase_to_device(testcase_path):
  """Copy a file to the device's test case directory."""
  # TODO(mbarbella): Implement this.
