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

import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms.fuchsia import errors
from clusterfuzz._internal.platforms.fuchsia.util.device import Device
from clusterfuzz._internal.platforms.fuchsia.util.fuzzer import Fuzzer
from clusterfuzz._internal.platforms.fuchsia.util.host import Host
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import process_handler

_QEMU_WAIT_SECONDS = 60


def _fetch_qemu_vars():
  """
  Returns a dictionary with variables necessary for configuring and running
  Fuchsia via QEMU.

  This function assumes the following layout for
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
  * build/buildtools/linux-x64/clang/bin/llvm-symbolizer

  If these locations change in the build, they should be changed here as well.
  """
  qemu_vars = {}

  # First, ensure we have a resources directory.
  fuchsia_resources_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
  if not fuchsia_resources_dir:
    raise errors.FuchsiaConfigError('Could not find FUCHSIA_RESOURCES_DIR')

  # Then, save and chmod the associated paths.
  qemu_vars['fuchsia_resources_dir'] = fuchsia_resources_dir
  qemu_vars['qemu_path'] = os.path.join(
      fuchsia_resources_dir, 'qemu-for-fuchsia', 'bin', 'qemu-system-x86_64')
  os.chmod(qemu_vars['qemu_path'], 0o550)
  qemu_vars['kernel_path'] = os.path.join(fuchsia_resources_dir, 'target',
                                          'x64', 'multiboot.bin')
  os.chmod(qemu_vars['kernel_path'], 0o644)
  qemu_vars['pkey_path'] = os.path.join(fuchsia_resources_dir, '.ssh', 'pkey')
  os.chmod(qemu_vars['pkey_path'], 0o400)
  qemu_vars['sharefiles_path'] = os.path.join(
      fuchsia_resources_dir, 'qemu-for-fuchsia', 'share', 'qemu')
  qemu_vars['drive_path'] = os.path.join(fuchsia_resources_dir, 'target', 'x64',
                                         'fvm-extended.blk')
  qemu_vars['orig_drive_path'] = os.path.join(fuchsia_resources_dir, 'target',
                                              'x64', 'fvm.blk')
  os.chmod(qemu_vars['orig_drive_path'], 0o644)
  qemu_vars['fuchsia_zbi'] = os.path.join(fuchsia_resources_dir, 'target',
                                          'x64', 'fuchsia.zbi')
  qemu_vars['initrd_path'] = os.path.join(fuchsia_resources_dir,
                                          'fuchsia-ssh.zbi')
  return qemu_vars


def initial_qemu_setup():
  """Performs one-time setup necessary to subsequently run Fuchsia QEMU VMs.
  This only needs to be called once per build setup, and will do nothing if
  called multiple times.
  This function does not run a VM, merely performs setup for a VM.
  """
  qemu_vars = _fetch_qemu_vars()

  # Exit early if it appears we've already been called for this build
  if os.path.exists(qemu_vars['initrd_path']):
    return

  extend_fvm(qemu_vars['fuchsia_resources_dir'], qemu_vars['orig_drive_path'],
             qemu_vars['drive_path'])
  add_keys_to_zbi(qemu_vars['fuchsia_resources_dir'], qemu_vars['initrd_path'],
                  qemu_vars['fuchsia_zbi'])


class QemuError(Exception):
  """Error for errors handling QEMU."""


class QemuProcess(object):
  """A QemuProcess encapsulates the creation, running, and destruction
  of Fuchsia QEMU processes."""

  # For now, use a system-global log path so we don't need to pass a tempfile
  # path around everywhere. We use a class constant so it can be accessed
  # without an instance, but defer initialization until the constructor so that
  # it isn't run in non-Fuchsia contexts.
  LOG_PATH = None

  def __init__(self):
    self.process_runner = None
    self.popen = None
    self.logfile = None

    if not QemuProcess.LOG_PATH:
      QemuProcess.LOG_PATH = os.path.join(tempfile.gettempdir(),
                                          'fuchsia-qemu-log')

  def create(self):
    """Configures a QEMU process which can subsequently be `run`.

    Assumes that initial_qemu_setup was already called exactly once.
    """
    qemu_vars = _fetch_qemu_vars()

    # Get a free port for the VM, so we can SSH in later.
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('localhost', 0))
    _, port = tcp.getsockname()
    tcp.close()
    # Fuzzing jobs that SSH into the QEMU VM need access to this env var.
    environment.set_value('FUCHSIA_PORTNUM', port)
    environment.set_value('FUCHSIA_RESOURCES_DIR',
                          qemu_vars['fuchsia_resources_dir'])

    # yapf: disable
    qemu_args = [
        '-m', '3072',
        '-nographic',
        '-kernel', qemu_vars['kernel_path'],
        '-initrd', qemu_vars['initrd_path'],
        '-smp', '4',
        '-drive',
        ('file=' + qemu_vars['drive_path'] + ',format=raw,if=none,'
         'id=blobstore'),
        '-device', 'virtio-blk-pci,drive=blobstore',
        '-monitor', 'none',
        '-append', 'kernel.serial=legacy TERM=dumb',
        '-machine', 'q35',
        '-display', 'none',
        '-netdev',
        ('user,id=net0,net=192.168.3.0/24,dhcpstart=192.168.3.9,'
         'host=192.168.3.2,hostfwd=tcp::') + str(port) + '-:22',
        '-device', 'e1000,netdev=net0,mac=52:54:00:63:5e:7b',
        '-L', qemu_vars['sharefiles_path']
    ]
    # yapf: enable

    # Detecting KVM is tricky, so use an environment variable to determine
    # whether to turn it on or not.
    if environment.get_value('FUCHSIA_USE_KVM'):
      # In builds before fxrev.dev/375343, a bug prevents booting with newer
      # versions of KVM. On some of these older builds,
      # `kernel.x86.disable-spec-mitigations` also doesn't work as
      # expected, so we work around this by selecting a CPU type where the
      # speculation mitigation will not applied.
      if environment.get_value('APP_REVISION') < 20200414210423:
        qemu_args.extend(['-cpu', 'Opteron_G5,+invtsc'])
      else:
        qemu_args.extend(['-cpu', 'host,migratable=no,+invtsc'])
      qemu_args.append('-enable-kvm')
    else:
      # Can't use host CPU since we don't necessarily have KVM on the machine.
      # Emulate a Haswell CPU with a few feature toggles. This mirrors the most
      # common configuration for Fuchsia VMs when using in-tree tools.
      qemu_args.extend(['-cpu', 'Haswell,+smap,-check,-fsgsbase'])

    # Get the list of fuzzers for ClusterFuzz to choose from.
    host = Host.from_dir(
        os.path.join(qemu_vars['fuchsia_resources_dir'], 'build', 'out',
                     'default'))
    Device(host, 'localhost', str(port))
    Fuzzer.filter(host.fuzzers, '')

    # Fuzzing jobs that SSH into the QEMU VM need access to this env var.
    environment.set_value('FUCHSIA_PKEY_PATH', qemu_vars['pkey_path'])
    logs.log('Ready to run QEMU. Command: ' + qemu_vars['qemu_path'] + ' ' +
             ' '.join(shlex.quote(arg) for arg in qemu_args))
    self.process_runner = new_process.ProcessRunner(qemu_vars['qemu_path'],
                                                    qemu_args)

  def run(self):
    """Actually runs a QEMU VM, assuming `create` has already been called."""
    if not self.process_runner:
      raise QemuError('Attempted to `run` QEMU VM before calling `create`')

    # pylint: disable=consider-using-with
    self.logfile = open(QemuProcess.LOG_PATH, 'wb')
    self.popen = self.process_runner.run(
        stdout=self.logfile, stderr=subprocess.PIPE)
    time.sleep(_QEMU_WAIT_SECONDS)

  def kill(self):
    """ Kills the currently-running QEMU VM, if there is one. """
    if self.popen:
      self.popen.kill()
      self.popen = None

    if self.logfile:
      self.logfile.close()
      self.logfile = None


def start_qemu():
  """Start qemu."""
  qemu = QemuProcess()
  qemu.create()
  qemu.run()


def stop_qemu():
  """Stop qemu."""
  process_handler.terminate_processes_matching_names('qemu-system-x86_64')


def extend_fvm(fuchsia_resources_dir, orig_drive_path, drive_path):
  """The FVM is minimally sized to begin with; make an extended copy
  of it to make room for ephemeral packages etc."""
  fvm_tool_path = os.path.join(fuchsia_resources_dir, 'build', 'out',
                               'default.zircon', 'tools', 'fvm')
  os.chmod(fvm_tool_path, 0o500)

  # Since the fvm tool modifies the image in place, make a copy so the build
  # isn't mutated (required for running undercoat on a cached build previously
  # affected by this legacy codepath)
  shutil.copy(orig_drive_path, drive_path)

  process = new_process.ProcessRunner(fvm_tool_path,
                                      [drive_path, 'extend', '--length', '3G'])
  result = process.run_and_wait()
  if result.return_code or result.timed_out:
    raise errors.FuchsiaSdkError('Failed to extend FVM: ' + result.output)

  os.chmod(drive_path, 0o644)


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
