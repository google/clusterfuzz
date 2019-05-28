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
"""Utilites for managing Fuchsia devices."""
from __future__ import absolute_import

from builtins import object
from builtins import range
from builtins import str
import os
import re
import subprocess

from .host import Host


class Device(object):
  """Represents a Fuchsia device attached to a host.

    This class abstracts the details of remotely running commands and
    transferring data to and from the device.

    Attributes:
      host: A Host object represent the local platform attached to this target
        device.
  """

  @classmethod
  def from_args(cls, host, args):
    """Constructs a Device from command line arguments."""
    netaddr_cmd = ['netaddr', '--fuchsia', '--nowait']
    if args.device:
      netaddr_cmd.append(args.device)
    try:
      netaddr = host.zircon_tool(netaddr_cmd)
    except subprocess.CalledProcessError:
      raise RuntimeError('Unable to find device')
    device = cls(host, netaddr)
    if not host.build_dir:
      raise Host.ConfigError('Unable to find SSH configuration.')
    device.set_ssh_config(Host.join(host.build_dir, 'ssh-keys', 'ssh_config'))
    return device

  def __init__(self, host, addr, port=22):
    self.host = host
    self._addr = addr
    self._ssh_opts = {}
    if port != 22:
      self._ssh_opts['p'] = [str(port)]

  def set_ssh_config(self, config_file):
    """Sets the SSH arguments to use a config file."""
    if not os.path.exists(config_file):
      raise Host.ConfigError('Unable to find SSH configuration.')
    self._ssh_opts['F'] = [config_file]

  def set_ssh_identity(self, identity_file):
    if not os.path.exists(identity_file):
      raise Host.ConfigError('Unable to find SSH identity.')
    self._ssh_opts['i'] = [identity_file]

  def set_ssh_option(self, option):
    """Sets SSH configuration options. Can be used multiple times."""
    if 'o' in self._ssh_opts:
      self._ssh_opts['o'].append(option)
    else:
      self._ssh_opts['o'] = [option]

  def set_ssh_verbosity(self, level):
    """Sets how much debugging SSH prints. Default is 0 (none), max is 3."""
    for i in range(1, 4):
      opt = 'v' * i
      if level == i and not opt in self._ssh_opts:
        self._ssh_opts[opt] = []
      elif level != i and opt in self._ssh_opts:
        del self._ssh_opts[opt]

  def get_ssh_cmd(self, cmd):
    """Returns the SSH executable and options."""
    result = cmd[:1]
    for opt, args in self._ssh_opts.items():
      if not args:
        result.append('-' + opt)
      else:
        for arg in args:
          result.append('-' + opt)
          result.append(arg)
    return result + cmd[1:]

  def _ssh(self, cmdline, stdout=subprocess.PIPE):
    """Internal wrapper around _rexec that adds the ssh command and config.

    Don't call this directly. This method exists to be overridden in testing.

    Args:
      cmdline: List of command line arguments to execute on device
      stdout: Same as for subprocess.Popen

    Returns:
      If check was false, a subprocess.Popen object representing the running
      child process.

    Raises: Same as subprocess.Popen
    """
    return subprocess.Popen(
        self.get_ssh_cmd(['ssh', self._addr] + cmdline),
        stdout=stdout,
        stderr=subprocess.STDOUT)

  def ssh(self, cmdline, quiet=True, logfile=None):
    """Runs a command to completion on the device.

    Connects to the target device and executes a shell command.  Output from
    the shell command is sent to stdout, and may optionally be saved to a file
    via the POSIX utility 'tee'.

    Args:
      cmdline: A list of command line arguments, starting with the command to
        execute.
      logfile: An optional pathname to save a copy of the command output to. The
        output will also still be sent to stdout.
    """
    if quiet:
      if logfile:
        with open(logfile, 'w') as f:
          self._ssh(cmdline, stdout=f).wait()
      else:
        self._ssh(cmdline, stdout=Host.DEVNULL).wait()
    else:
      if logfile:
        proc = self._ssh(cmdline, stdout=subprocess.PIPE)
        subprocess.check_call(['tee', logfile], stdin=proc.stdout)
      else:
        self._ssh(cmdline, stdout=None).wait()

  def getpids(self):
    """Maps names to process IDs for running fuzzers.

    Connects to the device and checks which fuzz targets have a matching entry
    in the component list given by 'cs'.  This matches on *only* the first 32
    characters of the component manifest and package URL.  This is due to 'cs'
    being limited to returning strings of length `ZX_MAX_NAME_LEN`, as defined
    in //zircon/system/public/zircon/types.h.

    Returns:
      A dict mapping fuzz target names to process IDs. May be empty if no
      fuzzers are running.
    """
    out, _ = self._ssh(['cs'], stdout=subprocess.PIPE).communicate()
    pids = {}
    for fuzzer in self.host.fuzzers:
      tgt = (fuzzer[1] + '.cmx')[:32]
      url = ('fuchsia-pkg://fuchsia.com/%s#meta' % fuzzer[0])[:32]
      for line in str(out).split('\n'):
        match = re.search(tgt + r'\[(\d+)\]: ' + url, line)
        if match:
          pids[fuzzer[1]] = int(match.group(1))
    return pids

  def ls(self, path):
    """Maps file names to sizes for the given path.

    Connects to a Fuchsia device and lists the files in a directory given by
    the provided path.  Ignore non-existent paths.

    Args:
      path: Absolute path to a directory on the device.

    Returns:
      A dict mapping file names to file sizes, or an empty dict if the path
      does not exist.
    """
    results = {}
    try:
      out, _ = self._ssh(
          ['ls', '-l', path], stdout=subprocess.PIPE).communicate()
      for line in str(out).split('\n'):
        # Line ~= '-rw-r--r-- 1 0 0 8192 Mar 18 22:02 some-name'
        parts = line.split()
        if len(parts) > 8:
          results[' '.join(parts[8:])] = int(parts[4])
    except subprocess.CalledProcessError:
      pass
    return results

  def _scp(self, src, dst):
    """Copies `src` to `dst`.

    Don't call directly; use `fetch` or `store` instead.`

    Args:
      src: Local or remote path to copy from.
      dst: Local or remote path to copy to.
    """
    subprocess.check_call(
        self.get_ssh_cmd(['scp', src, dst]),
        shell=True,
        stdout=None,
        stderr=None)

  def fetch(self, data_src, host_dst):
    """Copies `data_src` on the target to `host_dst` on the host."""
    if not os.path.isdir(host_dst):
      raise ValueError(host_dst + ' is not a directory')
    self._scp('[' + self._addr + ']:' + data_src, host_dst)

  def store(self, host_src, data_dst):
    """Copies `host_src` on the host to `data_dst` on the target."""
    self.ssh(['mkdir', '-p', data_dst])
    self._scp(host_src, '[' + self._addr + ']:' + data_dst)
