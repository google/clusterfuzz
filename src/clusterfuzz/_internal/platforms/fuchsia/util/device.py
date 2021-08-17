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
"""Utilities for managing Fuchsia devices."""

import glob
import os
import re
import shutil
import subprocess

import six

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
    default_device = '{}.device'.format(host.build_dir)
    if args.device:
      netaddr_cmd.append(args.device)
    elif os.path.exists(default_device):
      with open(default_device) as f:
        netaddr_cmd.append(f.read().strip())
    try:
      netaddr = host.zircon_tool(netaddr_cmd)
    except subprocess.CalledProcessError:
      raise RuntimeError('Unable to find device; try `fx set-device`.')
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
    for opt, args in six.iteritems(self._ssh_opts):
      if result[0] == 'scp' and opt == 'p':
        opt = 'P'
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

    Raises: A Process object.
    """
    args = self.get_ssh_cmd(['ssh', self._addr] + cmdline)
    return self.host.create_process(
        args, stdout=stdout, stderr=subprocess.STDOUT)

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
          return self._ssh(cmdline, stdout=f).call()
      return self._ssh(cmdline, stdout=Host.DEVNULL).call()

    if logfile:
      p1 = self._ssh(cmdline, stdout=subprocess.PIPE).popen()
      p2 = self.host.create_process(['tee', logfile], stdin=p1.stdout)
      return p2.check_call()
    return self._ssh(cmdline, stdout=None).call()

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
    p = self._ssh(['cs'], stdout=subprocess.PIPE).popen()
    out, _ = p.communicate()
    pids = {}
    for fuzzer in self.host.fuzzers:
      tgt = (fuzzer[1] + '.cmx')[:32]
      url = ('fuchsia-pkg://fuchsia.com/%s#meta' % fuzzer[0])[:32]
      for line in out.decode('utf-8').split('\n'):
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
      p = self._ssh(['ls', '-l', path], stdout=subprocess.PIPE).popen()
      out, _ = p.communicate()
      for line in out.decode('utf-8').split('\n'):
        # Line ~= '-rw-r--r-- 1 0 0 8192 Mar 18 22:02 some-name'
        parts = line.split()
        # When we're running ls over ssh, we may get a note about
        # "Warning: Permanently added [address] to the list of known hosts"
        # Don't try to treat those as file paths
        if len(parts) > 8 and 'Warning:' not in parts:
          results[' '.join(parts[8:])] = int(parts[4])
    except subprocess.CalledProcessError:
      pass
    return results

  def rm(self, pathname, recursive=False):
    """Removes a file or directory from the device."""
    args = ['rm']
    if recursive:
      args.append('-r')
    args.append(pathname)
    self.ssh(args)

  def _dump_log(self, args):
    """Retrieve a syslog from the device."""
    p = self._ssh(['log_listener', '--dump_logs', 'yes'] + args)
    return p.check_output()

  def _guess_pid(self):
    """Tries to guess the fuzzer process ID from the device syslog.

        This will assume the last line which contained one of the strings
        '{{{reset}}}', 'libFuzzer', or 'Sanitizer' is the fuzzer process, and
        try to extract its PID.

        Returns:
          The PID of the process suspected to be the fuzzer, or -1 if no
          suitable candidate was found.
        """
    out = self._dump_log(['--only', 'reset,Fuzzer,Sanitizer'])
    pid = -1
    for line in out.split(b'\n'):
      # Log lines are like '[timestamp][pid][tid][name] data'
      parts = line.split(b'][')
      if len(parts) > 2:
        pid = int(parts[1])
    return pid

  def process_logs(self, logfile, guess_pid=False, retcode=0):
    """Constructs a symbolized fuzzer log from a device.

        Merges the provided fuzzer log with the symbolized system log for the
        fuzzer process.

        Args:
          logfile: Absolute path to a fuzzer's log file.
          guess_pid: If true and the fuzzer process ID cannot be found in the
            fuzzer log, the process ID is picked from candidates in the system
            log.

        Returns:
          A list of the test artifacts (e.g. crashes) reported in the logs.
        """
    pid = -1
    pid_pattern = re.compile(br'==([0-9]+)==')
    mutation_pattern = re.compile(br'^MS: [0-9]*')
    artifacts = []
    artifact_pattern = re.compile(br'Test unit written to data/(\S*)')
    repro_pattern = re.compile(br'Running: .*')
    line_with_crash_message = None
    with open(logfile, 'rb') as log:
      with open(logfile + '.tmp', 'wb') as tmp:
        for line in log:
          # Check for a line that tells us the process ID
          match = pid_pattern.search(line)
          if match:
            line_with_crash_message = line
            pid = int(match.group(1))

          # Check for one of two things:
          # 1) a unit being dumped (e.g. a finding from a regular fuzz run)
          # 2) a nonzero return code plus a "Running: [foo]" message (which
          # indicates this is a *reproducer* run that has successfully crashed)
          repro_match = repro_pattern.search(line)
          match = mutation_pattern.search(line)
          if match or (repro_match and retcode):
            if pid <= 0 and guess_pid:
              pid = self._guess_pid()
            if pid > 0:
              raw = self._dump_log(['--pid', str(pid)])
              sym = self.host.symbolize(raw)
              tmp.write(b'\n'.join(sym))
              tmp.write(b'\n')

          # Check for an artifact being reported.
          match = artifact_pattern.search(line)
          if match:
            artifacts.append(match.group(1))

          # Echo the line
          tmp.write(line)

    # Clusterfuzz's stack analyzer expects the
    # `==[num]== ERROR: [SanitizerName]: [failure type]` line
    # to occur *before* the stacktrace, so make a new tempfile
    # where we insert that line at the top.
    # TODO(flowerhack): Change the log output in Fuchsia itself, s.t. the
    # ordering is correct the *first* time, and we won't have to do this
    # fix-up-the-logs dance!
    with open(logfile + '.tmp', 'rb') as tmp:
      with open(logfile, 'wb') as final:
        if line_with_crash_message:
          final.write(line_with_crash_message)

        shutil.copyfileobj(tmp, final)

    os.remove(logfile + '.tmp')
    return artifacts

  def _scp(self, srcs, dst):
    """Copies `src` to `dst`.

    Don't call directly; use `fetch` or `store` instead.`

    Args:
      srcs: Local or remote paths to copy from.
      dst: Local or remote path to copy to.
    """
    args = self.get_ssh_cmd(['scp'] + srcs + [dst])
    p = self.host.create_process(args)
    p.call()

  def fetch(self, data_src, host_dst):
    """Copies `data_src` on the target to `host_dst` on the host."""
    if not os.path.isdir(host_dst):
      raise ValueError(host_dst + ' is not a directory')
    self._scp(['[{}]:{}'.format(self._addr, data_src)], host_dst)

  def store(self, host_src, data_dst):
    """Copies `host_src` on the host to `data_dst` on the target."""
    self.ssh(['mkdir', '-p', data_dst])
    srcs = glob.glob(host_src)
    if not srcs:
      return
    self._scp(srcs, '[{}]:{}'.format(self._addr, data_dst))
