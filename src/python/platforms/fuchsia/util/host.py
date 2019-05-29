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
"""Utilities for handling Fuchsia hosts."""

from builtins import object
from builtins import str
import json
import os
import subprocess


class Host(object):
  """Represents a local system with a build of Fuchsia.

    This class abstracts the details of various repository, tool, and build
    paths, as well as details about the host architecture and platform.

    Attributes:
      fuzzers:   The fuzzer binaries available in the current Fuchsia image
      build_dir: The build output directory, if present.
  """

  class ConfigError(RuntimeError):
    """Indicates the host is not configured for building Fuchsia."""
    pass

  @classmethod
  def from_build(cls):
    """Uses a local build directory to configure a Host object from it."""
    host = Host()
    host.set_build_dir(host.find_build_dir())
    return host

  @classmethod
  def from_dir(cls, this_dir):
    host = Host()
    host.set_build_dir(this_dir)
    return host

  @classmethod
  def join(cls, *segments):
    """Creates a source tree path."""
    fuchsia = os.getenv('FUCHSIA_DIR')
    if not fuchsia:
      raise Host.ConfigError('Unable to find FUCHSIA_DIR; have you `fx set`?')
    return os.path.join(fuchsia, *segments)

  def __init__(self):
    self._ids = None
    self._llvm_symbolizer = None
    self._symbolizer_exec = None
    self._platform = None
    self._zxtools = None
    self.fuzzers = []
    self.build_dir = None

  @classmethod
  def find_build_dir(cls):
    """Examines the source tree to locate a build directory."""
    build_dir = Host.join('.fx-build-dir')
    if not os.path.exists(build_dir):
      raise Host.ConfigError('Unable to find .fx-build-dir; have you `fx set`?')
    with open(build_dir, 'r') as f:
      return Host.join(f.read().strip())

  def set_build_ids(self, build_ids):
    """Sets the build IDs used to symbolize logs."""
    if not os.path.exists(build_ids):
      raise Host.ConfigError('Unable to find builds IDs.')
    self._ids = build_ids

  def set_zxtools(self, zxtools):
    """Sets the location of the Zircon host tools directory."""
    if not os.path.isdir(zxtools):
      raise Host.ConfigError('Unable to find Zircon host tools.')
    self._zxtools = zxtools

  def set_platform(self, platform):
    """Sets the platform used for host OS-specific behavior."""
    if not os.path.isdir(Host.join('buildtools', platform)):
      raise Host.ConfigError('Unsupported host platform: ' + platform +
                             ' (full path): ' + str(os.getenv('FUCHSIA_DIR')))
    self._platform = platform

  def set_symbolizer(self, executable, symbolizer):
    """Sets the paths to both the wrapper and LLVM symbolizers."""
    if not os.path.exists(executable) or not os.access(executable, os.X_OK):
      raise Host.ConfigError('Invalid symbolize binary: ' + executable)
    if not os.path.exists(symbolizer) or not os.access(symbolizer, os.X_OK):
      raise Host.ConfigError('Invalid LLVM symbolizer: ' + symbolizer)
    self._symbolizer_exec = executable
    self._llvm_symbolizer = symbolizer

  def set_fuzzers_json(self, json_file):
    """Sets the path to the build file with fuzzer metadata."""
    if not os.path.exists(json_file):
      raise Host.ConfigError('Unable to find list of fuzzers.')
    self.fuzzers = []
    with open(json_file) as f:
      fuzz_specs = json.load(f)
    for fuzz_spec in fuzz_specs:
      pkg = fuzz_spec['fuzzers_package']
      for tgt in fuzz_spec['fuzzers']:
        self.fuzzers.append((pkg, tgt))

  def set_build_dir(self, build_dir):
    """Configure the host using data from a build directory."""
    self.set_build_ids(Host.join(build_dir, 'ids.txt'))
    self.set_zxtools(Host.join(build_dir + '.zircon', 'tools'))
    platform = 'mac-x64' if os.uname()[0] == 'Darwin' else 'linux-x64'
    self.set_platform(platform)
    self.set_symbolizer(
        Host.join('zircon', 'prebuilt', 'downloads', 'symbolize'),  # change
        Host.join('buildtools', platform, 'clang', 'bin', 'llvm-symbolizer'))
    json_file = Host.join(build_dir, 'fuzzers.json')
    # fuzzers.json isn't emitted in release builds
    if os.path.exists(json_file):
      self.set_fuzzers_json(json_file)
    self.build_dir = build_dir

  def zircon_tool(self, cmd, logfile=None):  # pylint: disable=inconsistent-return-statement
    """Executes a tool found in the ZIRCON_BUILD_DIR."""
    if not self._zxtools:
      raise Host.ConfigError('Zircon host tools unavailable.')
    if not os.path.isabs(cmd[0]):
      cmd[0] = os.path.join(self._zxtools, cmd[0])
    if not os.path.exists(cmd[0]):
      raise Host.ConfigError('Unable to find Zircon host tool: ' + cmd[0])
    if logfile:
      return subprocess.Popen(cmd, stdout=logfile, stderr=subprocess.STDOUT)
    return subprocess.check_output(cmd).strip()

  def killall(self, process):
    """ Invokes killall on the process name."""
    subprocess.call(['killall', process])

  def symbolize(self, log_in, log_out):
    """Symbolizes backtraces in a log file using the current build."""
    if not self._symbolizer_exec:
      raise Host.ConfigError('Symbolizer executable not set.')
    if not self._ids:
      raise Host.ConfigError('Build IDs not set.')
    if not self._llvm_symbolizer:
      raise Host.ConfigError('LLVM symbolizer not set.')
    subprocess.check_call(
        [
            self._symbolizer_exec, '-ids-rel', '-ids', self._ids,
            '-llvm-symbolizer', self._llvm_symbolizer
        ],
        stdin=log_in,
        stdout=log_out)

  def notify_user(self, title, body):
    """Displays a message to the user in a platform-specific way"""
    if not self._platform:
      return
    elif self._platform == 'mac-x64':
      subprocess.call([
          'osascript', '-e',
          'display notification "' + body + '" with title "' + title + '"'
      ])
    elif subprocess.call(['which', 'notify-send']) == 0:
      subprocess.call(['notify-send', title, body])
    else:
      subprocess.call(['wall', title + '; ' + body])

  def snapshot(self):
    integration = Host.join('integration')
    if not os.path.isdir(integration):
      raise Host.ConfigError('Missing integration repo.')
    return subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=integration).strip()
