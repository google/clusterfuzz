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

#===- lib/asan/scripts/asan_symbolize.py -----------------------------------===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

#
# This file has local modifications needed for ClusterFuzz project.
#

# Disable all pylint warnings/errors as this is based on external code.
# pylint: disable-all

import os
import re
import six
import subprocess
import sys

from base import utils
from google_cloud_utils import storage
from metrics import logs
from platforms.android import adb
from platforms.android import fetch_artifact
from platforms.android import settings
from platforms.android import symbols_downloader
from system import archive
from system import environment
from system import shell

try:
  import pty
  import termios
except ImportError:
  # Applies only on unix platforms.
  pass

stack_inlining = 'false'
llvm_symbolizer_path = ''
pipes = []
symbolizers = {}


class LineBuffered(object):
  """Disable buffering on a file object."""

  def __init__(self, stream):
    self.stream = stream

  def write(self, data):
    self.stream.write(data)
    if '\n' in data:
      self.stream.flush()

  def __getattr__(self, attr):
    return getattr(self.stream, attr)


# Construct a path to the .dSYM bundle for the given binary.
# There are three possible cases for binary location in Chromium:
# 1. The binary is a standalone executable or dynamic library in the product
#    dir, the debug info is in "binary.dSYM" in the product dir.
# 2. The binary is a standalone framework or .app bundle, the debug info is in
#    "Framework.dSYM" or "App.dSYM" in the product dir.
# 3. The binary is a framework or an .app bundle within another .app bundle
#    (e.g. Outer.app/Contents/Versions/1.2.3.4/Inner.app), and the debug info
#    is in Inner.dSYM in the product dir.
# The first case is handled by llvm-symbolizer, so we only need to construct
# .dSYM paths for .app bundles and frameworks.
# We're assuming that there're no more than two nested bundles in the binary
# path. Only one of these bundles may be a framework and frameworks cannot
# contain other bundles.
def chrome_dsym_hints(binary):
  """Construct a path to the .dSYM bundle for the given binary.
  There are three possible cases for binary location in Chromium:
  1. The binary is a standalone executable or dynamic library in the product
     dir, the debug info is in "binary.dSYM" in the product dir.
  2. The binary is a standalone framework or .app bundle, the debug info is in
     "Framework.framework.dSYM" or "App.app.dSYM" in the product dir.
  3. The binary is a framework or an .app bundle within another .app bundle
     (e.g. Outer.app/Contents/Versions/1.2.3.4/Inner.app), and the debug info
     is in Inner.app.dSYM in the product dir.
  The first case is handled by llvm-symbolizer, so we only need to construct
  .dSYM paths for .app bundles and frameworks."""
  path_parts = binary.split(os.path.sep)
  app_positions = []
  framework_positions = []
  for index, part in enumerate(path_parts):
    if part.endswith('.app'):
      app_positions.append(index)
    elif part.endswith('.framework'):
      framework_positions.append(index)

  bundle_positions = app_positions + framework_positions
  if len(bundle_positions) == 0:
    # Case 1: this is a standalone executable or dylib.
    return []

  # Cases 2 and 3. The outermost bundle (which is the only bundle in the case 2)
  # is located in the product dir.
  bundle_positions.sort()
  outermost_bundle = bundle_positions[0]
  product_dir = path_parts[:outermost_bundle]
  # In case 2 this is the same as |outermost_bundle|.
  innermost_bundle = bundle_positions[-1]
  innermost_bundle_dir = path_parts[innermost_bundle]
  innermost_bundle_dir = utils.strip_from_right(innermost_bundle_dir, '.app')
  innermost_bundle_dir = utils.strip_from_right(innermost_bundle_dir,
                                                '.framework')
  dsym_path = product_dir + [innermost_bundle_dir]
  result = '%s.dSYM' % os.path.sep.join(dsym_path)
  return [result]


def disable_buffering():
  """Make this process and child processes stdout unbuffered."""
  os.environ['PYTHONUNBUFFERED'] = '1'

  if not isinstance(sys.stdout, LineBuffered):
    # Don't wrap sys.stdout if it is already wrapped.
    # See https://github.com/google/clusterfuzz/issues/234 for why.
    # Since sys.stdout is a C++ object, it's impossible to do sys.stdout.write =
    # lambda...
    sys.stdout = LineBuffered(sys.stdout)


def fix_filename(file_name):
  """Clean up the filename, nulls out tool specific ones."""
  file_name = re.sub('.*asan_[a-z_]*.cc:[0-9]*', '_asan_rtl_', file_name)
  file_name = re.sub('.*crtstuff.c:0', '', file_name)
  file_name = re.sub(':0$', '', file_name)

  # If we don't have a file name, just bail out.
  if not file_name or file_name.startswith('??'):
    return ''

  return os.path.normpath(file_name)


def fix_function_name(function_name):
  """Clean up function name."""
  if function_name.startswith('??'):
    return ''

  return function_name


def get_stack_frame(binary, addr, function_name, file_name):
  """Return a stack frame entry."""
  # Cleanup file and function name.
  file_name = fix_filename(file_name)
  function_name = fix_function_name(function_name)

  # Check if we don't have any symbols at all. If yes, this is probably
  # a system library. In this case, just return the binary name.
  if not function_name and not file_name:
    return '%s in %s' % (addr, os.path.basename(binary))

  # We just have a file name. Probably running in global context.
  if not function_name:
    # Filter the filename to act as a function name.
    filtered_file_name = os.path.basename(file_name)
    return '%s in %s %s' % (addr, filtered_file_name, file_name)

  # Regular stack frame.
  return '%s in %s %s' % (addr, function_name, file_name)


def is_valid_arch(s):
  """Check if this is a valid supported architecture."""
  return s in [
      "i386", "x86_64", "x86_64h", "arm", "armv6", "armv7", "armv7s", "armv7k",
      "arm64", "powerpc64", "powerpc64le", "s390x", "s390"
  ]


def guess_arch(address):
  """Guess which architecture we're running on (32/64).
  10 = len('0x') + 8 hex digits."""
  if len(address) > 10:
    return 'x86_64'
  else:
    return 'i386'


class Symbolizer(object):

  def __init__(self):
    pass

  def symbolize(self, addr, binary, offset):
    """Symbolize the given address (pair of binary and offset).

    Overriden in subclasses.
    Args:
        addr: virtual address of an instruction.
        binary: path to executable/shared object containing this instruction.
        offset: instruction offset in the @binary.
    Returns:
        list of strings (one string for each inlined frame) describing
        the code locations for this instruction (that is, function name, file
        name, line and column numbers).
    """
    return None


class LLVMSymbolizer(Symbolizer):

  def __init__(self, symbolizer_path, default_arch, system, dsym_hints=[]):
    super(LLVMSymbolizer, self).__init__()
    self.symbolizer_path = symbolizer_path
    self.default_arch = default_arch
    self.system = system
    self.dsym_hints = dsym_hints
    self.pipe = self.open_llvm_symbolizer()

  def open_llvm_symbolizer(self):
    if not os.path.exists(self.symbolizer_path):
      return None

    # Setup symbolizer command line.
    cmd = [
        self.symbolizer_path,
        '--default-arch=%s' % self.default_arch,
        '--demangle',
        '--functions=linkage',
        '--inlining=%s' % stack_inlining,
    ]
    if self.system == 'darwin':
      for hint in self.dsym_hints:
        cmd.append('--dsym-hint=%s' % hint)

    # Set LD_LIBRARY_PATH to use the right libstdc++.
    env_copy = environment.copy()
    env_copy['LD_LIBRARY_PATH'] = os.path.dirname(self.symbolizer_path)

    # FIXME: Since we are not using process_handler.run_process here, we can run
    # into issues with unicode environment variable and values. Add this
    # explicit hack to convert these into strings.
    env_copy = {str(key): str(value) for key, value in six.iteritems(env_copy)}

    # Run the symbolizer.
    pipe = subprocess.Popen(
        cmd, env=env_copy, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    global pipes
    pipes.append(pipe)

    return pipe

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if not binary.strip():
      return ['%s in' % addr]

    result = []
    try:
      symbolizer_input = '"%s" %s' % (binary, offset)
      self.pipe.stdin.write(symbolizer_input.encode('utf-8') + b'\n')
      self.pipe.stdin.flush()
      while True:
        function_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
        if not function_name:
          break

        file_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
        result.append(get_stack_frame(binary, addr, function_name, file_name))

    except Exception:
      logs.log_error('Symbolization using llvm-symbolizer failed for: "%s".' %
                     symbolizer_input)
      result = []
    if not result:
      result = None
    return result


def LLVMSymbolizerFactory(system, default_arch, dsym_hints=[]):
  return LLVMSymbolizer(llvm_symbolizer_path, default_arch, system, dsym_hints)


class Addr2LineSymbolizer(Symbolizer):

  def __init__(self, binary):
    super(Addr2LineSymbolizer, self).__init__()
    self.binary = binary
    self.pipe = self.open_addr2line()

  def open_addr2line(self):
    cmd = ['addr2line', '--demangle', '-f', '-e', self.binary]
    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    global pipes
    pipes.append(pipe)
    return pipe

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if self.binary != binary:
      return None
    if not binary.strip():
      return ['%s in' % addr]

    try:
      symbolizer_input = str(offset).encode('utf-8')
      self.pipe.stdin.write(symbolizer_input + b'\n')
      self.pipe.stdin.flush()
      function_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
      file_name = self.pipe.stdout.readline().rstrip().decode('utf-8')
    except Exception:
      logs.log_error('Symbolization using addr2line failed for: "%s %s".' %
                     (binary, str(offset)))
      function_name = ''
      file_name = ''

    return [get_stack_frame(binary, addr, function_name, file_name)]


class UnbufferedLineConverter(object):
  """Wrap a child process that responds to each line of input with one line of output.

  Uses pty to trick the child into providing unbuffered output.
  """

  def __init__(self, args, close_stderr=False):
    pid, fd = pty.fork()
    if pid == 0:
      # We're the child. Transfer control to command.
      if close_stderr:
        dev_null = os.open('/dev/null', 0)
        os.dup2(dev_null, 2)
      os.execvp(args[0], args)
    else:
      # Disable echoing.
      attr = termios.tcgetattr(fd)
      attr[3] = attr[3] & ~termios.ECHO
      termios.tcsetattr(fd, termios.TCSANOW, attr)
      # Set up a file()-like interface to the child process
      self.r = os.fdopen(fd, 'r', 1)
      self.w = os.fdopen(os.dup(fd), 'w', 1)

  def convert(self, line):
    self.w.write(line + '\n')
    return self.readline()

  def readline(self):
    return self.r.readline().rstrip()


class DarwinSymbolizer(Symbolizer):

  def __init__(self, addr, binary, arch):
    super(DarwinSymbolizer, self).__init__()
    self.binary = binary
    self.arch = arch
    self.open_atos()

  def open_atos(self):
    cmdline = ['atos', '-o', self.binary, '-arch', self.arch]
    self.atos = UnbufferedLineConverter(cmdline, close_stderr=True)

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    if self.binary != binary:
      return None

    try:
      atos_line = self.atos.convert('0x%x' % int(offset, 16))
      while 'got symbolicator for' in atos_line:
        atos_line = self.atos.readline()
      # A well-formed atos response looks like this:
      #   foo(type1, type2) (in object.name) (filename.cc:80)
      match = re.match('^(.*) \(in (.*)\) \((.*:\d*)\)$', atos_line)
      if match:
        function_name = match.group(1)
        function_name = re.sub('\(.*?\)', '', function_name)
        file_name = match.group(3)
        return [get_stack_frame(binary, addr, function_name, file_name)]
      else:
        return ['%s in %s' % (addr, atos_line)]
    except Exception:
      logs.log_error('Symbolization using atos failed for: "%s %s".' %
                     (binary, str(offset)))
      return ['{} ({}:{}+{})'.format(addr, binary, self.arch, offset)]


# Chain several symbolizers so that if one symbolizer fails, we fall back
# to the next symbolizer in chain.
class ChainSymbolizer(Symbolizer):

  def __init__(self, symbolizer_list):
    super(ChainSymbolizer, self).__init__()
    self.symbolizer_list = symbolizer_list

  def symbolize(self, addr, binary, offset):
    """Overrides Symbolizer.symbolize."""
    for symbolizer in self.symbolizer_list:
      if symbolizer:
        result = symbolizer.symbolize(addr, binary, offset)
        if result:
          return result
    return None

  def append_symbolizer(self, symbolizer):
    self.symbolizer_list.append(symbolizer)


def SystemSymbolizerFactory(system, addr, binary, arch):
  if system == 'darwin':
    return DarwinSymbolizer(addr, binary, arch)
  elif system.startswith('linux'):
    return Addr2LineSymbolizer(binary)


class SymbolizationLoop(object):

  def __init__(self, binary_path_filter=None, dsym_hint_producer=None):
    # Used by clients who may want to supply a different binary name.
    # E.g. in Chrome several binaries may share a single .dSYM.
    self.binary_path_filter = binary_path_filter
    self.dsym_hint_producer = dsym_hint_producer
    self.system = sys.platform
    self.llvm_symbolizers = {}
    self.last_llvm_symbolizer = None
    self.dsym_hints = set([])

  def symbolize_address(self, addr, binary, offset, arch):
    # On non-Darwin (i.e. on platforms without .dSYM debug info) always use
    # a single symbolizer binary.
    # On Darwin, if the dsym hint producer is present:
    #  1. check whether we've seen this binary already; if so,
    #     use |llvm_symbolizers[binary]|, which has already loaded the debug
    #     info for this binary (might not be the case for
    #     |last_llvm_symbolizer|);
    #  2. otherwise check if we've seen all the hints for this binary already;
    #     if so, reuse |last_llvm_symbolizer| which has the full set of hints;
    #  3. otherwise create a new symbolizer and pass all currently known
    #     .dSYM hints to it.
    if not binary in self.llvm_symbolizers:
      use_new_symbolizer = True
      if self.system == 'darwin' and self.dsym_hint_producer:
        dsym_hints_for_binary = set(self.dsym_hint_producer(binary))
        use_new_symbolizer = bool(dsym_hints_for_binary - self.dsym_hints)
        self.dsym_hints |= dsym_hints_for_binary
      if self.last_llvm_symbolizer and not use_new_symbolizer:
        self.llvm_symbolizers[binary] = self.last_llvm_symbolizer
      else:
        self.last_llvm_symbolizer = LLVMSymbolizerFactory(
            self.system, arch, self.dsym_hints)
        self.llvm_symbolizers[binary] = self.last_llvm_symbolizer

    # Use the chain of symbolizers:
    # LLVM symbolizer -> addr2line/atos
    # (fall back to next symbolizer if the previous one fails).
    if not binary in symbolizers:
      symbolizers[binary] = ChainSymbolizer([self.llvm_symbolizers[binary]])
    result = symbolizers[binary].symbolize(addr, binary, offset)
    if result is None:
      # Initialize system symbolizer only if other symbolizers failed.
      symbolizers[binary].append_symbolizer(
          SystemSymbolizerFactory(self.system, addr, binary, arch))
      result = symbolizers[binary].symbolize(addr, binary, offset)
    # The system symbolizer must produce some result.
    assert result
    return result

  def process_stacktrace(self, unsymbolized_crash_stacktrace):
    self.frame_no = 0
    symbolized_crash_stacktrace = u''
    for line in unsymbolized_crash_stacktrace.splitlines():
      self.current_line = utils.decode_to_unicode(line.rstrip())
      # 0 0x7f6e35cf2e45  (/blah/foo.so+0x11fe45)
      stack_trace_line_format = (
          '^( *#([0-9]+) *)(0x[0-9a-f]+) *\(([^+]*)\+(0x[0-9a-f]+)\)')
      match = re.match(stack_trace_line_format, line)
      if not match:
        symbolized_crash_stacktrace += u'%s\n' % self.current_line
        continue
      _, frameno_str, addr, binary, offset = match.groups()
      arch = ""
      # Arch can be embedded in the filename, e.g.: "libabc.dylib:x86_64h"
      colon_pos = binary.rfind(":")
      if colon_pos != -1:
        maybe_arch = binary[colon_pos + 1:]
        if is_valid_arch(maybe_arch):
          arch = maybe_arch
          binary = binary[0:colon_pos]
      if arch == "":
        arch = guess_arch(addr)
      if frameno_str == '0':
        # Assume that frame #0 is the first frame of new stack trace.
        self.frame_no = 0
      original_binary = binary
      if self.binary_path_filter:
        binary = self.binary_path_filter(binary)
      symbolized_line = self.symbolize_address(addr, binary, offset, arch)
      if not symbolized_line:
        if original_binary != binary:
          symbolized_line = self.symbolize_address(addr, original_binary,
                                                   offset, arch)

      if not symbolized_line:
        symbolized_crash_stacktrace += u'%s\n' % self.current_line
      else:
        for symbolized_frame in symbolized_line:
          symbolized_crash_stacktrace += u'%s\n' % (
              '    #' + str(self.frame_no) + ' ' + symbolized_frame.rstrip())
          self.frame_no += 1

    # Close any left-over open pipes.
    for pipe in pipes:
      pipe.stdin.close()
      pipe.stdout.close()
      pipe.kill()

    return symbolized_crash_stacktrace


def filter_binary_path(binary_path):
  """Filters binary path to provide a local copy."""
  if environment.is_android():
    # Skip symbolization when running it on bad entries like [stack:XYZ].
    if not binary_path.startswith('/') or '(deleted)' in binary_path:
      return ''

    # Initialize some helper variables.
    binary_filename = os.path.basename(binary_path)
    build_directory = environment.get_value('BUILD_DIR')
    symbols_directory = environment.get_value('SYMBOLS_DIR')

    # Try to find the library in the build directory first.
    local_binary_path = utils.find_binary_path(build_directory, binary_path)
    if local_binary_path:
      return local_binary_path

    # We didn't find the library locally in the build directory.
    # Try finding the library in the local system library cache.
    symbols_downloader.download_system_symbols_if_needed(symbols_directory)
    local_binary_path = utils.find_binary_path(symbols_directory, binary_path)
    if local_binary_path:
      return local_binary_path

    # Try pulling in the binary directly from the device into the
    # system library cache directory.
    local_binary_path = os.path.join(symbols_directory, binary_filename)
    adb.run_command('pull %s %s' % (binary_path, local_binary_path))
    if os.path.exists(local_binary_path):
      return local_binary_path

    # Unable to find library.
    logs.log_error('Unable to find library %s for symbolization.' % binary_path)
    return ''

  if environment.platform() == 'CHROMEOS':
    # FIXME: Add code to pull binaries from ChromeOS device.
    return binary_path

  if environment.is_chromeos_system_job():
    # This conditional is True for ChromeOS system fuzzers that are running on
    # Linux. Ensure that the binary is always looked for in the chroot and not
    # in system directories.
    build_dir = environment.get_value('BUILD_DIR')
    if not binary_path.startswith(build_dir):
      # Fixup path so |binary_path| points to a binary in the chroot (probably
      # a system library).
      return os.path.join(build_dir, binary_path[1:])

  # For Linux and Mac, the binary exists locally. No work to do,
  # just return the same binary path.
  return binary_path


def symbolize_stacktrace(unsymbolized_crash_stacktrace,
                         enable_inline_frames=True):
  """Symbolize a crash stacktrace."""
  if environment.is_trusted_host():
    from bot.untrusted_runner import symbolize_host
    return symbolize_host.symbolize_stacktrace(unsymbolized_crash_stacktrace,
                                               enable_inline_frames)

  platform = environment.platform()
  if platform == 'WINDOWS':
    # Windows Clang ASAN provides symbolized stacktraces anyway.
    return unsymbolized_crash_stacktrace

  if platform == 'FUCHSIA':
    # Fuchsia Clang ASAN provides symbolized stacktraces anyway.
    return unsymbolized_crash_stacktrace

  # FIXME: Support symbolization on ChromeOS device.
  if platform == 'CHROMEOS':
    return unsymbolized_crash_stacktrace

  # Initialize variables.
  global llvm_symbolizer_path
  global pipes
  global stack_inlining
  global symbolizers
  pipes = []
  stack_inlining = str(enable_inline_frames).lower()
  symbolizers = {}

  # Make sure we have a llvm symbolizer for this platform.
  llvm_symbolizer_path = environment.get_llvm_symbolizer_path()
  if not llvm_symbolizer_path:
    return unsymbolized_crash_stacktrace

  # Disable buffering for stdout.
  disable_buffering()

  loop = SymbolizationLoop(
      binary_path_filter=filter_binary_path,
      dsym_hint_producer=chrome_dsym_hints)
  symbolized_crash_stacktrace = loop.process_stacktrace(
      unsymbolized_crash_stacktrace)

  return symbolized_crash_stacktrace
