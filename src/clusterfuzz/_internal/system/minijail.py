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
"""Running processes with minijail."""

from collections.abc import Sequence
import os
import shutil
import signal
import subprocess
import tempfile
import types
from typing import Any
from typing import cast
from typing import IO
from typing import NamedTuple
from typing import Self

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell


def _get_minijail_path() -> str:
  """Get the minijail path.

  Returns:
    The path to the minijail binary.
  """
  return os.path.join(environment.get_platform_resources_directory(),
                      'minijail0')


def _get_minijail_user_namespace_args() -> list[str]:
  """Get user namespace arguments for minijail.

  Returns:
    A list representing arguments to minijail.
  """
  arguments = ['-U']  # User namespace option

  # root (uid 0 in namespace) -> USER.
  # The reason for this is that minijail does setresuid(0, 0, 0) before doing a
  # chroot, which means uid 0 needs access to the chroot dir (owned by USER).
  #
  # Note that we also run fuzzers as uid 0 (but with no capabilities in
  # permitted/effective/inherited sets which *should* mean there's nothing
  # special about it). This is because the uid running the fuzzer also needs
  # access to things owned by USER (fuzzer binaries, supporting files), and USER
  # can only be mapped once.
  uid_map = [
      f'0 {os.getuid()} 1',
  ]
  arguments.extend(['-m', ','.join(uid_map)])

  return arguments


def _create_chroot_dir(base_dir: str | None) -> str:
  """Create dir for chroot."""
  return tempfile.mkdtemp(dir=base_dir)


def _create_tmp_mount(base_dir: str | None) -> str:
  """Create a tmp mount in base_dir."""
  return tempfile.mkdtemp(dir=base_dir)


class ChrootBinding(NamedTuple):
  src_path: str
  dest_path: str
  writeable: bool


class MinijailChroot:
  """Minijail environment."""

  # Default directories to bind from host to chroot. Mostly library directories.
  DEFAULT_BINDINGS: list[str] = [
      '/lib',
      '/lib32',
      '/lib64',
      '/usr/lib',
      '/usr/lib32',
  ]

  _chroot_dir: str
  _tmp_mount: str
  _bindings: list[ChrootBinding]

  def __init__(
      self,
      base_dir: str | None = None,
      bindings: Sequence[ChrootBinding] | None = None,
      use_existing_base: bool = False,
  ) -> None:
    """Inits the MinijailChroot.

    Args:
      base_dir: The directory to create the chroot directory in.
      bindings: Additional bindings (ChrootBinding).
      use_existing_base: use existing base_dir or create a new one.
    """
    if not use_existing_base:
      self._chroot_dir = _create_chroot_dir(base_dir=base_dir)
    else:
      self._chroot_dir = cast(str, base_dir)

    # Create /tmp, /proc directories.
    os.mkdir(os.path.join(self._chroot_dir, 'tmp'))
    os.mkdir(os.path.join(self._chroot_dir, 'proc'))

    # Create a /tmp binding.
    self._tmp_mount = _create_tmp_mount(base_dir=base_dir)
    self._bindings = [
        ChrootBinding(self._tmp_mount, '/tmp', True),
    ]

    self._create_devices()

    # Default dirs. Read-only.
    for directory in self.DEFAULT_BINDINGS:
      if not os.path.exists(directory):
        # Ignore default dirs that don't exist. May happen because of different
        # directory layouts.
        continue

      self.add_binding(ChrootBinding(directory, directory, False))

    if not bindings:
      return

    # Additional bind dirs.
    for binding in bindings:
      self.add_binding(binding)

  def _mknod(self, path: str, file_type: str, major: int, minor: int) -> None:
    """Creates a special file."""
    try:
      with open(os.devnull) as devnull:
        subprocess.check_output(
            [
                'sudo', '-S', 'mknod', '-m', '666', path, file_type,
                str(major),
                str(minor)
            ],
            stdin=devnull,
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      logs.error('Failed to call mknod.', output=e.output)

  def _create_devices(self) -> None:
    """Create /dev/null, /dev/random, /dev/urandom, and /dev/shm."""
    dev_dir = os.path.join(self._chroot_dir, 'dev')
    os.mkdir(dev_dir)
    self._mknod(os.path.join(dev_dir, 'null'), 'c', 1, 3)
    self._mknod(os.path.join(dev_dir, 'random'), 'c', 1, 8)
    self._mknod(os.path.join(dev_dir, 'urandom'), 'c', 1, 9)
    os.mkdir(os.path.join(dev_dir, 'shm'))

  def _makedirs(self, directory: str) -> None:
    """Create directories for binding in chroot.

    Args:
      directory: The absolute path to the directory target in the chroot.
    """
    if directory[0] == '/':
      directory = directory[1:]

    shell.create_directory(
        os.path.join(self._chroot_dir, directory), create_intermediates=True)

  @property
  def bindings(self) -> list[ChrootBinding]:
    return self._bindings

  @property
  def directory(self) -> str:
    return self._chroot_dir

  @property
  def tmp_directory(self) -> str:
    return self._tmp_mount

  def add_binding(self, binding: ChrootBinding) -> None:
    """Adds a directory to be bound to the chroot.

    Args:
      binding: A ChrootBinding.
    """
    if binding in self._bindings:
      return

    self._makedirs(binding.dest_path)
    self._bindings.append(binding)

  def get_binding(self, src_path: str) -> ChrootBinding | None:
    """Returns binding for src_path.

    Args:
      src_path: The source directory path.

    Returns:
      A ChrootBinding with the same src_path.
    """
    return next((x for x in self._bindings
                 if os.path.abspath(x.src_path) == os.path.abspath(src_path)),
                None)

  def close(self) -> None:
    """Cleanup the chroot environment."""
    shutil.rmtree(self._chroot_dir, ignore_errors=True)
    shutil.rmtree(self._tmp_mount, ignore_errors=True)

  def remove_binding(self, binding: ChrootBinding) -> None:
    """Remove a directory bound to the chroot. This function does not delete the
    given directory.

    Args:
      binding: A ChrootBinding.
    """
    self._bindings.remove(binding)

  def __enter__(self) -> Self:
    """Context manager override."""
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_value: BaseException | None,
      traceback: types.TracebackType | None,
  ) -> None:
    """Context manager override."""
    self.close()


class ChromeOSChroot(MinijailChroot):
  """Minijail environment for ChromeOS fuzzers."""

  DEFAULT_BINDINGS: list[str] = []

  def __init__(
      self,
      chroot_dir: str,
      bindings: Sequence[ChrootBinding] | None = None,
  ) -> None:
    # Do clean up in case close() was not called.
    self.remove_created_dirs(chroot_dir)
    super().__init__(chroot_dir, bindings, use_existing_base=True)

  def remove_created_dirs(
      self,
      chroot_dir: str,
      minijail_created_dirs: Sequence[str] | None = None,
  ) -> None:
    if minijail_created_dirs is None:
      minijail_created_dirs = ['tmp', 'proc', 'dev']

    for directory in minijail_created_dirs:
      shell.remove_directory(os.path.join(chroot_dir, directory))

  def remove_binding(self, binding: ChrootBinding) -> None:
    """Overriden version of remove_binding that ensures the bound directory is
    removed. This is necessary because unlike in regular minijails, we do not
    delete the entire chroot directory."""
    abs_path = os.path.join(self._chroot_dir, binding.dest_path[1:])
    shell.remove_directory(abs_path)
    super().remove_binding(binding)

  def close(self) -> None:
    """Overrides MinijailChroot.close(). Closes the chroot environment. Does
    not delete the chroot directory."""
    for binding in self._bindings:
      self.remove_binding(binding)
    shutil.rmtree(self._tmp_mount, ignore_errors=True)


class MinijailChildProcess(new_process.ChildProcess):
  """Minijail child process."""

  _jailed_pid_file: IO[Any]

  def __init__(
      self,
      popen: subprocess.Popen,
      command: list[str],
      max_stdout_len: int | None,
      stdout_file: Any,
      jailed_pid_file: IO[Any],
  ) -> None:
    super().__init__(popen, command, max_stdout_len, stdout_file)
    self._jailed_pid_file = jailed_pid_file

  def terminate(self) -> None:
    """Send SIGTERM to the jailed process."""
    self._jailed_pid_file.seek(0)
    jailed_pid = int(self._jailed_pid_file.read())
    os.kill(jailed_pid, signal.SIGTERM)

  def kill(self) -> None:
    """Kill minijail and all child processes."""
    os.killpg(self.popen.pid, signal.SIGKILL)


class MinijailProcessRunner(new_process.ProcessRunner):
  """ProcessRunner wrapper for minijail."""

  MINIJAIL_ARGS: list[str] = [
      '-T',
      'static',  # don't use preload.
      '-c',
      '0',  # drop all capabilities.
      '-n',  # no_new_privs
      '-v',  # mount namespace
      '-p',  # PID namespace
      '-l',  # IPC namespace
      '-I',  # Run jailed process as init.
      '-k',
      'proc,/proc,proc,1'  # Mount procfs RO (1 == MS_RDONLY).
  ]

  PATH_ENVIRONMENT_VALUE: str = '/bin:/usr/bin'

  _chroot: MinijailChroot

  def __init__(
      self,
      chroot: MinijailChroot,
      executable_path: str,
      default_args: Sequence[str] | None = None,
  ) -> None:
    super().__init__(executable_path, default_args=default_args)
    self._chroot = chroot

  @property
  def chroot(self) -> MinijailChroot:
    return self._chroot

  def get_command(
      self,
      additional_args: Sequence[str] | None = None,
  ) -> list[str]:
    """ProcessRunner.get_command override to prepend minijail."""
    base_command = super().get_command(additional_args)
    command = [_get_minijail_path()]
    command.extend(_get_minijail_user_namespace_args())
    command.extend(self.MINIJAIL_ARGS)

    # Change root filesystem to the chroot directory. See pivot_root(2).
    command.extend(['-P', self._chroot.directory])

    # Bind dirs in chroot.
    for (directory, target, writeable) in self._chroot.bindings:
      command.extend(['-b', '%s,%s,%d' % (directory, target, int(writeable))])

    command.extend(base_command)
    return command

  def run(
      self,
      additional_args: Sequence[str] | None = None,
      max_stdout_len: int | None = None,
      extra_env: dict[str, str] | None = None,
      stdin: Any = subprocess.PIPE,
      stdout: Any = subprocess.PIPE,
      stderr: Any = subprocess.STDOUT,
      **popen_args: Any,
  ) -> MinijailChildProcess:
    """ProcessRunner.run override."""

    pid_file = tempfile.NamedTemporaryFile()
    command = self.get_command(additional_args)

    if stdout == subprocess.PIPE and max_stdout_len:
      stdout = tempfile.TemporaryFile()

    # Insert arguments to write jailed PID to a file.
    command.insert(1, '-f')
    command.insert(2, pid_file.name)

    passed_env = popen_args.pop('env', None)
    from clusterfuzz._internal.bot.untrusted_runner import \
        environment as untrusted_environment
    env = untrusted_environment.get_env_for_untrusted_process(passed_env)
    if extra_env is not None:
      env.update(extra_env)

    env['PATH'] = self.PATH_ENVIRONMENT_VALUE

    return MinijailChildProcess(
        subprocess.Popen(
            command,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            env=env,
            **popen_args),
        command,
        max_stdout_len=max_stdout_len,
        stdout_file=stdout,
        jailed_pid_file=pid_file)
