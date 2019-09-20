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
"""libFuzzer runners."""
from __future__ import print_function

from builtins import object
import copy
import os
import re
import shutil
import tempfile

from base import retry
from bot.fuzzers import engine_common
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.libFuzzer import constants
from platforms import fuchsia
from platforms.fuchsia.device import run_qemu_instance
from platforms.fuchsia.device import setup_qemu_instance
from platforms.fuchsia.device import setup_qemu_values
from platforms.fuchsia.util.device import Device
from platforms.fuchsia.util.fuzzer import Fuzzer
from platforms.fuchsia.util.host import Host
from system import environment
from system import minijail
from system import new_process
from system import shell

MAX_OUTPUT_LEN = 1 * 1024 * 1024  # 1 MB

# Regex to find testcase path from a crash.
CRASH_TESTCASE_REGEX = (r'.*Test unit written to\s*'
                        r'(.*(crash|oom|timeout|leak)-.*)')


class LibFuzzerException(Exception):
  """LibFuzzer exception."""


class LibFuzzerCommon(object):
  """Provides common libFuzzer functionality."""

  # Window of time for libFuzzer to exit gracefully before we KILL it.
  LIBFUZZER_CLEAN_EXIT_TIME = 10.0

  # Additional window of time for libFuzzer fork mode to exit gracefully.
  LIBFUZZER_FORK_MODE_CLEAN_EXIT_TIME = 100.0

  # Time to wait for SIGTERM handler.
  SIGTERM_WAIT_TIME = 10.0

  def __init__(self):
    pass

  def _normalize_artifact_prefix(self, artifact_prefix, sep=os.sep):
    if artifact_prefix.endswith(sep):
      return artifact_prefix

    return artifact_prefix + sep

  def get_testcase_path(self, log_lines):
    """Get testcase path from log lines."""
    for line in log_lines:
      match = re.match(CRASH_TESTCASE_REGEX, line)
      if match:
        return match.group(1)

    return None

  def analyze_dictionary(self,
                         dictionary_path,
                         corpus_directory,
                         analyze_timeout,
                         artifact_prefix=None,
                         additional_args=None):
    """Runs a dictionary analysis command.

    Args:
      dictionary_path: Path to a dictionary file to be passed to libFuzzer for
          the analysis.
      corpus_directory: Path to corpus directory to be passed to libFuzzer.
      analyze_timeout: The maximum time in seconds that libFuzzer is allowed to
          run for.
      artifact_prefix: The directory to store new fuzzing artifacts (crashes,
          timeouts, slow units)
      additional_args: A sequence of additional arguments to be passed to the
          executable.

    Returns:
      A process.ProcessResult.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    additional_args.append(constants.ANALYZE_DICT_ARGUMENT)
    additional_args.append(constants.DICT_FLAG + dictionary_path)

    if artifact_prefix:
      additional_args.append(
          '%s%s' % (constants.ARTIFACT_PREFIX_FLAG,
                    self._normalize_artifact_prefix(artifact_prefix)))

    additional_args.append(corpus_directory)
    return self.run_and_wait(
        additional_args=additional_args,
        timeout=analyze_timeout,
        max_stdout_len=MAX_OUTPUT_LEN)

  def get_max_total_time(self, timeout):
    """Calculate value of `-max_total_time=` argument to be passed to fuzzer.

    Args:
      timeout: The maximum time in seconds that libFuzzer is allowed to run for.
    """
    timeout = timeout - self.LIBFUZZER_CLEAN_EXIT_TIME - self.SIGTERM_WAIT_TIME
    return int(timeout)

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """Running fuzzing command.

    Args:
      corpus_directories: List of corpus directory paths to be passed to
          libFuzzer.
      fuzz_timeout: The maximum time in seconds that libFuzzer is allowed to run
          for.
      artifact_prefix: The directory to store new fuzzing artifacts (crashes,
          timeouts, slow units)
      additional_args: A sequence of additional arguments to be passed to the
          executable.
      extra_env: A dictionary containing environment variables and their values.
          These will be added to the environment of the new process.

    Returns:
      A process.ProcessResult.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    max_total_time = self.get_max_total_time(fuzz_timeout)
    if any(arg.startswith(constants.FORK_FLAG) for arg in additional_args):
      max_total_time -= self.LIBFUZZER_FORK_MODE_CLEAN_EXIT_TIME
    assert max_total_time > 0

    # Old libFuzzer jobs specify -artifact_prefix through additional_args
    if artifact_prefix:
      additional_args.append(
          '%s%s' % (constants.ARTIFACT_PREFIX_FLAG,
                    self._normalize_artifact_prefix(artifact_prefix)))

    additional_args.extend([
        '%s%d' % (constants.MAX_TOTAL_TIME_FLAG, max_total_time),
        constants.PRINT_FINAL_STATS_ARGUMENT,
        # FIXME: temporarily disabled due to a lack of crash information in
        # output.
        # '-close_fd_mask=3',
    ])

    additional_args.extend(corpus_directories)
    return self.run_and_wait(
        additional_args=additional_args,
        timeout=fuzz_timeout - self.SIGTERM_WAIT_TIME,
        terminate_before_kill=True,
        terminate_wait_time=self.SIGTERM_WAIT_TIME,
        max_stdout_len=MAX_OUTPUT_LEN,
        extra_env=extra_env)

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None):
    """Runs a corpus merge command.

    Args:
      corpus_directories: List of corpus directory paths to be passed to
          libFuzzer.
      merge_timeout: The maximum time in seconds that libFuzzer is allowed to
          run for.
      artifact_prefix: The directory to store new fuzzing artifacts (crashes,
          timeouts, slow units)
      tmp_dir: Temporary directory that merge uses to write progress.
      additional_args: A sequence of additional arguments to be passed to the
          executable.

    Returns:
      A process.ProcessResult.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    additional_args.append(constants.MERGE_ARGUMENT)
    if artifact_prefix:
      additional_args.append(
          '%s%s' % (constants.ARTIFACT_PREFIX_FLAG,
                    self._normalize_artifact_prefix(artifact_prefix)))

    extra_env = {}
    if tmp_dir:
      extra_env['TMPDIR'] = tmp_dir

    additional_args.extend(corpus_directories)
    return self.run_and_wait(
        additional_args=additional_args,
        timeout=merge_timeout,
        max_stdout_len=MAX_OUTPUT_LEN,
        extra_env=extra_env)

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """Runs a single testcase.

    Args:
      testcase_path: Path to testcase to be run.
      timeout: Timeout in seconds, or None.
      additional_args: A sequence of additional arguments to be passed to the
          executable.

    Returns:
      A process.ProcessResult.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    additional_args.append(testcase_path)

    return self.run_and_wait(
        additional_args=additional_args,
        timeout=timeout,
        max_stdout_len=MAX_OUTPUT_LEN)

  def minimize_crash(self,
                     testcase_path,
                     output_path,
                     timeout,
                     artifact_prefix=None,
                     additional_args=None):
    """Minimize crasher with libFuzzer.

    Args:
      testcase_path: Path to testcase to be run.
      timeout: Timeout in seconds, or None.
      output_path: Path to write the minimized output.
      additional_args: A sequence of additional arguments to be passed to the
          executable.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    # We do timeout / 2 here because libFuzzer uses max_total_time for
    # individual runs of the target and not for the entire minimization.
    # Internally, libFuzzer does 2 runs of the target every iteration. This is
    # the minimum for any results to be written at all.
    max_total_time = (timeout - self.LIBFUZZER_CLEAN_EXIT_TIME) // 2
    assert max_total_time > 0
    max_total_time_argument = '%s%d' % (constants.MAX_TOTAL_TIME_FLAG,
                                        max_total_time)

    additional_args.extend([
        constants.MINIMIZE_CRASH_ARGUMENT,
        max_total_time_argument,
        constants.EXACT_ARTIFACT_PATH_FLAG + output_path,
    ])

    if artifact_prefix:
      additional_args.append(constants.ARTIFACT_PREFIX_FLAG +
                             self._normalize_artifact_prefix(artifact_prefix))
    additional_args.append(testcase_path)

    return self.run_and_wait(
        additional_args=additional_args,
        timeout=timeout,
        max_stdout_len=MAX_OUTPUT_LEN)

  def cleanse_crash(self,
                    testcase_path,
                    output_path,
                    timeout,
                    artifact_prefix=None,
                    additional_args=None):
    """Cleanse crasher with libFuzzer. This attempts to remove non-essential
    bits of the testcase by replacing them with garbage.

    Args:
      testcase_path: Path to testcase to be run.
      timeout: Timeout in seconds, or None.
      output_path: Path to write the cleansed output.
      additional_args: A sequence of additional arguments to be passed to the
          executable.
    """
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    additional_args.extend([
        constants.CLEANSE_CRASH_ARGUMENT,
        constants.EXACT_ARTIFACT_PATH_FLAG + output_path,
    ])

    if artifact_prefix:
      additional_args.append(constants.ARTIFACT_PREFIX_FLAG +
                             self._normalize_artifact_prefix(artifact_prefix))
    additional_args.append(testcase_path)

    return self.run_and_wait(
        additional_args=additional_args,
        timeout=timeout,
        max_stdout_len=MAX_OUTPUT_LEN)


class LibFuzzerRunner(new_process.ProcessRunner, LibFuzzerCommon):
  """libFuzzer runner (when minijail is not used)."""

  def __init__(self, executable_path, default_args=None):
    """Inits the LibFuzzerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super(LibFuzzerRunner, self).__init__(
        executable_path=executable_path, default_args=default_args)

  def get_command(self, additional_args=None):
    """Process.get_command override."""
    base_command = super(LibFuzzerRunner,
                         self).get_command(additional_args=additional_args)

    return base_command

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """LibFuzzerCommon.fuzz override."""
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    return LibFuzzerCommon.fuzz(self, corpus_directories, fuzz_timeout,
                                artifact_prefix, additional_args, extra_env)


class FuchsiaQemuLibFuzzerRunner(new_process.ProcessRunner, LibFuzzerCommon):
  """libFuzzer runner (when Fuchsia is the target platform)."""

  FUCHSIA_BUILD_REL_PATH = os.path.join('build', 'out', 'default')

  SSH_RETRIES = 3
  SSH_WAIT = 3

  FUZZER_TEST_DATA_REL_PATH = os.path.join('test_data', 'fuzzing')

  def _setup_fuzzer_and_device(self):
    """ Build a Fuzzer object based on the QEMU values.
    Call this only after setup_qemu_values()"""
    fuchsia_pkey_path = environment.get_value('FUCHSIA_PKEY_PATH')
    fuchsia_portnum = environment.get_value('FUCHSIA_PORTNUM')
    fuchsia_resources_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
    if (not fuchsia_pkey_path or not fuchsia_portnum or
        not fuchsia_resources_dir):
      raise fuchsia.errors.FuchsiaConfigError(
          ('FUCHSIA_PKEY_PATH, FUCHSIA_PORTNUM, or FUCHSIA_RESOURCES_DIR was '
           'not set'))
    fuchsia_resources_dir_plus_build = os.path.join(fuchsia_resources_dir,
                                                    self.FUCHSIA_BUILD_REL_PATH)
    self.host = Host.from_dir(fuchsia_resources_dir_plus_build)
    self.device = Device(self.host, 'localhost', fuchsia_portnum)
    self.device.set_ssh_option('StrictHostKeyChecking no')
    self.device.set_ssh_option('UserKnownHostsFile=/dev/null')
    self.device.set_ssh_identity(fuchsia_pkey_path)

    # Fuchsia fuzzer names have the format {package_name}/{binary_name}.
    package, target = self.executable_path.split('/')
    test_data_dir = os.path.join(fuchsia_resources_dir_plus_build,
                                 self.FUZZER_TEST_DATA_REL_PATH, package,
                                 target)
    self.fuzzer = Fuzzer(
        self.device, package, target, output=test_data_dir, foreground=True)

  def __init__(self, executable_path, default_args=None):
    super(FuchsiaQemuLibFuzzerRunner, self).__init__(
        executable_path=executable_path, default_args=default_args)

    qemu_path, qemu_args = setup_qemu_values(initial_setup=False)
    qemu_process = setup_qemu_instance(qemu_path, qemu_args)
    self._setup_fuzzer_and_device()
    self.qemu_instance = run_qemu_instance(qemu_process)

  def __del__(self):
    self.qemu_instance.kill()

  def get_command(self, additional_args=None):
    # TODO(flowerhack): Update this to dynamically pick a result from "fuzz
    # list" and then run that fuzzer.
    return self.ssh_command('ls')

  def process_logs_and_crash(self, artifact_prefix):
    """Fetch symbolized logs and crashes."""
    if not artifact_prefix:
      return

    # Clusterfuzz assumes that the Libfuzzer output points to an absolute path,
    # where it can find the crash file.
    # This doesn't work in our case due to how Fuchsia is run.
    # So, we make a new file, change the appropriate line with a regex to point
    # to the true location. Apologies for the hackery.
    crash_location_regex = r'(.*)(Test unit written to )(data/.*)'
    _, processed_log_path = tempfile.mkstemp()
    with open(processed_log_path, 'w') as new_file:
      with open(self.fuzzer.logfile) as old_file:
        for line in old_file:
          line_match = re.match(crash_location_regex, line)
          if line_match:
            # We now know the name of our crash file.
            crash_name = line_match.group(3).replace('data/', '')
            # Save the crash locally.
            self.device.fetch(
                self.fuzzer.data_path(crash_name), artifact_prefix)
            # Then update the crash report to point to that file.
            crash_testcase_file_path = os.path.join(artifact_prefix, crash_name)
            line = re.sub(crash_location_regex,
                          r'\1\2' + crash_testcase_file_path, line)
          new_file.write(line)
    os.remove(self.fuzzer.logfile)
    shutil.move(processed_log_path, self.fuzzer.logfile)

  def _test_ssh(self):
    """Test the ssh connection."""
    # Test the connection.  If this works, proceed.
    # - If we fail, restart QEMU and test the connection again.
    # - If that fails, throw the error; we can't seem to recover.
    try:
      self._test_qemu_ssh()
    except fuchsia.errors.FuchsiaConnectionError:
      self._restart_qemu()
      self._test_qemu_ssh()

  def _restart_qemu(self):
    """Restart QEMU."""
    self.qemu_instance.kill()
    qemu_path, qemu_args = setup_qemu_values(initial_setup=False)
    qemu_process = setup_qemu_instance(qemu_path, qemu_args)
    self._setup_fuzzer_and_device()
    self.qemu_instance = run_qemu_instance(qemu_process)

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """LibFuzzerCommon.fuzz override."""
    self._test_ssh()

    #TODO(flowerhack): Pass libfuzzer args (additional_args) here
    return_code = self.fuzzer.start(additional_args)
    self.fuzzer.monitor(return_code)
    self.process_logs_and_crash(artifact_prefix)

    with open(self.fuzzer.logfile) as logfile:
      symbolized_output = logfile.read()

    # TODO(flowerhack): Would be nice if we could figure out a way to make
    # the "fuzzer start" code return its own ProcessResult. For now, we simply
    # craft one by hand here.
    fuzzer_process_result = new_process.ProcessResult()
    fuzzer_process_result.return_code = 0
    fuzzer_process_result.output = symbolized_output
    fuzzer_process_result.time_executed = 0
    fuzzer_process_result.command = self.fuzzer.last_fuzz_cmd
    return fuzzer_process_result

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """Run a single testcase."""
    self._test_ssh()

    # We need to push the testcase to the device and pass in the name.
    testcase_path_name = os.path.basename(os.path.normpath(testcase_path))
    self.device.store(testcase_path, self.fuzzer.data_path())

    # TODO(flowerhack): Pass libfuzzer args (additional_args) here
    return_code = self.fuzzer.start(['repro', 'data/' + testcase_path_name] +
                                    additional_args)
    self.fuzzer.monitor(return_code)

    with open(self.fuzzer.logfile) as logfile:
      symbolized_output = logfile.read()

    fuzzer_process_result = new_process.ProcessResult()
    fuzzer_process_result.return_code = 0
    fuzzer_process_result.output = symbolized_output
    fuzzer_process_result.time_executed = 0
    fuzzer_process_result.command = self.fuzzer.last_fuzz_cmd
    return fuzzer_process_result

  def minimize_crash(self,
                     testcase_path,
                     output_path,
                     timeout,
                     artifact_prefix=None,
                     additional_args=None):
    return new_process.ProcessResult()

  def ssh_command(self, *args):
    return ['ssh'] + self.ssh_root + list(args)

  @retry.wrap(retries=SSH_RETRIES, delay=SSH_WAIT, function='_test_qemu_ssh')
  def _test_qemu_ssh(self):
    """Tests that a VM is up and can be successfully SSH'd into.
    Raises an exception if no success after MAX_SSH_RETRIES."""
    ssh_test_process = new_process.ProcessRunner(
        'ssh',
        self.device.get_ssh_cmd(
            ['ssh', 'localhost', 'echo running on fuchsia!'])[1:])
    result = ssh_test_process.run_and_wait()
    if result.return_code or result.timed_out:
      raise fuchsia.errors.FuchsiaConnectionError(
          'Failed to establish initial SSH connection: ' +
          str(result.return_code) + " , " + str(result.command) + " , " +
          str(result.output))
    return result


class MinijailLibFuzzerRunner(engine_common.MinijailEngineFuzzerRunner,
                              LibFuzzerCommon):
  """Minijail libFuzzer runner."""

  def __init__(self, executable_path, chroot, default_args=None):
    """Inits the LibFuzzerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      chroot: A MinijailChroot.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super(MinijailLibFuzzerRunner, self).__init__(
        executable_path=executable_path,
        chroot=chroot,
        default_args=default_args)

  def get_testcase_path(self, log_lines):
    """Get testcase path from log lines."""
    path = LibFuzzerCommon.get_testcase_path(self, log_lines)
    if not path:
      return path

    for binding in self.chroot.bindings:
      if path.startswith(binding.dest_path):
        return os.path.join(binding.src_path,
                            os.path.relpath(path, binding.dest_path))

    raise LibFuzzerException('Invalid testcase path ' + path)

  def _get_chroot_corpus_paths(self, corpus_directories):
    """Return chroot relative paths for the given corpus directories.

    Args:
      corpus_directories: A list of host corpus directories.

    Returns:
      A list of chroot relative paths.
    """
    return [self._get_chroot_directory(path) for path in corpus_directories]

  def _get_chroot_directory(self, directory_path):
    """Return chroot relative path for the given directory.

    Args:
      directory_path: A path to the directory to be bound.

    Returns:
      A chroot relative path for the given directory.
    """
    binding = self.chroot.get_binding(directory_path)
    if not binding:
      raise LibFuzzerException(
          'Failed to get chroot binding for "%s".' % directory_path)
    return binding.dest_path

  def _bind_corpus_dirs(self, corpus_directories):
    """Bind corpus directories to the minijail chroot.

    Also makes sure that the directories are world writeable.

    Args:
      corpus_directories: A list of corpus paths.
    """
    for corpus_directory in corpus_directories:
      target_dir = '/' + os.path.basename(corpus_directory)
      self.chroot.add_binding(
          minijail.ChrootBinding(corpus_directory, target_dir, writeable=True))

  def analyze_dictionary(self,
                         dictionary_path,
                         corpus_directory,
                         analyze_timeout,
                         artifact_prefix=None,
                         additional_args=None):
    """LibFuzzerCommon.analyze_dictionary override."""
    bind_directories = [corpus_directory]
    if artifact_prefix:
      bind_directories.append(artifact_prefix)

    self._bind_corpus_dirs(bind_directories)
    corpus_directory = self._get_chroot_directory(corpus_directory)

    if artifact_prefix:
      artifact_prefix = self._get_chroot_directory(artifact_prefix)

    with self._chroot_testcase(dictionary_path) as chroot_dictionary_path:
      return LibFuzzerCommon.analyze_dictionary(
          self, chroot_dictionary_path, corpus_directory, analyze_timeout,
          artifact_prefix, additional_args)

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """LibFuzzerCommon.fuzz override."""
    bind_directories = copy.copy(corpus_directories)
    if artifact_prefix:
      bind_directories.append(artifact_prefix)

    ld_preload = None
    if extra_env and 'LD_PRELOAD' in extra_env:
      ld_preload = extra_env['LD_PRELOAD']
      bind_directories.append(os.path.dirname(ld_preload))

    self._bind_corpus_dirs(bind_directories)
    corpus_directories = self._get_chroot_corpus_paths(corpus_directories)

    if ld_preload:
      extra_env['LD_PRELOAD'] = os.path.join(
          self._get_chroot_directory(os.path.dirname(ld_preload)),
          os.path.basename(ld_preload))

    if artifact_prefix:
      artifact_prefix = self._get_chroot_directory(artifact_prefix)

    return LibFuzzerCommon.fuzz(
        self,
        corpus_directories,
        fuzz_timeout,
        artifact_prefix=artifact_prefix,
        additional_args=additional_args,
        extra_env=extra_env)

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None):
    """LibFuzzerCommon.merge override."""
    bind_directories = copy.copy(corpus_directories)
    if artifact_prefix:
      bind_directories.append(artifact_prefix)

    self._bind_corpus_dirs(bind_directories)
    corpus_directories = self._get_chroot_corpus_paths(corpus_directories)

    if artifact_prefix:
      artifact_prefix = self._get_chroot_directory(artifact_prefix)

    return LibFuzzerCommon.merge(
        self,
        corpus_directories,
        merge_timeout,
        artifact_prefix=artifact_prefix,
        tmp_dir=None,  # Use default in minijail.
        additional_args=additional_args)

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """LibFuzzerCommon.test_single_input override."""
    with self._chroot_testcase(testcase_path) as chroot_testcase_path:
      return LibFuzzerCommon.run_single_testcase(self, chroot_testcase_path,
                                                 timeout, additional_args)

  def minimize_crash(self,
                     testcase_path,
                     output_path,
                     timeout,
                     artifact_prefix=None,
                     additional_args=None):
    """LibFuzzerCommon.minimize_crash override."""
    with self._chroot_testcase(testcase_path) as chroot_testcase_path:
      chroot_output_name = 'minimized_crash'
      chroot_output_path = '/' + chroot_output_name
      host_output_path = os.path.join(self.chroot.directory, chroot_output_name)

      result = LibFuzzerCommon.minimize_crash(
          self,
          chroot_testcase_path,
          chroot_output_path,
          timeout,
          artifact_prefix=constants.TMP_ARTIFACT_PREFIX_ARGUMENT,
          additional_args=additional_args)
      if os.path.exists(host_output_path):
        shutil.copy(host_output_path, output_path)

      return result

  def cleanse_crash(self,
                    testcase_path,
                    output_path,
                    timeout,
                    artifact_prefix=None,
                    additional_args=None):
    """LibFuzzerCommon.cleanse_crash override."""
    with self._chroot_testcase(testcase_path) as chroot_testcase_path:
      chroot_output_name = 'cleanse_crash'
      chroot_output_path = '/' + chroot_output_name
      host_output_path = os.path.join(self.chroot.directory, chroot_output_name)

      result = LibFuzzerCommon.cleanse_crash(
          self,
          chroot_testcase_path,
          chroot_output_path,
          timeout,
          artifact_prefix=constants.TMP_ARTIFACT_PREFIX_ARGUMENT,
          additional_args=additional_args)
      if os.path.exists(host_output_path):
        shutil.copy(host_output_path, output_path)

      return result


def get_runner(fuzzer_path, temp_dir=None, use_minijail=None):
  """Get a libfuzzer runner."""
  if use_minijail is None:
    use_minijail = environment.get_value('USE_MINIJAIL')

  if use_minijail is False:
    # If minijail is explicitly disabled, set the environment variable as well.
    environment.set_value('USE_MINIJAIL', False)

  if temp_dir is None:
    temp_dir = fuzzer_utils.get_temp_dir()

  build_dir = environment.get_value('BUILD_DIR')
  dataflow_build_dir = environment.get_value('DATAFLOW_BUILD_DIR')

  is_fuchsia = environment.platform() == 'FUCHSIA'
  if not is_fuchsia:
    # To ensure that we can run the fuzz target.
    os.chmod(fuzzer_path, 0o755)

  is_chromeos_system_job = environment.is_chromeos_system_job()
  if is_chromeos_system_job:
    minijail_chroot = minijail.ChromeOSChroot(build_dir)
  elif use_minijail:
    minijail_chroot = minijail.MinijailChroot(base_dir=temp_dir)

  if use_minijail or is_chromeos_system_job:
    # While it's possible for dynamic binaries to run without this, they need
    # to be accessible for symbolization etc. For simplicity we bind BUILD_DIR
    # to the same location within the chroot, which leaks the directory
    # structure of CF but this shouldn't be a big deal.
    minijail_chroot.add_binding(
        minijail.ChrootBinding(build_dir, build_dir, writeable=False))

    if dataflow_build_dir:
      minijail_chroot.add_binding(
          minijail.ChrootBinding(
              dataflow_build_dir, dataflow_build_dir, writeable=False))

    # Also bind the build dir to /out to make it easier to hardcode references
    # to data files.
    minijail_chroot.add_binding(
        minijail.ChrootBinding(build_dir, '/out', writeable=False))

    minijail_bin = os.path.join(minijail_chroot.directory, 'bin')
    shell.create_directory(minijail_bin)

    # Set up /bin with llvm-symbolizer to allow symbolized stacktraces.
    # Don't copy if it already exists (e.g. ChromeOS chroot jail).
    llvm_symbolizer_source_path = environment.get_llvm_symbolizer_path()
    llvm_symbolizer_destination_path = os.path.join(minijail_bin,
                                                    'llvm-symbolizer')
    if not os.path.exists(llvm_symbolizer_destination_path):
      shutil.copy(llvm_symbolizer_source_path, llvm_symbolizer_destination_path)

    # copy /bin/sh, necessary for system().
    if not environment.is_chromeos_system_job():
      # The chroot has its own shell we don't need to copy (and probably
      # shouldn't because of library differences).
      shutil.copy(os.path.realpath('/bin/sh'), os.path.join(minijail_bin, 'sh'))

    runner = MinijailLibFuzzerRunner(fuzzer_path, minijail_chroot)
  elif is_fuchsia:
    runner = FuchsiaQemuLibFuzzerRunner(fuzzer_path)
  else:
    runner = LibFuzzerRunner(fuzzer_path)

  return runner
