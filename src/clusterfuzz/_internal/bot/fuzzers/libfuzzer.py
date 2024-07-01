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

import collections
import contextlib
import copy
import os
import random
import re
import shutil
import string

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options as fuzzer_options
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.platforms.fuchsia import undercoat
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import minijail
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell

# Maximum length of a random chosen length for `-max_len`.
MAX_VALUE_FOR_MAX_LENGTH = 10000

# Allow 30 minutes to merge the testcases back into the corpus.
DEFAULT_MERGE_TIMEOUT = 30 * 60

MERGED_DICT_SUFFIX = '.merged'

StrategyInfo = collections.namedtuple('StrategiesInfo', [
    'fuzzing_strategies',
    'arguments',
    'additional_corpus_dirs',
    'extra_env',
    'is_mutations_run',
])

MAX_OUTPUT_LEN = 1 * 1024 * 1024  # 1 MB

# Regex to find testcase path from a crash.
CRASH_TESTCASE_REGEX = (r'.*Test unit written to\s*'
                        r'(.*(crash|oom|timeout|leak)-.*)')

# pylint: disable=no-member


class LibFuzzerError(Exception):
  """LibFuzzer error."""


class LibFuzzerCommon:
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

  def get_total_timeout(self, timeout):
    """Calculate the total process timeout.

    Args:
      timeout: The maximum time in seconds that libFuzzer is allowed to run for.
    """
    timeout = timeout + self.LIBFUZZER_CLEAN_EXIT_TIME
    return int(timeout)

  def get_minimize_total_time(self, timeout):
    # We do timeout / 2 here because libFuzzer uses max_total_time for
    # individual runs of the target and not for the entire minimization.
    # Internally, libFuzzer does 2 runs of the target every iteration. This is
    # the minimum for any results to be written at all.
    max_total_time = (timeout - self.LIBFUZZER_CLEAN_EXIT_TIME) // 2
    assert max_total_time > 0
    return max_total_time

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
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    max_total_time = fuzz_timeout
    if constants.FORK_FLAGNAME in arguments:
      max_total_time -= self.LIBFUZZER_FORK_MODE_CLEAN_EXIT_TIME
    assert max_total_time > 0

    # Old libFuzzer jobs specify -artifact_prefix through additional_args
    if artifact_prefix:
      arguments[constants.ARTIFACT_PREFIX_FLAGNAME] = str(
          self._normalize_artifact_prefix(artifact_prefix))

    arguments[constants.MAX_TOTAL_TIME_FLAGNAME] = int(max_total_time)
    arguments[constants.PRINT_FINAL_STATS_FLAGNAME] = 1
    # FIXME: temporarily disabled due to a lack of crash information in
    # output.
    # arguments['close_fd_mask'] = 3

    return self.run_and_wait(
        additional_args=arguments.list() + corpus_directories,
        timeout=self.get_total_timeout(fuzz_timeout),
        terminate_before_kill=True,
        terminate_wait_time=self.SIGTERM_WAIT_TIME,
        max_stdout_len=MAX_OUTPUT_LEN,
        extra_env=extra_env)

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None,
            merge_control_file=None):
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
      merge_control_file: Path to the merge control file to be used.

    Returns:
      A process.ProcessResult.
    """
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    arguments[constants.MERGE_FLAGNAME] = 1
    if artifact_prefix:
      arguments[constants.ARTIFACT_PREFIX_FLAGNAME] = str(
          self._normalize_artifact_prefix(artifact_prefix))

    if merge_control_file:
      arguments[constants.MERGE_CONTROL_FILE_FLAGNAME] = merge_control_file

    extra_env = {}
    if tmp_dir:
      extra_env['TMPDIR'] = tmp_dir

    return self.run_and_wait(
        additional_args=arguments.list() + corpus_directories,
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
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    max_total_time = self.get_minimize_total_time(timeout)
    arguments[constants.MAX_TOTAL_TIME_FLAGNAME] = int(max_total_time)
    arguments[constants.EXACT_ARTIFACT_PATH_FLAGNAME] = str(output_path)
    arguments[constants.MINIMIZE_CRASH_FLAGNAME] = 1

    if artifact_prefix:
      arguments[constants.ARTIFACT_PREFIX_FLAGNAME] = str(
          self._normalize_artifact_prefix(artifact_prefix))

    return self.run_and_wait(
        additional_args=arguments.list() + [testcase_path],
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
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    arguments[constants.CLEANSE_CRASH_FLAGNAME] = 1
    arguments[constants.EXACT_ARTIFACT_PATH_FLAGNAME] = str(output_path)

    if artifact_prefix:
      arguments[constants.ARTIFACT_PREFIX_FLAGNAME] = str(
          self._normalize_artifact_prefix(artifact_prefix))

    return self.run_and_wait(
        additional_args=arguments.list() + [testcase_path],
        timeout=timeout,
        max_stdout_len=MAX_OUTPUT_LEN)


# False positive.
# pylint: disable=unexpected-keyword-arg
class LibFuzzerRunner(new_process.ModifierProcessRunnerMixin,
                      new_process.UnicodeProcessRunner, LibFuzzerCommon):
  """libFuzzer runner (when minijail is not used)."""

  def __init__(self, executable_path, default_args=None):
    """Inits the LibFuzzerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super().__init__(executable_path=executable_path, default_args=default_args)

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


class FuchsiaUndercoatLibFuzzerRunner(new_process.UnicodeProcessRunner,
                                      LibFuzzerCommon):
  """libFuzzer runner (when Fuchsia is the target platform, and undercoat
  is used)."""

  # Unfortunately the time to transfer corpora cannot be distinguished from time
  # to run the fuzzer, so we need to pad the timeouts we enforce here by an
  # upper limit on typical corpora transfer times to avoid prematurely killing a
  # perfectly healthy fuzz run. For some typical stats, see fxbug.dev/94029; we
  # go much higher than that to account for variability in the virtualized
  # environment, and because this is after all intended solely as a second line
  # of defense.
  TIMEOUT_PADDING = 30 * 60

  def __init__(self, executable_path, instance_handle, default_args=None):
    # An instance_handle from undercoat is required, and should be set up by the
    # build_manager.
    # Note: In this case executable_path is simply `package/fuzzer`
    super().__init__(executable_path=executable_path, default_args=default_args)
    self.handle = instance_handle

  def _corpus_directories_libfuzzer(self, corpus_directories):
    """Returns the corpus directory paths expected by libfuzzer itself."""
    return [
        self._target_corpus_path(os.path.basename(corpus_dir))
        for corpus_dir in corpus_directories
    ]

  def _new_corpus_dir_host(self, corpus_directories):
    """Returns the path of the 'new' corpus directory on the host."""
    return corpus_directories[0]

  def _new_corpus_dir_target(self, corpus_directories):
    """Returns the path of the 'new' corpus directory on the target."""
    return self._target_corpus_path(
        os.path.basename(self._new_corpus_dir_host(corpus_directories)))

  def _target_corpus_path(self, corpus_name):
    """Returns the path of a given corpus directory on the target."""
    return 'data/corpus/' + corpus_name

  def _push_corpora_from_host_to_target(self, corpus_directories):
    # Push corpus directories to the device.
    self._clear_all_target_corpora()
    logs.log('Push corpora from host to target.')
    for corpus_dir in corpus_directories:
      undercoat.put_data(self.handle, self.executable_path, corpus_dir,
                         'data/corpus')

  def _pull_new_corpus_from_target_to_host(self, corpus_directories):
    """Pull corpus directories from device to host."""
    # Appending '/*' indicates we want all the *files* in the target's
    # directory, rather than the directory itself.
    logs.log('Fuzzer ran; pulling down corpus')
    new_corpus_files_target = self._new_corpus_dir_target(
        corpus_directories) + '/*'
    undercoat.get_data(self.handle, self.executable_path,
                       new_corpus_files_target,
                       self._new_corpus_dir_host(corpus_directories))

  def _clear_all_target_corpora(self):
    """Clears out all the corpora on the target."""
    logs.log('Clearing corpora on target')
    # prepare_fuzzer resets the data/ directory
    undercoat.prepare_fuzzer(self.handle, self.executable_path)

  def _ensure_target_exists(self):
    """Check that the target fuzzer exists, raising an error if it does not.

    We do this check by looking at the list of fuzzers, instead of relying on
    an error from undercoat, because in some cases (e.g. regression tasks) it
    is an expected error that we wish to recover from. Additionally, we can't
    do this check earlier because we need an online target system to query."""
    targets = undercoat.list_fuzzers(self.handle)

    # These fuzzers are used for integration tests but not returned by
    # list_fuzzers because we don't want them to be run in production.
    targets += [
        'example-fuzzers/crash_fuzzer', 'example-fuzzers/overflow_fuzzer'
    ]

    if self.executable_path not in targets:
      raise testcase_manager.TargetNotFoundError(
          f'Failed to find target {self.executable_path}')

  def get_total_timeout(self, timeout):
    """LibFuzzerCommon.fuzz override."""
    return super().get_total_timeout(timeout) + self.TIMEOUT_PADDING

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """LibFuzzerCommon.fuzz override."""
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    undercoat.prepare_fuzzer(self.handle, self.executable_path)
    self._push_corpora_from_host_to_target(corpus_directories)

    max_total_time = fuzz_timeout
    if constants.FORK_FLAGNAME in arguments:
      max_total_time -= self.LIBFUZZER_FORK_MODE_CLEAN_EXIT_TIME
    assert max_total_time > 0

    arguments[constants.MAX_TOTAL_TIME_FLAGNAME] = int(max_total_time)
    arguments[constants.PRINT_FINAL_STATS_FLAGNAME] = 1

    # Run the fuzzer.
    # TODO(eep): Clarify comment from previous implementation: "actually we want
    # new_corpus_relative_dir_target for *each* corpus"
    result = undercoat.run_fuzzer(
        self.handle,
        self.executable_path,
        artifact_prefix,
        self._corpus_directories_libfuzzer(corpus_directories) +
        arguments.list(),
        timeout=self.get_total_timeout(fuzz_timeout))

    self._pull_new_corpus_from_target_to_host(corpus_directories)
    self._clear_all_target_corpora()
    return result

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None,
            merge_control_file=None):

    undercoat.prepare_fuzzer(self.handle, self.executable_path)
    self._push_corpora_from_host_to_target(corpus_directories)

    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    arguments[constants.MAX_TOTAL_TIME_FLAGNAME] = int(merge_timeout)

    target_merge_control_file = 'data/.mergefile'

    if merge_control_file:
      undercoat.put_data(self.handle, self.executable_path, merge_control_file,
                         target_merge_control_file)

    # Run merge.
    arguments['merge'] = 1
    arguments['merge_control_file'] = target_merge_control_file

    result = undercoat.run_fuzzer(
        self.handle,
        self.executable_path,
        None,
        self._corpus_directories_libfuzzer(corpus_directories) +
        arguments.list(),
        timeout=self.get_total_timeout(merge_timeout))

    self._pull_new_corpus_from_target_to_host(corpus_directories)
    if merge_control_file:
      undercoat.put_data(self.handle, self.executable_path,
                         target_merge_control_file, merge_control_file)

    self._clear_all_target_corpora()
    return result

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """Run a single testcase."""
    # TODO(eep): Are all these copy.copy() calls still necessary?
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    self._ensure_target_exists()

    # We need to push the testcase to the device and pass in the name.
    testcase_path_name = os.path.basename(os.path.normpath(testcase_path))
    undercoat.prepare_fuzzer(self.handle, self.executable_path)
    undercoat.put_data(self.handle, self.executable_path, testcase_path,
                       'data/')

    if timeout:
      timeout = self.get_total_timeout(timeout)

    result = undercoat.run_fuzzer(
        self.handle,
        self.executable_path,
        None, ['data/' + testcase_path_name] + additional_args,
        timeout=timeout)
    return result

  def minimize_crash(self,
                     testcase_path,
                     output_path,
                     timeout,
                     artifact_prefix=None,
                     additional_args=None):

    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    arguments[constants.MINIMIZE_CRASH_FLAGNAME] = 1
    arguments[constants.MAX_TOTAL_TIME_FLAGNAME] = int(
        self.get_minimize_total_time(timeout))

    target_artifact_prefix = 'data/'
    target_minimized_file = 'final-minimized-crash'
    min_file_fullpath = target_artifact_prefix + target_minimized_file
    arguments[constants.EXACT_ARTIFACT_PATH_FLAGNAME] = str(min_file_fullpath)

    # We need to push the testcase to the device and pass in the name.
    testcase_path_name = os.path.basename(os.path.normpath(testcase_path))
    undercoat.prepare_fuzzer(self.handle, self.executable_path)
    undercoat.put_data(self.handle, self.executable_path, testcase_path,
                       'data/')

    output_dir = os.path.dirname(output_path)
    result = undercoat.run_fuzzer(
        self.handle,
        self.executable_path,
        output_dir, ['data/' + testcase_path_name] + arguments.list(),
        timeout=self.get_total_timeout(timeout))

    # The minimized artifact is automatically fetched if minimization succeeded,
    # but this isn't always the case so let's just always fetch a new copy
    undercoat.get_data(self.handle, self.executable_path, min_file_fullpath,
                       output_dir)
    shutil.move(os.path.join(output_dir, target_minimized_file), output_path)

    return result


class MinijailLibFuzzerRunner(new_process.UnicodeProcessRunnerMixin,
                              engine_common.MinijailEngineFuzzerRunner,
                              LibFuzzerCommon):
  """Minijail libFuzzer runner."""

  def __init__(self, executable_path, chroot, default_args=None):
    """Inits the LibFuzzerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      chroot: A MinijailChroot.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super().__init__(
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

    raise LibFuzzerError('Invalid testcase path ' + path)

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
      raise LibFuzzerError(
          f'Failed to get chroot binding for "{directory_path}".')
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
            additional_args=None,
            merge_control_file=None):
    """LibFuzzerCommon.merge override."""
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    bind_directories = copy.copy(corpus_directories)
    if artifact_prefix:
      bind_directories.append(artifact_prefix)

    self._bind_corpus_dirs(bind_directories)
    corpus_directories = self._get_chroot_corpus_paths(corpus_directories)

    if artifact_prefix:
      artifact_prefix = self._get_chroot_directory(artifact_prefix)

    chroot_merge_control_file = None
    if merge_control_file:
      merge_control_dir = os.path.dirname(merge_control_file)
      self._bind_corpus_dirs([merge_control_dir])
      chroot_merge_control_dir = self._get_chroot_directory(merge_control_dir)
      chroot_merge_control_file = os.path.join(
          chroot_merge_control_dir,
          os.path.relpath(merge_control_file, merge_control_dir))

    return LibFuzzerCommon.merge(
        self,
        corpus_directories,
        merge_timeout,
        artifact_prefix=artifact_prefix,
        tmp_dir=None,  # Use default in minijail.
        additional_args=additional_args,
        merge_control_file=chroot_merge_control_file)

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """LibFuzzerCommon.run_single_testcase override."""
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


class AndroidLibFuzzerRunner(new_process.UnicodeProcessRunner, LibFuzzerCommon):
  """Android libFuzzer runner."""
  # This temp directory is used by libFuzzer merge tool. DONT CHANGE.
  LIBFUZZER_TEMP_DIR = '/data/local/tmp'

  def __init__(self, executable_path, build_directory, default_args=None):
    """Inits the AndroidLibFuzzerRunner.

    Args:
      executable_path: Path to the fuzzer executable.
      build_directory: A MinijailChroot.
      default_args: Default arguments to always pass to the fuzzer.
    """
    super().__init__(
        executable_path=android.adb.get_adb_path(),
        default_args=self._get_default_args(executable_path, default_args))

    android.adb.create_directory_if_needed(self.LIBFUZZER_TEMP_DIR)
    self.copy_local_directory_to_device(build_directory)

  def _get_default_args(self, executable_path, extra_args):
    """Return a set of default arguments to pass to adb binary."""
    default_args = ['shell']

    # LD_LIBRARY_PATH set to search for fuzzer deps first, and then
    # sanitizers if any are found.
    ld_library_path = ''
    if not android.settings.is_automotive():
      # TODO(MHA3): Remove this auto check.
      executable_dir = os.path.dirname(executable_path)
      deps_path = os.path.join(self._get_device_path(executable_dir), 'lib')
      ld_library_path += deps_path
      memory_tool_path = android.sanitizer.get_ld_library_path_for_memory_tools(
      )
      if memory_tool_path:
        ld_library_path += ':' + memory_tool_path
      default_args.append('LD_LIBRARY_PATH=' + ld_library_path)

    # Add sanitizer options.
    default_args += environment.get_sanitizer_options_for_display()

    default_args.append(self._get_device_path(executable_path))

    if extra_args:
      default_args += extra_args

    return default_args

  def _get_device_corpus_paths(self, corpus_directories):
    """Return device paths for the given corpus directories."""
    return [self._get_device_path(path) for path in corpus_directories]

  def _get_device_path(self, local_path):
    """Return device path for the given local path."""
    root_directory = environment.get_root_directory()
    return os.path.join(android.constants.DEVICE_FUZZING_DIR,
                        os.path.relpath(local_path, root_directory))

  def _get_local_path(self, device_path):
    """Return local path for the given device path."""
    if not device_path.startswith(android.constants.DEVICE_FUZZING_DIR + '/'):
      logs.log_error('Bad device path: ' + device_path)
      return None

    root_directory = environment.get_root_directory()
    return os.path.join(
        root_directory,
        os.path.relpath(device_path, android.constants.DEVICE_FUZZING_DIR))

  def _copy_local_directories_to_device(self, local_directories):
    """Copies local directories to device."""
    for local_directory in sorted(set(local_directories)):
      self.copy_local_directory_to_device(local_directory)

  def copy_local_directory_to_device(self, local_directory):
    """Copy local directory to device."""
    device_directory = self._get_device_path(local_directory)
    android.adb.remove_directory(device_directory, recreate=True)
    android.adb.copy_local_directory_to_remote(local_directory,
                                               device_directory)

  def _copy_local_directories_from_device(self, local_directories):
    """Copies directories from device to local."""
    for local_directory in sorted(set(local_directories)):
      device_directory = self._get_device_path(local_directory)
      shell.remove_directory(local_directory, recreate=True)
      android.adb.copy_remote_directory_to_local(device_directory,
                                                 local_directory)

  def _extract_trusty_stacktrace_from_logcat(self, logcat):
    """Finds and returns a TA stacktrace from a logcat"""
    begin = android.constants.TRUSTY_STACKTRACE_BEGIN
    end = android.constants.TRUSTY_STACKTRACE_END
    target_idx = logcat.rfind(begin)

    if target_idx != -1:
      #Logcat contains kernel panic
      begin = logcat[:target_idx].rfind('\n')
      end_idx = target_idx + logcat[target_idx:].find('\n')
      end_idx += logcat[end_idx:].find(end)
      end_idx += logcat[end_idx:].find('\n')

      ta_stacktrace = []
      split_marker = 'trusty:log: '
      for line in logcat[begin:end_idx].splitlines():
        split_idx = line.find(split_marker) + len(split_marker)
        ta_stacktrace.append(line[split_idx:])

      return '\n'.join(ta_stacktrace)

    begin = '---------'
    target = 'Backtrace for thread:'
    target_idx = logcat.rfind(target)
    if target_idx == -1:
      return 'No TA crash stacktrace found in logcat.\n'

    begin_idx = logcat[:target_idx].rfind(begin)
    end_idx = target_idx + logcat[target_idx:].find(end)
    end_idx += logcat[end_idx:].find('\n')

    return logcat[begin_idx:end_idx]

  def _add_trusty_stacktrace_if_needed(self, output):
    """Add trusty stacktrace to beginning of output if found in logcat."""

    if android.adb.get_device_state() == 'is-ramdump-mode:yes':
      logcat = android.adb.extract_logcat_from_ramdump_and_reboot()
    else:
      logcat = android.logger.log_output()

    ta_stacktrace = self._extract_trusty_stacktrace_from_logcat(logcat)

    # Defer imports since stack_symbolizer pulls in a lot of things.
    from clusterfuzz._internal.crash_analysis.stack_parsing import \
        stack_symbolizer
    loop = stack_symbolizer.SymbolizationLoop()
    ta_stacktrace = loop.process_trusty_stacktrace(ta_stacktrace)

    return ('+-- Logcat excerpt: Trusted App crash stacktrace --+'
            f'\n{ta_stacktrace}\n\n{output}\n\nLogcat:\n{logcat}')

  def _extract_mte_stacktrace_from_logcat(self, logcat):
    """Finds and returns the MTE stacktrace from a logcat."""
    begin = android.constants.MTE_STACKTRACE_BEGIN
    end = android.constants.MTE_STACKTRACE_END
    target_idx = logcat.rfind(begin)

    if target_idx != -1:
      # Logcat contains MTE crash
      begin = logcat[:target_idx].rfind('\n')
      end_idx = target_idx + logcat[target_idx:].find('\n')
      end_idx += logcat[end_idx:].find(end)
      end_idx += logcat[end_idx:].find('\n')

      mte_stacktrace = ['MTE Stacktrace:']
      for line in logcat[begin:end_idx].splitlines():
        mte_stacktrace.append(line)

      return '\n'.join(mte_stacktrace)

    begin = '---------'
    target = 'Backtrace for thread:'
    target_idx = logcat.rfind(target)
    if target_idx == -1:
      return 'No MTE crash stacktrace found in logcat.\n'

    begin_idx = logcat[:target_idx].rfind(begin)
    end_idx = target_idx + logcat[target_idx:].find(end)
    end_idx += logcat[end_idx:].find('\n')

    return logcat[begin_idx:end_idx]

  def _add_mte_stacktrace_if_needed(self, output):
    """Add mte stacktrace to beginning of output if found in logcat."""
    logcat = android.logger.log_output()
    mte_stacktrace = self._extract_mte_stacktrace_from_logcat(logcat)

    return ('+-- Logcat excerpt: MTE crash stacktrace --+'
            f'\n{mte_stacktrace}\n\n{output}\n\nLogcat:\n{logcat}')

  def _add_logcat_output_if_needed(self, output):
    """Add logcat output to end of output to capture crashes from related
    processes if current output has no sanitizer crash."""
    if 'Sanitizer: ' in output:
      return output

    if environment.is_android_emulator():
      return self._add_trusty_stacktrace_if_needed(output)

    if environment.is_android() and android.settings.is_mte_build():
      return self._add_mte_stacktrace_if_needed(output)

    return f'{output}\n\nLogcat:\n{android.logger.log_output()}'

  @contextlib.contextmanager
  def _device_file(self, file_path):
    """Context manager for device files.
    Args:
      file_path: Host path to file.
    Returns:
      Path to file on device.
    """
    device_file_path = self._get_device_path(file_path)
    android.adb.copy_local_file_to_remote(file_path, device_file_path)
    yield device_file_path
    # Cleanup
    android.adb.remove_file(device_file_path)

  def get_testcase_path(self, log_lines):
    """Get testcase path from log lines."""
    path = LibFuzzerCommon.get_testcase_path(self, log_lines)
    if not path:
      return path

    return self._get_local_path(path)

  def fuzz(self,
           corpus_directories,
           fuzz_timeout,
           artifact_prefix=None,
           additional_args=None,
           extra_env=None):
    """LibFuzzerCommon.fuzz override."""
    android.logger.clear_log()

    sync_directories = copy.copy(corpus_directories)
    if artifact_prefix:
      sync_directories.append(artifact_prefix)

    self._copy_local_directories_to_device(sync_directories)
    corpus_directories = self._get_device_corpus_paths(corpus_directories)

    if artifact_prefix:
      artifact_prefix = self._get_device_path(artifact_prefix)

    # Extract local dict path from arguments list and subsitute with device one.
    arguments = fuzzer_options.FuzzerArguments.from_list(additional_args)
    assert arguments is not None

    dict_path = arguments.get(
        constants.DICT_FLAGNAME, default=None, constructor=str)

    if dict_path:
      device_dict_path = self._get_device_path(dict_path)
      android.adb.copy_local_file_to_remote(dict_path, device_dict_path)
      arguments[constants.DICT_FLAGNAME] = device_dict_path

    result = LibFuzzerCommon.fuzz(
        self,
        corpus_directories,
        fuzz_timeout,
        artifact_prefix=artifact_prefix,
        additional_args=arguments.list(),
        extra_env=extra_env)

    result.output = self._add_logcat_output_if_needed(result.output)

    self._copy_local_directories_from_device(sync_directories)
    return result

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None,
            merge_control_file=None):
    """LibFuzzerCommon.merge override."""
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    sync_directories = copy.copy(corpus_directories)
    if artifact_prefix:
      sync_directories.append(artifact_prefix)

    device_merge_control_file = None
    if merge_control_file:
      device_merge_control_file = self._get_device_path(merge_control_file)
      merge_control_dir = os.path.dirname(merge_control_file)
      sync_directories.append(merge_control_dir)

    self._copy_local_directories_to_device(sync_directories)
    corpus_directories = self._get_device_corpus_paths(corpus_directories)

    if artifact_prefix:
      artifact_prefix = self._get_device_path(artifact_prefix)

    result = LibFuzzerCommon.merge(
        self,
        corpus_directories,
        merge_timeout,
        artifact_prefix=artifact_prefix,
        tmp_dir=None,
        additional_args=additional_args,
        merge_control_file=device_merge_control_file)

    self._copy_local_directories_from_device(sync_directories)
    return result

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """LibFuzzerCommon.run_single_testcase override."""
    android.logger.clear_log()

    with self._device_file(testcase_path) as device_testcase_path:
      result = LibFuzzerCommon.run_single_testcase(self, device_testcase_path,
                                                   timeout, additional_args)
      result.output = self._add_logcat_output_if_needed(result.output)
      return result

  def minimize_crash(self,
                     testcase_path,
                     output_path,
                     timeout,
                     artifact_prefix=None,
                     additional_args=None):
    """LibFuzzerCommon.minimize_crash override."""
    with self._device_file(testcase_path) as device_testcase_path:
      device_output_path = self._get_device_path(output_path)

      result = LibFuzzerCommon.minimize_crash(
          self,
          device_testcase_path,
          device_output_path,
          timeout,
          artifact_prefix=constants.TMP_ARTIFACT_PREFIX_ARGUMENT,
          additional_args=additional_args)
      if android.adb.file_exists(device_output_path):
        android.adb.copy_remote_file_to_local(device_output_path, output_path)

      return result

  def cleanse_crash(self,
                    testcase_path,
                    output_path,
                    timeout,
                    artifact_prefix=None,
                    additional_args=None):
    """LibFuzzerCommon.cleanse_crash override."""
    with self._device_file(testcase_path) as device_testcase_path:
      device_output_path = self._get_device_path(output_path)

      result = LibFuzzerCommon.cleanse_crash(
          self,
          device_testcase_path,
          device_output_path,
          timeout,
          artifact_prefix=constants.TMP_ARTIFACT_PREFIX_ARGUMENT,
          additional_args=additional_args)
      if android.adb.file_exists(device_output_path):
        android.adb.copy_remote_file_to_local(device_output_path, output_path)

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
  is_android = environment.is_android()
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
    instance_handle = environment.get_value('FUCHSIA_INSTANCE_HANDLE')
    if not instance_handle:
      raise undercoat.UndercoatError('Instance handle not provided.')
    runner = FuchsiaUndercoatLibFuzzerRunner(fuzzer_path, instance_handle)
  elif is_android:
    runner = AndroidLibFuzzerRunner(fuzzer_path, build_dir)
  else:
    runner = LibFuzzerRunner(fuzzer_path)

  return runner


def create_corpus_directory(name):
  """Create a corpus directory with a give name in temp directory and return its
  full path."""
  new_corpus_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
  engine_common.recreate_directory(new_corpus_directory)
  return new_corpus_directory


def copy_from_corpus(dest_corpus_path, src_corpus_path, num_testcases):
  """Choose |num_testcases| testcases from the src corpus directory (and its
  subdirectories) and copy it into the dest directory."""
  src_corpus_files = []
  for root, _, files in shell.walk(src_corpus_path):
    for f in files:
      src_corpus_files.append(os.path.join(root, f))

  # There is no reason to preserve structure of src_corpus_path directory.
  for i, to_copy in enumerate(random.sample(src_corpus_files, num_testcases)):
    shutil.copy(os.path.join(to_copy), os.path.join(dest_corpus_path, str(i)))


def strip_fuzzing_arguments(arguments, is_merge=False):
  """Remove arguments used during fuzzing."""
  args = fuzzer_options.FuzzerArguments.from_list(arguments)
  for argument in [
      # Remove as it overrides `-merge` argument.
      constants.FORK_FLAGNAME,  # It overrides `-merge` argument.

      # Remove as it may shrink the testcase.
      constants.MAX_LEN_FLAGNAME,  # This may shrink the testcases.

      # Remove any existing runs argument as we will create our own for
      # reproduction.
      constants.RUNS_FLAGNAME,  # Make sure we don't have any '-runs' argument.

      # Remove the following flags/arguments that are only used for fuzzing.
      constants.DATA_FLOW_TRACE_FLAGNAME,
      constants.DICT_FLAGNAME,
      constants.FOCUS_FUNCTION_FLAGNAME,
  ]:
    if argument in args:
      del args[argument]

  # Value profile is needed during corpus merge, so do not remove if set.
  if not is_merge:
    if constants.VALUE_PROFILE_FLAGNAME in args:
      del args[constants.VALUE_PROFILE_FLAGNAME]

  return args.list()


def fix_timeout_argument_for_reproduction(arguments):
  """Changes timeout argument for reproduction. This is slightly less than the
  |TEST_TIMEOUT| value for the job."""
  args = fuzzer_options.FuzzerArguments.from_list(arguments)
  if constants.TIMEOUT_FLAGNAME in args:
    del args[constants.TIMEOUT_FLAGNAME]

  # Leave 5 sec buffer for report processing.
  adjusted_test_timeout = max(
      1,
      environment.get_value('TEST_TIMEOUT', constants.DEFAULT_TIMEOUT_LIMIT) -
      constants.REPORT_PROCESSING_TIME)
  args[constants.TIMEOUT_FLAGNAME] = adjusted_test_timeout
  return args.list()


def parse_log_stats(log_lines):
  """Parse libFuzzer log output."""
  log_stats = {}

  # Parse libFuzzer generated stats (`-print_final_stats=1`).
  stats_regex = re.compile(r'stat::([A-Za-z_]+):\s*([^\s]+)')
  for line in log_lines:
    match = stats_regex.match(line)
    if not match:
      continue

    value = match.group(2)
    if not value.isdigit():
      # We do not expect any non-numeric stats from libFuzzer, skip those.
      logs.log_error('Corrupted stats reported by libFuzzer: "%s".' % line)
      continue

    value = int(value)

    log_stats[match.group(1)] = value

  if log_stats.get('new_units_added') is not None:
    # 'new_units_added' value will be overwritten after corpus merge step, but
    # the initial number of units generated is an interesting data as well.
    log_stats['new_units_generated'] = log_stats['new_units_added']

  return log_stats


def set_sanitizer_options(fuzzer_path):
  """Sets sanitizer options based on .options file overrides and what this
  script requires."""
  engine_common.process_sanitizer_options_overrides(fuzzer_path)
  sanitizer_options_var = environment.get_current_memory_tool_var()
  sanitizer_options = environment.get_memory_tool_options(
      sanitizer_options_var, {})
  sanitizer_options['exitcode'] = constants.TARGET_ERROR_EXITCODE
  environment.set_memory_tool_options(sanitizer_options_var, sanitizer_options)


def get_fuzz_timeout(is_mutations_run, total_timeout=None):
  """Get the fuzz timeout."""
  fuzz_timeout = (
      engine_common.get_hard_timeout(total_timeout=total_timeout) -
      engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT))

  if is_mutations_run:
    fuzz_timeout -= engine_common.get_new_testcase_mutations_timeout()

  return fuzz_timeout


def is_linux_asan():
  """Helper functions. Returns whether or not the current env is linux asan."""
  return (environment.platform() != 'LINUX' or
          environment.get_value('MEMORY_TOOL') != 'ASAN')


def is_sha1_hash(possible_hash):
  """Returns True if |possible_hash| looks like a valid sha1 hash."""
  if len(possible_hash) != 40:
    return False

  hexdigits_set = set(string.hexdigits)
  return all(char in hexdigits_set for char in possible_hash)


def move_mergeable_units(merge_directory, corpus_directory):
  """Move new units in |merge_directory| into |corpus_directory|."""
  initial_units = {
      os.path.basename(filename)
      for filename in shell.get_files_list(corpus_directory)
  }

  for unit_path in shell.get_files_list(merge_directory):
    unit_name = os.path.basename(unit_path)
    if unit_name in initial_units and is_sha1_hash(unit_name):
      continue
    dest_path = os.path.join(corpus_directory, unit_name)
    shell.move(unit_path, dest_path)


def pick_strategies(strategy_pool, fuzzer_path, corpus_directory,
                    existing_arguments):
  """Pick strategies."""
  fuzzing_strategies = []
  arguments = fuzzer_options.FuzzerArguments({})
  additional_corpus_dirs = []

  # Select a generator to attempt to use for existing testcase mutations.
  candidate_generator = engine_common.select_generator(strategy_pool,
                                                       fuzzer_path)
  is_mutations_run = (not environment.is_ephemeral() and
                      candidate_generator != engine_common.Generator.NONE)

  # Generate new testcase mutations using radamsa, etc.
  if is_mutations_run:
    new_testcase_mutations_directory = create_corpus_directory('mutations')
    generator_used = engine_common.generate_new_testcase_mutations(
        corpus_directory, new_testcase_mutations_directory, candidate_generator)

    # Add the used generator strategy to our fuzzing strategies list.
    if (generator_used and
        candidate_generator == engine_common.Generator.RADAMSA):
      fuzzing_strategies.append(strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name)

    additional_corpus_dirs.append(new_testcase_mutations_directory)

  if strategy_pool.do_strategy(strategy.RANDOM_MAX_LENGTH_STRATEGY):
    if constants.MAX_LEN_FLAGNAME not in existing_arguments:
      max_length = random.SystemRandom().randint(1, MAX_VALUE_FOR_MAX_LENGTH)
      arguments[constants.MAX_LEN_FLAGNAME] = max_length
      fuzzing_strategies.append(strategy.RANDOM_MAX_LENGTH_STRATEGY.name)

  if strategy_pool.do_strategy(strategy.VALUE_PROFILE_STRATEGY):
    arguments[constants.VALUE_PROFILE_FLAGNAME] = 1
    fuzzing_strategies.append(strategy.VALUE_PROFILE_STRATEGY.name)

  if should_set_fork_flag(existing_arguments, strategy_pool):
    max_fuzz_threads = environment.get_value('MAX_FUZZ_THREADS', 1)
    num_fuzz_processes = max(1, utils.cpu_count() // max_fuzz_threads)
    arguments[constants.FORK_FLAGNAME] = num_fuzz_processes
    fuzzing_strategies.append(
        '%s_%d' % (strategy.FORK_STRATEGY.name, num_fuzz_processes))

  extra_env = {}

  if (environment.platform() == 'LINUX' and utils.is_oss_fuzz() and
      strategy_pool.do_strategy(strategy.USE_EXTRA_SANITIZERS_STRATEGY)):
    fuzzing_strategies.append(strategy.USE_EXTRA_SANITIZERS_STRATEGY.name)

  return StrategyInfo(fuzzing_strategies, arguments, additional_corpus_dirs,
                      extra_env, is_mutations_run)


def should_set_fork_flag(existing_arguments, strategy_pool):
  """Returns True if fork flag should be set."""
  # FIXME: Disable for now to avoid severe battery drainage. Stabilize and
  # re-enable with a lower process count.
  if environment.is_android():
    return False
  # Fork mode is not supported on Fuchsia platform.
  if environment.platform() == 'FUCHSIA':
    return False
  # Fork mode is disabled on ephemeral bots due to a bug on the platform.
  if environment.is_ephemeral():
    return False
  # Do not use fork mode for DFT-based fuzzing. This is needed in order to
  # collect readable and actionable logs from fuzz targets running with DFT.
  # If fork_server is already set by the user, let's keep it that way.
  if constants.FORK_FLAGNAME in existing_arguments.flags:
    return False
  return strategy_pool.do_strategy(strategy.FORK_STRATEGY)
