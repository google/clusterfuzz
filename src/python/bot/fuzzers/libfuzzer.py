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
import sys
import tempfile

from base import retry
from base import utils
from bot.fuzzers import dictionary_manager
from bot.fuzzers import engine_common
from bot.fuzzers import mutator_plugin
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.libFuzzer import constants
from bot.fuzzers.libFuzzer.peach import pits
from datastore import data_types
from fuzzing import strategy
from metrics import logs
from platforms import android
from platforms import fuchsia
from platforms.fuchsia.device import QemuProcess
from platforms.fuchsia.device import start_qemu
from platforms.fuchsia.device import stop_qemu
from platforms.fuchsia.util.device import Device
from platforms.fuchsia.util.fuzzer import Fuzzer
from platforms.fuchsia.util.host import Host
from system import archive
from system import environment
from system import minijail
from system import new_process
from system import process_handler
from system import shell

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
    'use_dataflow_tracing',
    'is_mutations_run',
])

MAX_OUTPUT_LEN = 1 * 1024 * 1024  # 1 MB

# Regex to find testcase path from a crash.
CRASH_TESTCASE_REGEX = (r'.*Test unit written to\s*'
                        r'(.*(crash|oom|timeout|leak)-.*)')

# Currently matches oss-fuzz/infra/base-images/base-runner/collect_dft#L34.
DATAFLOW_TRACE_DIR_SUFFIX = '_dft'

# List of all strategies that affect LD_PRELOAD.
MUTATOR_STRATEGIES = [
    strategy.PEACH_GRAMMAR_MUTATION_STRATEGY.name,
    strategy.MUTATOR_PLUGIN_STRATEGY.name,
    strategy.MUTATOR_PLUGIN_RADAMSA_STRATEGY.name
]


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
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    additional_args.append(constants.MERGE_ARGUMENT)
    if artifact_prefix:
      additional_args.append(
          '%s%s' % (constants.ARTIFACT_PREFIX_FLAG,
                    self._normalize_artifact_prefix(artifact_prefix)))

    if merge_control_file:
      additional_args.append(constants.MERGE_CONTROL_FILE_ARGUMENT +
                             merge_control_file)

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

    max_total_time = self.get_minimize_total_time(timeout)
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


class LibFuzzerRunner(new_process.UnicodeProcessRunner, LibFuzzerCommon):
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


class UnshareLibFuzzerRunner(new_process.UnshareProcessRunnerMixin,
                             new_process.UnicodeProcessRunner, LibFuzzerCommon):
  """LibFuzzerRunner which unshares."""


class FuchsiaQemuLibFuzzerRunner(new_process.UnicodeProcessRunner,
                                 LibFuzzerCommon):
  """libFuzzer runner (when Fuchsia is the target platform)."""

  FUCHSIA_BUILD_REL_PATH = os.path.join('build', 'out', 'default')

  SSH_RETRIES = 3
  SSH_WAIT = 5

  FUZZER_TEST_DATA_REL_PATH = os.path.join('test_data', 'fuzzing')

  def _setup_device_and_fuzzer(self):
    """Build a Device and Fuzzer object based on QEMU's settings."""
    # These environment variables are set when start_qemu is run.
    # We need them in order to ssh / otherwise communicate with the VM.
    fuchsia_pkey_path = environment.get_value('FUCHSIA_PKEY_PATH')
    fuchsia_portnum = environment.get_value('FUCHSIA_PORTNUM')
    fuchsia_resources_dir = environment.get_value('FUCHSIA_RESOURCES_DIR')
    if (not fuchsia_pkey_path or not fuchsia_portnum or
        not fuchsia_resources_dir):
      raise fuchsia.errors.FuchsiaConfigError(
          ('FUCHSIA_PKEY_PATH, FUCHSIA_PORTNUM, or FUCHSIA_RESOURCES_DIR was '
           'not set'))

    # Fuzzer objects communicate with the VM via a Device object,
    # which we set up here.
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

    # Finally, we set up the Fuzzer object itself, which will run our fuzzer!
    sanitizer = environment.get_memory_tool_name(
        environment.get_value('JOB_NAME')).lower()
    self.fuzzer = Fuzzer(
        self.device,
        package,
        target,
        output=test_data_dir,
        foreground=True,
        sanitizer=sanitizer)

  def __init__(self, executable_path, default_args=None):
    # We always assume QEMU is running on __init__, since build_manager sets
    # it up initially. If this isn't the case, _test_ssh will detect and
    # restart QEMU anyway.
    super().__init__(executable_path=executable_path, default_args=default_args)
    self._setup_device_and_fuzzer()

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
    with open(processed_log_path, mode='w', encoding='utf-8') as new_file:
      with open(
          self.fuzzer.logfile, encoding='utf-8', errors='ignore') as old_file:
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

  def _restart_qemu(self):
    """Restart QEMU."""
    logs.log_warn(
        'Connection to fuzzing VM lost. Restarting.',
        processes=process_handler.get_runtime_snapshot())
    stop_qemu()

    # Do this after the stop, to make sure everything is flushed
    if os.path.exists(QemuProcess.LOG_PATH):
      with open(QemuProcess.LOG_PATH) as f:
        # Strip non-printable characters at beginning of qemu log
        qemu_log = ''.join(c for c in f.read() if c in string.printable)
        logs.log_warn(qemu_log)
    else:
      logs.log_error('Qemu log not found in {}'.format(QemuProcess.LOG_PATH))

    start_qemu()
    self._setup_device_and_fuzzer()

  def _corpus_target_subdir(self, relpath):
    """ Returns the absolute path of the corpus subdirectory on the target,
    given "relpath", the name of the specific corpus. """
    return os.path.join(self._corpus_directories_target(), relpath)

  def _corpus_directories_libfuzzer(self, corpus_directories):
    """ Returns the corpus directory paths expected by libfuzzer itself. """
    corpus_directories_libfuzzer = []
    for corpus_dir in corpus_directories:
      corpus_directories_libfuzzer.append(
          os.path.join('data', 'corpus', os.path.basename(corpus_dir)))
    return corpus_directories_libfuzzer

  def _new_corpus_dir_host(self, corpus_directories):
    """ Returns the path of the 'new' corpus directory on the host. """
    return corpus_directories[0]

  def _new_corpus_dir_target(self, corpus_directories):
    """ Returns the path of the 'new' corpus directory on the target. """
    new_corpus_dir_host = self._new_corpus_dir_host(corpus_directories)
    return self.fuzzer.data_path(
        os.path.join('corpus', os.path.basename(new_corpus_dir_host)))

  def _corpus_directories_target(self):
    """ Returns the path of the root corpus directory on the target. """
    return self.fuzzer.data_path('corpus')

  def _push_corpora_from_host_to_target(self, corpus_directories):
    # Push corpus directories to the device.
    self._clear_all_target_corpora()
    logs.log('Push corpora from host to target.')
    for corpus_dir in corpus_directories:
      # Appending '/*' indicates we want all the *files* in the corpus_dir's.
      self.fuzzer.device.store(
          corpus_dir + '/*',
          self._corpus_target_subdir(os.path.basename(corpus_dir)))

  def _pull_new_corpus_from_target_to_host(self, corpus_directories,
                                           artifact_prefix):
    """ Pull corpus directories from device to host. """
    # Appending '/*' indicates we want all the *files* in the target's
    # directory, rather than the directory itself.
    logs.log('Fuzzer ran; pull down corpus')
    files_in_new_corpus_dir_target = self._new_corpus_dir_target(
        corpus_directories) + "/*"
    self.fuzzer.device.fetch(files_in_new_corpus_dir_target,
                             self._new_corpus_dir_host(corpus_directories))

    # TODO(flowerhack): While this should fetch all the "bad units" after the
    # merge, the *ideal* solution is that we move all these bad units to a
    # directory *on* the target, so that we can just sync/pull that one
    # directory automagically. Since we're moving to the Go-based
    # Clusterfuchsia interface soon, and since setting that up is nontrivial
    # on the Fuchsia end, we just pull each type of bad unit manually for now.
    # Note this wouldn't work if we ran more than one merge task per run (we'd
    # be double-copying crashes etc.)
    if artifact_prefix:
      self.device.fetch(self.fuzzer.data_path('crash*'), artifact_prefix)
      self.device.fetch(self.fuzzer.data_path('oom*'), artifact_prefix)
      self.device.fetch(self.fuzzer.data_path('timeout*'), artifact_prefix)
      self.device.fetch(self.fuzzer.data_path('leak*'), artifact_prefix)

  def _clear_all_target_corpora(self):
    """ Clears out all the corpora on the target. """
    logs.log('Clearing corpora on target')
    self.fuzzer.device.ssh(['rm', '-rf', self._corpus_directories_target()])

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

    self._test_ssh()
    self._push_corpora_from_host_to_target(corpus_directories)

    max_total_time = self.get_max_total_time(fuzz_timeout)
    if any(arg.startswith(constants.FORK_FLAG) for arg in additional_args):
      max_total_time -= self.LIBFUZZER_FORK_MODE_CLEAN_EXIT_TIME
    assert max_total_time > 0

    additional_args.extend([
        '%s%d' % (constants.MAX_TOTAL_TIME_FLAG, max_total_time),
        constants.PRINT_FINAL_STATS_ARGUMENT,
    ])

    # Run the fuzzer.
    # TODO: actually we want new_corpus_relative_dir_target for *each* corpus
    return_code = self.fuzzer.start(
        self._corpus_directories_libfuzzer(corpus_directories) +
        additional_args)
    self.fuzzer.monitor(return_code)
    self.process_logs_and_crash(artifact_prefix)
    with open(
        self.fuzzer.logfile, encoding='utf-8', errors='ignore') as logfile:
      symbolized_output = logfile.read()

    self._pull_new_corpus_from_target_to_host(corpus_directories,
                                              artifact_prefix)
    self._clear_all_target_corpora()

    # TODO(flowerhack): Would be nice if we could figure out a way to make
    # the "fuzzer start" code return its own ProcessResult. For now, we simply
    # craft one by hand here.
    fuzzer_process_result = new_process.ProcessResult()
    fuzzer_process_result.return_code = 0
    fuzzer_process_result.output = symbolized_output
    fuzzer_process_result.time_executed = 0
    fuzzer_process_result.command = self.fuzzer.last_fuzz_cmd
    return fuzzer_process_result

  def merge(self,
            corpus_directories,
            merge_timeout,
            artifact_prefix=None,
            tmp_dir=None,
            additional_args=None,
            merge_control_file=None):
    self._push_corpora_from_host_to_target(corpus_directories)

    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []
    max_total_time_flag = constants.MAX_TOTAL_TIME_FLAG + str(merge_timeout)
    additional_args.append(max_total_time_flag)

    target_merge_control_file = None
    if merge_control_file:
      merge_control_dir = os.path.dirname(merge_control_file)
      target_merge_control_dir = self._corpus_target_subdir(
          os.path.basename(merge_control_dir))
      self.fuzzer.device.rm(target_merge_control_dir, recursive=True)
      self.fuzzer.device.store(merge_control_dir, target_merge_control_dir)
      target_merge_control_file = os.path.join(
          target_merge_control_dir,
          os.path.relpath(merge_control_file, merge_control_dir))

    # Run merge.
    _, _ = self.fuzzer.merge(
        self._corpus_directories_libfuzzer(corpus_directories) +
        additional_args,
        merge_control_file=target_merge_control_file)

    self._pull_new_corpus_from_target_to_host(corpus_directories,
                                              artifact_prefix)
    if merge_control_file:
      # Fetch artifacts from the merge control file dir.
      self.fuzzer.device.fetch(target_merge_control_dir, merge_control_dir)
      self.fuzzer.device.rm(target_merge_control_dir, recursive=True)

    self._clear_all_target_corpora()

    # TODO(flowerhack): Return actual output for accurate stats tracking.
    merge_result = new_process.ProcessResult()
    merge_result.return_code = 0
    merge_result.timed_out = False
    merge_result.output = ''
    merge_result.time_executed = 0
    merge_result.command = ''
    return merge_result

  def run_single_testcase(self,
                          testcase_path,
                          timeout=None,
                          additional_args=None):
    """Run a single testcase."""
    self._test_ssh()

    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []

    # We need to push the testcase to the device and pass in the name.
    testcase_path_name = os.path.basename(os.path.normpath(testcase_path))
    self.device.store(testcase_path, self.fuzzer.data_path())

    return_code = self.fuzzer.start(['repro', 'data/' + testcase_path_name] +
                                    additional_args)
    self.fuzzer.monitor(return_code)

    with open(
        self.fuzzer.logfile, encoding='utf-8', errors='ignore') as logfile:
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
    self._test_ssh()

    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []
    additional_args.append(constants.MINIMIZE_CRASH_ARGUMENT)
    max_total_time = self.get_minimize_total_time(timeout)
    max_total_time_arg = constants.MAX_TOTAL_TIME_FLAG + str(max_total_time)
    additional_args.append(max_total_time_arg)

    # TODO(flowerhack): libfuzzer-on-Fuchsia believes that all files are in
    # the directory 'data/'.  We bake that 'data/' assumption into this file
    # in a few places--may need to move it into constants?
    target_artifact_prefix = 'data/'
    target_minimized_file = 'final-minimized-crash'
    min_file_fullpath = target_artifact_prefix + target_minimized_file
    exact_artifact_arg = constants.EXACT_ARTIFACT_PATH_FLAG + min_file_fullpath
    additional_args.append(exact_artifact_arg)

    # We need to push the testcase to the device and pass in the name.
    testcase_path_name = os.path.basename(os.path.normpath(testcase_path))
    self.device.store(testcase_path, self.fuzzer.data_path())

    return_code = self.fuzzer.start(
        additional_args + [target_artifact_prefix + testcase_path_name])
    self.fuzzer.monitor(return_code)

    with open(
        self.fuzzer.logfile, encoding='utf-8', errors='ignore') as logfile:
      symbolized_output = logfile.read()

    output_dir = os.path.dirname(output_path)
    self.device.fetch(self.fuzzer.data_path(target_minimized_file), output_dir)
    shutil.move(os.path.join(output_dir, target_minimized_file), output_path)

    fuzzer_process_result = new_process.ProcessResult()
    fuzzer_process_result.return_code = return_code
    fuzzer_process_result.output = symbolized_output
    fuzzer_process_result.time_executed = 0
    # It's not a standard fuzzer command, so don't save it.
    fuzzer_process_result.command = None
    return fuzzer_process_result

  def ssh_command(self, *args):
    return ['ssh'] + self.ssh_root + list(args)


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
    self._copy_local_directory_to_device(build_directory)

  def _get_default_args(self, executable_path, extra_args):
    """Return a set of default arguments to pass to adb binary."""
    default_args = ['shell']

    # Add directory containing libclang_rt.ubsan_standalone-aarch64-android.so
    # to LD_LIBRARY_PATH.
    ld_library_path = android.sanitizer.get_ld_library_path_for_sanitizers()
    if ld_library_path:
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
      self._copy_local_directory_to_device(local_directory)

  def _copy_local_directory_to_device(self, local_directory):
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

  def _append_logcat_output_if_needed(self, output):
    """Add logcat output to end of output to capture crashes from related
    processes if current output has no sanitizer crash."""
    if 'Sanitizer: ' in output:
      return output

    return '{output}\n\nLogcat:\n{logcat_output}'.format(
        output=output, logcat_output=android.logger.log_output())

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

  def analyze_dictionary(self,
                         dictionary_path,
                         corpus_directory,
                         analyze_timeout,
                         artifact_prefix=None,
                         additional_args=None):
    """LibFuzzerCommon.analyze_dictionary override."""
    sync_directories = [corpus_directory]
    if artifact_prefix:
      sync_directories.append(artifact_prefix)

    self._copy_local_directories_to_device(sync_directories)
    corpus_directory = self._get_device_path(corpus_directory)

    if artifact_prefix:
      artifact_prefix = self._get_device_path(artifact_prefix)

    with self._device_file(dictionary_path) as device_dictionary_path:
      return LibFuzzerCommon.analyze_dictionary(
          self, device_dictionary_path, corpus_directory, analyze_timeout,
          artifact_prefix, additional_args)

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
    additional_args = copy.copy(additional_args)
    if additional_args is None:
      additional_args = []
    dict_path = fuzzer_utils.extract_argument(additional_args,
                                              constants.DICT_FLAG)
    if dict_path:
      device_dict_path = self._get_device_path(dict_path)
      android.adb.copy_local_file_to_remote(dict_path, device_dict_path)
      additional_args.append(constants.DICT_FLAG + device_dict_path)

    result = LibFuzzerCommon.fuzz(
        self,
        corpus_directories,
        fuzz_timeout,
        artifact_prefix=artifact_prefix,
        additional_args=additional_args,
        extra_env=extra_env)

    result.output = self._append_logcat_output_if_needed(result.output)

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
      result.output = self._append_logcat_output_if_needed(result.output)
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


def get_runner(fuzzer_path, temp_dir=None, use_minijail=None, use_unshare=None):
  """Get a libfuzzer runner."""
  if use_minijail is None:
    use_minijail = environment.get_value('USE_MINIJAIL')

  if use_unshare is None:
    use_unshare = environment.get_value('USE_UNSHARE')

  if use_minijail is False:
    # If minijail is explicitly disabled, set the environment variable as well.
    environment.set_value('USE_MINIJAIL', False)

  if temp_dir is None:
    temp_dir = fuzzer_utils.get_temp_dir()

  build_dir = environment.get_value('BUILD_DIR')
  dataflow_build_dir = environment.get_value('DATAFLOW_BUILD_DIR')
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
  elif is_android:
    runner = AndroidLibFuzzerRunner(fuzzer_path, build_dir)
  elif use_unshare:
    runner = UnshareLibFuzzerRunner(fuzzer_path)  # pylint: disable=too-many-function-args
  else:
    runner = LibFuzzerRunner(fuzzer_path)

  return runner


def add_recommended_dictionary(arguments, fuzzer_name, fuzzer_path):
  """Add recommended dictionary from GCS to existing .dict file or create
  a new one and update the arguments as needed.
  This function modifies |arguments| list in some cases."""
  recommended_dictionary_path = os.path.join(
      fuzzer_utils.get_temp_dir(),
      dictionary_manager.RECOMMENDED_DICTIONARY_FILENAME)

  dict_manager = dictionary_manager.DictionaryManager(fuzzer_name)

  try:
    # Bail out if cannot download recommended dictionary from GCS.
    if not dict_manager.download_recommended_dictionary_from_gcs(
        recommended_dictionary_path):
      return False
  except Exception as ex:
    logs.log_error(
        'Exception downloading recommended dictionary:\n%s.' % str(ex))
    return False

  # Bail out if the downloaded dictionary is empty.
  if not os.path.getsize(recommended_dictionary_path):
    return False

  # Check if there is an existing dictionary file in arguments.
  original_dictionary_path = fuzzer_utils.extract_argument(
      arguments, constants.DICT_FLAG)
  merged_dictionary_path = (
      original_dictionary_path or
      dictionary_manager.get_default_dictionary_path(fuzzer_path))
  merged_dictionary_path += MERGED_DICT_SUFFIX

  dictionary_manager.merge_dictionary_files(original_dictionary_path,
                                            recommended_dictionary_path,
                                            merged_dictionary_path)
  arguments.append(constants.DICT_FLAG + merged_dictionary_path)
  return True


def get_dictionary_analysis_timeout():
  """Get timeout for dictionary analysis."""
  return engine_common.get_overridable_timeout(5 * 60,
                                               'DICTIONARY_TIMEOUT_OVERRIDE')


def analyze_and_update_recommended_dictionary(runner, fuzzer_name, log_lines,
                                              corpus_directory, arguments):
  """Extract and analyze recommended dictionary from fuzzer output, then update
  the corresponding dictionary stored in GCS if needed."""
  if environment.platform() == 'FUCHSIA':
    # TODO(flowerhack): Support this.
    return None

  logs.log(
      'Extracting and analyzing recommended dictionary for %s.' % fuzzer_name)

  # Extract recommended dictionary elements from the log.
  dict_manager = dictionary_manager.DictionaryManager(fuzzer_name)
  recommended_dictionary = (
      dict_manager.parse_recommended_dictionary_from_log_lines(log_lines))
  if not recommended_dictionary:
    logs.log('No recommended dictionary in output from %s.' % fuzzer_name)
    return None

  # Write recommended dictionary into a file and run '-analyze_dict=1'.
  temp_dictionary_filename = (
      fuzzer_name + dictionary_manager.DICTIONARY_FILE_EXTENSION + '.tmp')
  temp_dictionary_path = os.path.join(fuzzer_utils.get_temp_dir(),
                                      temp_dictionary_filename)

  with open(temp_dictionary_path, 'wb') as file_handle:
    file_handle.write('\n'.join(recommended_dictionary).encode('utf-8'))

  dictionary_analysis = runner.analyze_dictionary(
      temp_dictionary_path,
      corpus_directory,
      analyze_timeout=get_dictionary_analysis_timeout(),
      additional_args=arguments)

  if dictionary_analysis.timed_out:
    logs.log_warn(
        'Recommended dictionary analysis for %s timed out.' % fuzzer_name)
    return None

  if dictionary_analysis.return_code != 0:
    logs.log_warn('Recommended dictionary analysis for %s failed: %d.' %
                  (fuzzer_name, dictionary_analysis.return_code))
    return None

  # Extract dictionary elements considered useless, calculate the result.
  useless_dictionary = dict_manager.parse_useless_dictionary_from_data(
      dictionary_analysis.output)

  logs.log('%d out of %d recommended dictionary elements for %s are useless.' %
           (len(useless_dictionary), len(recommended_dictionary), fuzzer_name))

  recommended_dictionary = set(recommended_dictionary) - set(useless_dictionary)
  if not recommended_dictionary:
    return None

  new_elements_added = dict_manager.update_recommended_dictionary(
      recommended_dictionary)
  logs.log('Added %d new elements to the recommended dictionary for %s.' %
           (new_elements_added, fuzzer_name))

  return recommended_dictionary


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


def remove_fuzzing_arguments(arguments, is_merge=False):
  """Remove arguments used during fuzzing."""
  for argument in [
      # Remove as it overrides `-merge` argument.
      constants.FORK_FLAG,  # It overrides `-merge` argument.

      # Remove as it may shrink the testcase.
      constants.MAX_LEN_FLAG,  # This may shrink the testcases.

      # Remove any existing runs argument as we will create our own for
      # reproduction.
      constants.RUNS_FLAG,  # Make sure we don't have any '-runs' argument.

      # Remove the following flags/arguments that are only used for fuzzing.
      constants.DATA_FLOW_TRACE_FLAG,
      constants.DICT_FLAG,
      constants.FOCUS_FUNCTION_FLAG,
  ]:
    fuzzer_utils.extract_argument(arguments, argument)

  # Value profile is needed during corpus merge, so do not remove if set.
  if not is_merge:
    fuzzer_utils.extract_argument(arguments, constants.VALUE_PROFILE_ARGUMENT)


def fix_timeout_argument_for_reproduction(arguments):
  """Changes timeout argument for reproduction. This is slightly less than the
  |TEST_TIMEOUT| value for the job."""
  fuzzer_utils.extract_argument(arguments, constants.TIMEOUT_FLAG)

  # Leave 5 sec buffer for report processing.
  adjusted_test_timeout = max(
      1,
      environment.get_value('TEST_TIMEOUT') - constants.REPORT_PROCESSING_TIME)
  arguments.append('%s%d' % (constants.TIMEOUT_FLAG, adjusted_test_timeout))


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


def set_sanitizer_options(fuzzer_path, fuzz_options=None):
  """Sets sanitizer options based on .options file overrides, FuzzOptions (if
  provided), and what this script requires."""
  engine_common.process_sanitizer_options_overrides(fuzzer_path)
  sanitizer_options_var = environment.get_current_memory_tool_var()
  sanitizer_options = environment.get_memory_tool_options(
      sanitizer_options_var, {})
  sanitizer_options['exitcode'] = constants.TARGET_ERROR_EXITCODE
  if fuzz_options and fuzz_options.use_dataflow_tracing:
    # Focus function feature does not work without symbolization.
    sanitizer_options['symbolize'] = 1
    environment.update_symbolizer_options(sanitizer_options)
  environment.set_memory_tool_options(sanitizer_options_var, sanitizer_options)


def get_fuzz_timeout(is_mutations_run, total_timeout=None):
  """Get the fuzz timeout."""
  fuzz_timeout = (
      engine_common.get_hard_timeout(total_timeout=total_timeout) -
      engine_common.get_merge_timeout(DEFAULT_MERGE_TIMEOUT) -
      get_dictionary_analysis_timeout())

  if is_mutations_run:
    fuzz_timeout -= engine_common.get_new_testcase_mutations_timeout()

  return fuzz_timeout


def use_mutator_plugin(target_name, extra_env):
  """Decide whether to use a mutator plugin. If yes and there is a usable plugin
  available for |target_name|, then add it to LD_PRELOAD in |extra_env|, and
  return True."""
  if not environment.get_value('MUTATOR_PLUGINS_DIR'):
    return False

  # TODO(metzman): Support Windows.
  if environment.platform() == 'WINDOWS':
    return False

  mutator_plugin_path = mutator_plugin.get_mutator_plugin(target_name)
  if not mutator_plugin_path:
    return False

  logs.log('Using mutator plugin: %s' % mutator_plugin_path)
  # TODO(metzman): Change the strategy to record which plugin was used, and
  # not simply that a plugin was used.
  extra_env['LD_PRELOAD'] = mutator_plugin_path
  return True


def is_linux_asan():
  """Helper functions. Returns whether or not the current env is linux asan."""
  return (environment.platform() != 'LINUX' or
          environment.get_value('MEMORY_TOOL') != 'ASAN')


def use_radamsa_mutator_plugin(extra_env):
  """Decide whether to use Radamsa in process. If yes, add the path to the
  radamsa shared object to LD_PRELOAD in |extra_env| and return True."""
  # Radamsa will only work on LINUX ASAN jobs.
  # TODO(mpherman): Include architecture info in job definition and exclude
  # i386.
  if environment.is_lib() or not is_linux_asan():
    return False

  radamsa_path = os.path.join(environment.get_platform_resources_directory(),
                              'radamsa', 'libradamsa.so')

  logs.log('Using Radamsa mutator plugin : %s' % radamsa_path)
  extra_env['LD_PRELOAD'] = radamsa_path
  return True


def use_peach_mutator(extra_env, grammar):
  """Decide whether or not to use peach mutator, and set up all of the
  environment variables necessary to do so."""
  # TODO(mpherman): Include architecture info in job definition and exclude
  # i386.
  if environment.is_lib() or not is_linux_asan():
    return False

  if not grammar:
    return False

  pit_path = pits.get_path(grammar)

  if not pit_path:
    return False

  # Set title and pit environment variables
  extra_env['PIT_FILENAME'] = pit_path
  extra_env['PIT_TITLE'] = grammar

  # Extract zip of peach mutator code.
  peach_dir = os.path.join(environment.get_platform_resources_directory(),
                           'peach')
  unzipped = os.path.join(peach_dir, 'mutator')
  source = os.path.join(peach_dir, 'peach_mutator.zip')

  archive.unpack(source, unzipped, trusted=True)

  # Set LD_PRELOAD.
  peach_path = os.path.join(unzipped, 'peach_mutator', 'src', 'peach.so')
  extra_env['LD_PRELOAD'] = peach_path

  # Set Python path.
  new_path = [
      os.path.join(unzipped, 'peach_mutator', 'src'),
      os.path.join(unzipped, 'peach_mutator', 'third_party', 'peach'),
  ] + sys.path

  extra_env['PYTHONPATH'] = os.pathsep.join(new_path)

  return True


def is_sha1_hash(possible_hash):
  """Returns True if |possible_hash| looks like a valid sha1 hash."""
  if len(possible_hash) != 40:
    return False

  hexdigits_set = set(string.hexdigits)
  return all(char in hexdigits_set for char in possible_hash)


def move_mergeable_units(merge_directory, corpus_directory):
  """Move new units in |merge_directory| into |corpus_directory|."""
  initial_units = set(
      os.path.basename(filename)
      for filename in shell.get_files_list(corpus_directory))

  for unit_path in shell.get_files_list(merge_directory):
    unit_name = os.path.basename(unit_path)
    if unit_name in initial_units and is_sha1_hash(unit_name):
      continue
    dest_path = os.path.join(corpus_directory, unit_name)
    shell.move(unit_path, dest_path)


def has_existing_mutator_strategy(fuzzing_strategy):
  return any(strategy in fuzzing_strategy for strategy in MUTATOR_STRATEGIES)


def pick_strategies(strategy_pool,
                    fuzzer_path,
                    corpus_directory,
                    existing_arguments,
                    grammar=None):
  """Pick strategies."""
  build_directory = environment.get_value('BUILD_DIR')
  target_name = os.path.basename(fuzzer_path)
  project_qualified_fuzzer_name = data_types.fuzz_target_project_qualified_name(
      utils.current_project(), target_name)

  fuzzing_strategies = []
  arguments = []
  additional_corpus_dirs = []

  # Select a generator to attempt to use for existing testcase mutations.
  candidate_generator = engine_common.select_generator(strategy_pool,
                                                       fuzzer_path)
  is_mutations_run = (not environment.is_ephemeral() and
                      candidate_generator != engine_common.Generator.NONE)

  # Depends on the presense of DFSan instrumented build.
  dataflow_build_dir = environment.get_value('DATAFLOW_BUILD_DIR')
  use_dataflow_tracing = (
      dataflow_build_dir and
      strategy_pool.do_strategy(strategy.DATAFLOW_TRACING_STRATEGY))
  if use_dataflow_tracing:
    dataflow_binary_path = os.path.join(
        dataflow_build_dir, os.path.relpath(fuzzer_path, build_directory))
    dataflow_trace_dir = dataflow_binary_path + DATAFLOW_TRACE_DIR_SUFFIX
    if os.path.exists(dataflow_trace_dir):
      arguments.append(
          '%s%s' % (constants.DATA_FLOW_TRACE_FLAG, dataflow_trace_dir))
      arguments.append('%s%s' % (constants.FOCUS_FUNCTION_FLAG, 'auto'))
      fuzzing_strategies.append(strategy.DATAFLOW_TRACING_STRATEGY.name)
    else:
      logs.log_warn(
          'Dataflow trace is not found in dataflow build, skipping strategy.')
      use_dataflow_tracing = False

  # Generate new testcase mutations using radamsa, etc.
  if is_mutations_run:
    new_testcase_mutations_directory = create_corpus_directory('mutations')
    generator_used = engine_common.generate_new_testcase_mutations(
        corpus_directory, new_testcase_mutations_directory,
        project_qualified_fuzzer_name, candidate_generator)

    # Add the used generator strategy to our fuzzing strategies list.
    if generator_used:
      if candidate_generator == engine_common.Generator.RADAMSA:
        fuzzing_strategies.append(
            strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name)
      elif candidate_generator == engine_common.Generator.ML_RNN:
        fuzzing_strategies.append(strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name)

    additional_corpus_dirs.append(new_testcase_mutations_directory)

  if strategy_pool.do_strategy(strategy.RANDOM_MAX_LENGTH_STRATEGY):
    max_len_argument = fuzzer_utils.extract_argument(
        existing_arguments, constants.MAX_LEN_FLAG, remove=False)
    if not max_len_argument:
      max_length = random.SystemRandom().randint(1, MAX_VALUE_FOR_MAX_LENGTH)
      arguments.append('%s%d' % (constants.MAX_LEN_FLAG, max_length))
      fuzzing_strategies.append(strategy.RANDOM_MAX_LENGTH_STRATEGY.name)

  if (strategy_pool.do_strategy(strategy.RECOMMENDED_DICTIONARY_STRATEGY) and
      add_recommended_dictionary(arguments, project_qualified_fuzzer_name,
                                 fuzzer_path)):
    fuzzing_strategies.append(strategy.RECOMMENDED_DICTIONARY_STRATEGY.name)

  if strategy_pool.do_strategy(strategy.VALUE_PROFILE_STRATEGY):
    arguments.append(constants.VALUE_PROFILE_ARGUMENT)
    fuzzing_strategies.append(strategy.VALUE_PROFILE_STRATEGY.name)

  # FIXME: Disable for now to avoid severe battery drainage. Stabilize and
  # re-enable with a lower process count.
  is_android = environment.is_android()
  # Fork mode is not supported on Fuchsia platform.
  is_fuchsia = environment.platform() == 'FUCHSIA'
  # Fork mode is disabled on ephemeral bots due to a bug on the platform.
  is_ephemeral = environment.is_ephemeral()

  # Do not use fork mode for DFT-based fuzzing. This is needed in order to
  # collect readable and actionable logs from fuzz targets running with DFT.
  if (not is_fuchsia and not is_android and not is_ephemeral and
      not use_dataflow_tracing and
      strategy_pool.do_strategy(strategy.FORK_STRATEGY)):
    max_fuzz_threads = environment.get_value('MAX_FUZZ_THREADS', 1)
    num_fuzz_processes = max(1, utils.cpu_count() // max_fuzz_threads)
    arguments.append('%s%d' % (constants.FORK_FLAG, num_fuzz_processes))
    fuzzing_strategies.append(
        '%s_%d' % (strategy.FORK_STRATEGY.name, num_fuzz_processes))

  extra_env = {}
  if (strategy_pool.do_strategy(strategy.MUTATOR_PLUGIN_STRATEGY) and
      use_mutator_plugin(target_name, extra_env)):
    fuzzing_strategies.append(strategy.MUTATOR_PLUGIN_STRATEGY.name)

  if (not has_existing_mutator_strategy(fuzzing_strategies) and
      strategy_pool.do_strategy(strategy.PEACH_GRAMMAR_MUTATION_STRATEGY) and
      use_peach_mutator(extra_env, grammar)):
    fuzzing_strategies.append(
        '%s_%s' % (strategy.PEACH_GRAMMAR_MUTATION_STRATEGY.name, grammar))

  if (not has_existing_mutator_strategy(fuzzing_strategies) and
      strategy_pool.do_strategy(strategy.MUTATOR_PLUGIN_RADAMSA_STRATEGY) and
      use_radamsa_mutator_plugin(extra_env)):
    fuzzing_strategies.append(strategy.MUTATOR_PLUGIN_RADAMSA_STRATEGY.name)

  return StrategyInfo(fuzzing_strategies, arguments, additional_corpus_dirs,
                      extra_env, use_dataflow_tracing, is_mutations_run)
