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
"""Functions for testcase management."""

import base64
import collections
import datetime
import os
import re
import zlib

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

# Testcase filename prefixes and suffixes.
CRASH_PREFIX = 'crash-'
FUZZ_PREFIX = 'fuzz-'
FLAGS_PREFIX = 'flags-'
HTTP_PREFIX = 'http-'
RESOURCES_PREFIX = 'resources-'

# TODO(mbarbella): Once all fuzzers are converted to "resources-", remove this.
DEPENDENCY_PREFIX = 'cfdependency-'
APPS_PREFIX = 'fuzz-apps-'
EXTENSIONS_PREFIX = 'fuzz-extension-'
COVERAGE_SUFFIX = '.cov'

INFO_FILE_EXTENSION = '.info'
IPCDUMP_EXTENSION = '.ipcdump'
REPRODUCIBILITY_FACTOR = 0.5
SEARCH_INDEX_TESTCASES_DIRNAME = 'common'
SEARCH_INDEX_BUNDLE_PREFIX = '__%s_' % SEARCH_INDEX_TESTCASES_DIRNAME
TESTCASE_LIST_FILENAME = 'files.info'

CHROME_URL_LOAD_REGEX = re.compile(
    r'.*(NetworkDelegate::NotifyBeforeURLRequest|FileURLLoader::Start)'
    r':\s+(.*)')
FILE_URL_REGEX = re.compile(r'file:///([^"#?]+)')
HTTP_URL_REGEX = re.compile(
    r'.*(localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^/]*[/]([^"#?]+)')

BAD_STATE_HINTS = [
    # X server issues.
    'cannot open display',
    'Maximum number of clients reached',
    'Missing X server',

    # Android logging issues.
    'logging service has stopped',
]


class TestcaseManagerError(Exception):
  """Base exception."""


class TargetNotFoundError(TestcaseManagerError):
  """Error when a fuzz target is not found."""


def create_testcase_list_file(output_directory):
  """Create a testcase list file for tests in a directory."""
  files_list = []
  files_list_file_path = os.path.join(output_directory, TESTCASE_LIST_FILENAME)
  for root, _, files in shell.walk(output_directory):
    for filename in files:
      if filename.endswith(INFO_FILE_EXTENSION):
        # Skip an info file.
        continue

      file_path = os.path.join(root, filename)
      if not utils.is_valid_testcase_file(file_path, check_if_exists=False):
        continue

      normalized_relative_file_path = utils.get_normalized_relative_path(
          file_path, output_directory)
      files_list.append(normalized_relative_file_path)

  utils.write_data_to_file('\n'.join(sorted(files_list)), files_list_file_path)


def get_testcases_from_directories(directories):
  """Returns all testcases from testcase directories."""
  testcase_paths = []
  max_testcases = environment.get_value('MAX_TESTCASES')

  generators = []
  for directory in directories:
    if not directory.strip():
      continue

    generators.append(shell.walk(directory))

  for generator in generators:
    for structure in generator:
      base_directory = structure[0]
      for filename in structure[2]:
        if not filename.startswith(FUZZ_PREFIX):
          continue

        if filename.endswith(COVERAGE_SUFFIX):
          continue

        file_path = os.path.join(base_directory, filename)
        if not os.path.getsize(file_path):
          continue

        testcase_paths.append(utils.normalize_path(file_path))
        if len(testcase_paths) == max_testcases:
          return testcase_paths

  return testcase_paths


def is_testcase_resource(filename):
  """Returns true if this is a testcase or its resource dependency."""
  if filename.startswith(FUZZ_PREFIX):
    return True

  if filename.startswith(FLAGS_PREFIX):
    return True

  if filename.startswith(DEPENDENCY_PREFIX):
    return True

  if filename.startswith(RESOURCES_PREFIX):
    return True

  if filename.endswith(COVERAGE_SUFFIX):
    return True

  return False


def remove_testcases_from_directories(directories):
  """Removes all testcases and their dependencies from testcase directories."""
  generators = []
  for directory in directories:
    if not directory.strip():
      continue

    # If there is a bot-specific files list, delete it now.
    bot_testcases_file_path = utils.get_bot_testcases_file_path(directory)
    shell.remove_file(bot_testcases_file_path)

    generators.append(shell.walk(directory))

  for generator in generators:
    for structure in generator:
      base_directory = structure[0]
      for filename in structure[2]:
        if not is_testcase_resource(filename):
          continue

        if filename.startswith(RESOURCES_PREFIX):
          # In addition to removing this file, remove all resources.
          resources_file_path = os.path.join(base_directory, filename)
          resources = read_resource_list(resources_file_path)
          for resource in resources:
            shell.remove_file(resource)

        file_path = os.path.join(base_directory, filename)
        shell.remove_file(file_path)


def read_resource_list(resource_file_path):
  """Generate a resource list."""
  if not os.path.exists(resource_file_path):
    return []

  resources = []
  base_directory = os.path.dirname(resource_file_path)
  with open(resource_file_path) as file_handle:
    resource_file_contents = file_handle.read()
    for line in resource_file_contents.splitlines():
      resource = os.path.join(base_directory, line.strip())
      if not os.path.exists(resource):
        break

      resources.append(resource)

  return resources


def get_resource_dependencies(testcase_absolute_path, test_prefix=FUZZ_PREFIX):
  """Returns the list of testcase resource dependencies."""
  resources = []
  if not os.path.exists(testcase_absolute_path):
    return resources

  base_directory = os.path.dirname(testcase_absolute_path)
  testcase_filename = os.path.basename(testcase_absolute_path)

  # FIXME(mbarbella): Remove this when all fuzzers are using "resources-".
  # This code includes the dependencies that begin with
  # dependency prefix and are referenced in the testcase.
  testcase_contents = None
  for filename in os.listdir(base_directory):
    if filename.startswith(DEPENDENCY_PREFIX):
      # Only load the testcase contents if necessary.
      if not testcase_contents:
        with open(testcase_absolute_path, 'rb') as file_handle:
          testcase_contents = file_handle.read()

      if filename.encode('utf-8') in testcase_contents:
        file_path = os.path.join(base_directory, filename)
        resources.append(file_path)

  # This code includes the dependencies in cases when the testcase itself is a
  # just a wrapper file around the actual testcase.
  if DEPENDENCY_PREFIX in testcase_absolute_path:
    dependency_filename = os.path.splitext(testcase_filename)[0]
    dependency_filename = re.compile(DEPENDENCY_PREFIX).sub(
        '', dependency_filename, 1)
    dependency_filename = re.compile(FUZZ_PREFIX).sub('', dependency_filename,
                                                      1)
    dependency_filename = re.compile(HTTP_PREFIX).sub('', dependency_filename,
                                                      1)
    dependency_file_path = os.path.join(base_directory, dependency_filename)
    resources.append(dependency_file_path)

  # Check to see if this test case lists all resources in a resources file.
  if testcase_filename.startswith(test_prefix):
    stripped_testcase_name = testcase_filename[len(test_prefix):]
    resources_filename = '%s%s' % (RESOURCES_PREFIX, stripped_testcase_name)
    resources_file_path = os.path.join(base_directory, resources_filename)
    resources += read_resource_list(resources_file_path)

  # For extensions, archive everything in the extension directory.
  if APPS_PREFIX in testcase_filename or EXTENSIONS_PREFIX in testcase_filename:
    for root, _, files in shell.walk(base_directory):
      for filename in files:
        file_path = os.path.join(root, filename)
        if file_path == testcase_absolute_path:
          continue

        resources.append(file_path)

  return resources


def get_command_line_flags(testcase_path):
  """Returns command line flags to use for a testcase."""
  arguments = environment.get_value('APP_ARGS')
  additional_arguments = get_additional_command_line_flags(testcase_path)
  if arguments:
    arguments += ' ' + additional_arguments
  else:
    arguments = additional_arguments

  return arguments.strip()


def get_additional_command_line_flags(testcase_path):
  """Returns additional command line flags to use for a testcase."""
  # Get the initial flags list from the environment value.
  additional_command_line_flags = (
      environment.get_value('ADDITIONAL_COMMAND_LINE_FLAGS', ''))

  # If we don't have a fuzz prefix, no need to look further for flags file.
  testcase_filename = os.path.basename(testcase_path)
  if not testcase_filename.startswith(FUZZ_PREFIX):
    return additional_command_line_flags

  # Gets the flags list from the flags file.
  stripped_testcase_name = testcase_filename[len(FUZZ_PREFIX):]
  flags_filename = '%s%s' % (FLAGS_PREFIX, stripped_testcase_name)
  flags_file_path = os.path.join(os.path.dirname(testcase_path), flags_filename)
  flags_file_content = utils.read_data_from_file(
      flags_file_path, eval_data=False)
  if flags_file_content:
    additional_command_line_flags += ' ' + flags_file_content.decode('utf-8')
  return additional_command_line_flags.strip()


def run_testcase(thread_index, file_path, gestures, env_copy):
  """Run a single testcase and return crash results in the crash queue."""
  try:
    # Update environment with environment copy from parent.
    if env_copy:
      os.environ.update(env_copy)

    # Initialize variables.
    needs_http = '-http-' in file_path
    test_timeout = environment.get_value('TEST_TIMEOUT', 10)
    app_directory = environment.get_value('APP_DIR')
    environment.set_value('PIDS', '[]')

    # Get command line options.
    command = get_command_line_for_application(
        file_path, user_profile_index=thread_index, needs_http=needs_http)

    # Run testcase.
    return process_handler.run_process(
        command,
        timeout=test_timeout,
        gestures=gestures,
        env_copy=env_copy,
        current_working_directory=app_directory)
  except Exception:
    logs.log_error('Exception occurred while running run_testcase.')

    return None, None, None


class Crash(
    collections.namedtuple(
        'Crash', 'file_path crash_time return_code resource_list gestures '
        'stack_file_path')):
  """Represents a crash in a queue. This class is transformed into
    fuzz_task.Crash. Therefore, please be careful when adding/removing
    fields."""


def get_resource_paths(output):
  """Read the urls from the output."""
  resource_paths = set()
  for line in output.splitlines():
    match = CHROME_URL_LOAD_REGEX.match(line)
    if not match:
      continue

    local_path = convert_dependency_url_to_local_path(match.group(2))
    if local_path:
      logs.log('Detected resource: %s.' % local_path)
      resource_paths.add(local_path)

  return list(resource_paths)


def convert_dependency_url_to_local_path(url):
  """Convert a dependency URL to a corresponding local path."""
  # Bot-specific import.
  from clusterfuzz._internal.bot.webserver import http_server

  logs.log('Process dependency: %s.' % url)
  file_match = FILE_URL_REGEX.search(url)
  http_match = HTTP_URL_REGEX.search(url)
  platform = environment.platform()

  local_path = None
  if file_match:
    file_path = file_match.group(1)
    logs.log('Detected file dependency: %s.' % file_path)
    if platform == 'WINDOWS':
      local_path = file_path
    else:
      local_path = '/' + file_path

      # Convert remote to local path for android.
      if environment.is_android():
        remote_testcases_directory = android.constants.DEVICE_TESTCASES_DIR
        local_testcases_directory = environment.get_value('FUZZ_INPUTS')
        local_path = local_path.replace(remote_testcases_directory,
                                        local_testcases_directory)

  elif http_match:
    relative_http_path = os.path.sep + http_match.group(2)
    logs.log('Detected http dependency: %s.' % relative_http_path)
    local_path = http_server.get_absolute_testcase_file(relative_http_path)
    if not local_path:
      # This needs to be a warning since in many cases, it is actually a
      # non-existent path. For others, we need to add the directory aliases in
      # file http_server.py.
      logs.log_warn(
          'Unable to find server resource %s, skipping.' % relative_http_path)

  if local_path:
    local_path = utils.normalize_path(local_path)

  return local_path


def _get_testcase_time(testcase_path):
  """Returns the timestamp of a testcase."""
  stats = fuzzer_stats.TestcaseRun.read_from_disk(testcase_path)
  if stats:
    return datetime.datetime.utcfromtimestamp(float(stats.timestamp))

  return None


def upload_testcase(testcase_path, log_time):
  """Uploads testcase so that a log file can be matched with it folder."""
  fuzz_logs_bucket = environment.get_value('FUZZ_LOGS_BUCKET')
  if not fuzz_logs_bucket:
    return

  if not os.path.exists(testcase_path):
    return

  with open(testcase_path, 'rb') as file_handle:
    testcase_contents = file_handle.read()

  fuzzer_logs.upload_to_logs(
      fuzz_logs_bucket,
      testcase_contents,
      time=log_time,
      file_extension='.testcase')


def _get_crash_output(output):
  """Returns crash part of the output, excluding unrelated content (e.g. output
  from corpus merge, etc)."""
  if output is None:
    return None

  crash_stacktrace_end_marker_index = output.find(
      data_types.CRASH_STACKTRACE_END_MARKER)
  if crash_stacktrace_end_marker_index == -1:
    return output

  return output[:crash_stacktrace_end_marker_index]


def run_testcase_and_return_result_in_queue(crash_queue,
                                            thread_index,
                                            file_path,
                                            gestures,
                                            env_copy,
                                            upload_output=False):
  """Run a single testcase and return crash results in the crash queue."""
  # Since this is running in its own process, initialize the log handler again.
  # This is needed for Windows where instances are not shared across child
  # processes. See:
  # https://stackoverflow.com/questions/34724643/python-logging-with-multiprocessing-root-logger-different-in-windows
  logs.configure('run_testcase', {
      'testcase_path': file_path,
  })

  # Also reinitialize NDB context for the same reason as above.
  with ndb_init.context():
    _do_run_testcase_and_return_result_in_queue(
        crash_queue,
        thread_index,
        file_path,
        gestures,
        env_copy,
        upload_output=upload_output)


def _do_run_testcase_and_return_result_in_queue(crash_queue,
                                                thread_index,
                                                file_path,
                                                gestures,
                                                env_copy,
                                                upload_output=False):
  """Run a single testcase and return crash results in the crash queue."""
  try:
    # Run testcase and check whether a crash occurred or not.
    return_code, crash_time, output = run_testcase(thread_index, file_path,
                                                   gestures, env_copy)

    # Pull testcase directory to host to get any stats files.
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      file_host.pull_testcases_from_worker()

    # Analyze the crash.
    crash_output = _get_crash_output(output)
    crash_result = CrashResult(return_code, crash_time, crash_output)

    # To provide consistency between stats and logs, we use timestamp taken
    # from stats when uploading logs and testcase.
    if upload_output:
      log_time = _get_testcase_time(file_path)

    if crash_result.is_crash():
      # Initialize resource list with the testcase path.
      resource_list = [file_path]
      resource_list += get_resource_paths(crash_output)

      # Store the crash stack file in the crash stacktrace directory
      # with filename as the hash of the testcase path.
      crash_stacks_directory = environment.get_value('CRASH_STACKTRACES_DIR')
      stack_file_path = os.path.join(crash_stacks_directory,
                                     utils.string_hash(file_path))
      utils.write_data_to_file(crash_output, stack_file_path)

      # Put crash/no-crash results in the crash queue.
      crash_queue.put(
          Crash(
              file_path=file_path,
              crash_time=crash_time,
              return_code=return_code,
              resource_list=resource_list,
              gestures=gestures,
              stack_file_path=stack_file_path))

      # Don't upload uninteresting testcases (no crash) or if there is no log to
      # correlate it with (not upload_output).
      if upload_output:
        upload_testcase(file_path, log_time)

    if upload_output:
      # Include full output for uploaded logs (crash output, merge output, etc).
      crash_result_full = CrashResult(return_code, crash_time, output)
      log = prepare_log_for_upload(crash_result_full.get_stacktrace(),
                                   return_code)
      upload_log(log, log_time)
  except Exception:
    logs.log_error('Exception occurred while running '
                   'run_testcase_and_return_result_in_queue.')


def engine_reproduce(engine_impl, target_name, testcase_path, arguments,
                     timeout):
  """Do engine reproduction."""
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import tasks_host
    return tasks_host.engine_reproduce(engine_impl, target_name, testcase_path,
                                       arguments, timeout)
  build_dir = environment.get_value('BUILD_DIR')
  is_blackbox = engine_impl.name == 'blackbox'
  target_path = engine_common.find_fuzzer_path(
      build_dir, target_name, is_blackbox=is_blackbox)
  if not target_path:
    raise TargetNotFoundError('Failed to find target ' + target_name)

  result = engine_impl.reproduce(target_path, testcase_path, list(arguments),
                                 timeout)

  # This matches the check in process_handler.run_process.
  if not result.return_code and \
      (crash_analyzer.is_memory_tool_crash(result.output) or
       crash_analyzer.is_check_failure_crash(result.output)):
    result.return_code = 1

  return result


class TestcaseRunner(object):
  """Testcase runner."""

  def __init__(self,
               fuzz_target,
               testcase_path,
               test_timeout,
               gestures,
               needs_http=False,
               arguments=None):
    self._testcase_path = testcase_path
    self._test_timeout = test_timeout
    self._gestures = gestures
    self._needs_http = needs_http

    if fuzz_target:
      engine_impl = engine.get(fuzz_target.engine)
    else:
      engine_impl = None

    # TODO(ochang): Make this hard fail once migration to new fuzzing pipeline
    # is complete.
    if fuzz_target and engine_impl:
      self._is_black_box = False
      self._engine_impl = engine_impl

      # Read target_name + args.
      if not arguments:
        arguments = get_command_line_flags(testcase_path)

      arguments = data_handler.filter_arguments(arguments, fuzz_target.binary)
      self._arguments = arguments.split()

      self._fuzz_target = fuzz_target
    else:
      self._is_black_box = True
      self._command = get_command_line_for_application(
          testcase_path, needs_http=needs_http)

  def run(self, round_number):
    """Run the testcase once."""
    app_directory = environment.get_value('APP_DIR')
    warmup_timeout = environment.get_value('WARMUP_TIMEOUT')
    run_timeout = warmup_timeout if round_number == 1 else self._test_timeout

    if self._is_black_box:
      return_code, crash_time, output = process_handler.run_process(
          self._command,
          timeout=run_timeout,
          gestures=self._gestures,
          current_working_directory=app_directory)
    else:
      try:
        result = engine_reproduce(self._engine_impl, self._fuzz_target.binary,
                                  self._testcase_path, self._arguments,
                                  run_timeout)
      except TimeoutError:
        # Treat reproduction timeouts as not crashing.
        return CrashResult(0, run_timeout, '')

      return_code = result.return_code
      crash_time = result.time_executed

      log_header = engine_common.get_log_header(result.command,
                                                result.time_executed)
      output = log_header + '\n' + result.output

    process_handler.terminate_stale_application_instances()

    crash_result = CrashResult(return_code, crash_time, output)
    if not crash_result.is_crash():
      logs.log(
          'No crash occurred (round {round_number}).'.format(
              round_number=round_number),
          output=output)

    return crash_result

  def _pre_run_cleanup(self):
    """Common cleanup before running a testcase."""
    # Cleanup any existing application instances and user profile directories.
    # Cleaning up temp user profile directories. Should be done before calling
    # |get_command_line_for_application| call since that creates dependencies in
    # the profile folder.
    process_handler.terminate_stale_application_instances()
    shell.clear_temp_directory()

  def _get_crash_state(self, round_number, crash_result):
    """Get crash state from a CrashResult."""
    state = crash_result.get_symbolized_data()
    if crash_result.is_crash():
      logs.log(
          ('Crash occurred in {crash_time} seconds (round {round_number}). '
           'State:\n{crash_state}').format(
               crash_time=crash_result.crash_time,
               round_number=round_number,
               crash_state=state.crash_state),
          output=state.crash_stacktrace)

    return state

  def reproduce_with_retries(self,
                             retries,
                             expected_state=None,
                             expected_security_flag=None,
                             flaky_stacktrace=False):
    """Try reproducing a crash with retries."""
    self._pre_run_cleanup()
    crash_result = None

    for round_number in range(1, retries + 1):
      crash_result = self.run(round_number)
      state = self._get_crash_state(round_number, crash_result)

      if not crash_result.is_crash():
        continue

      if not expected_state:
        logs.log('Crash stacktrace comparison skipped.')
        return crash_result

      if crash_result.should_ignore():
        logs.log('Crash stacktrace matched ignore signatures, ignored.')
        continue

      if crash_result.is_security_issue() != expected_security_flag:
        logs.log('Crash security flag does not match, ignored.')
        continue

      if flaky_stacktrace:
        logs.log('Crash stacktrace is marked flaky, skipping comparison.')
        return crash_result

      crash_comparer = CrashComparer(state.crash_state, expected_state)
      if crash_comparer.is_similar():
        logs.log('Crash stacktrace is similar to original stacktrace.')
        return crash_result
      logs.log('Crash stacktrace does not match original stacktrace.')

    logs.log('Didn\'t crash at all.')
    return CrashResult(return_code=0, crash_time=0, output=crash_result.output)

  def test_reproduce_reliability(self, retries, expected_state,
                                 expected_security_flag):
    """Test to see if a crash is fully reproducible or is a one-time crasher."""
    self._pre_run_cleanup()

    reproducible_crash_target_count = retries * REPRODUCIBILITY_FACTOR
    round_number = 0
    crash_count = 0
    for round_number in range(1, retries + 1):
      # Bail out early if there is no hope of finding a reproducible crash.
      if (retries - round_number + crash_count + 1 <
          reproducible_crash_target_count):
        break

      crash_result = self.run(round_number)
      state = self._get_crash_state(round_number, crash_result)

      if not crash_result.is_crash():
        continue

      # If we don't have an expected crash state, set it to the one from initial
      # crash.
      if not expected_state:
        expected_state = state.crash_state

      if crash_result.is_security_issue() != expected_security_flag:
        logs.log('Detected a crash without the correct security flag.')
        continue

      crash_comparer = CrashComparer(state.crash_state, expected_state)
      if not crash_comparer.is_similar():
        logs.log(
            'Detected a crash with an unrelated state: '
            'Expected(%s), Found(%s).' % (expected_state, state.crash_state))
        continue

      crash_count += 1
      if crash_count >= reproducible_crash_target_count:
        logs.log('Crash is reproducible.')
        return True

    logs.log('Crash is not reproducible. Crash count: %d/%d.' % (crash_count,
                                                                 round_number))
    return False


def test_for_crash_with_retries(testcase,
                                testcase_path,
                                test_timeout,
                                http_flag=False,
                                use_gestures=True,
                                compare_crash=True,
                                crash_retries=None):
  """Test for a crash and return crash parameters like crash type, crash state,
  crash stacktrace, etc."""
  gestures = testcase.gestures if use_gestures else None
  try:
    fuzz_target = testcase.get_fuzz_target()
    if engine.get(testcase.fuzzer_name) and not fuzz_target:
      raise TargetNotFoundError

    runner = TestcaseRunner(fuzz_target, testcase_path, test_timeout, gestures,
                            http_flag)

    if crash_retries is None:
      crash_retries = environment.get_value('CRASH_RETRIES')

    if compare_crash:
      expected_state = testcase.crash_state
      expected_security_flag = testcase.security_flag
    else:
      expected_state = None
      expected_security_flag = None

    return runner.reproduce_with_retries(crash_retries, expected_state,
                                         expected_security_flag,
                                         testcase.flaky_stack)
  except TargetNotFoundError:
    # If a target isn't found, treat it as not crashing.
    return CrashResult(return_code=0, crash_time=0, output='')


def test_for_reproducibility(fuzzer_name,
                             full_fuzzer_name,
                             testcase_path,
                             expected_state,
                             expected_security_flag,
                             test_timeout,
                             http_flag,
                             gestures,
                             arguments=None):
  """Test to see if a crash is fully reproducible or is a one-time crasher."""
  try:
    fuzz_target = data_handler.get_fuzz_target(full_fuzzer_name)
    if engine.get(fuzzer_name) and not fuzz_target:
      raise TargetNotFoundError

    runner = TestcaseRunner(
        fuzz_target,
        testcase_path,
        test_timeout,
        gestures,
        http_flag,
        arguments=arguments)

    crash_retries = environment.get_value('CRASH_RETRIES')
    return runner.test_reproduce_reliability(crash_retries, expected_state,
                                             expected_security_flag)
  except TargetNotFoundError:
    # If a target isn't found, treat it as not crashing.
    return False


def prepare_log_for_upload(symbolized_output, return_code):
  """Prepare log for upload."""
  # Add revision information to the logs.
  app_revision = environment.get_value('APP_REVISION')
  job_name = environment.get_value('JOB_NAME')
  components = revisions.get_component_list(app_revision, job_name)
  component_revisions = (
      revisions.format_revision_list(components, use_html=False) or
      'Not available.\n')

  revisions_header =\
  f'Component revisions (build r{app_revision}):\n{component_revisions}\n'

  bot_name = environment.get_value('BOT_NAME')
  bot_header = f'Bot name: {bot_name}\n'
  if environment.is_android():
    bot_header += f'Device serial: {environment.get_value("ANDROID_SERIAL")}\n'

  return_code_header = "Return code: %s\n\n" % return_code

  result = revisions_header + bot_header + return_code_header +\
  symbolized_output
  return result.encode('utf-8')


def upload_log(log, log_time):
  """Upload the output into corresponding GCS logs bucket."""
  fuzz_logs_bucket = environment.get_value('FUZZ_LOGS_BUCKET')
  if not fuzz_logs_bucket:
    return

  fuzzer_logs.upload_to_logs(fuzz_logs_bucket, log, time=log_time)


def get_user_profile_directory(user_profile_index):
  """Returns a user profile directory from a directory index."""
  temp_directory = environment.get_value('BOT_TMPDIR')
  user_profile_in_memory = environment.get_value('USER_PROFILE_IN_MEMORY')
  user_profile_root_directory = (
      temp_directory if user_profile_in_memory else
      environment.get_value('USER_PROFILE_ROOT_DIR'))

  # Create path to user profile directory.
  user_profile_directory_name = 'user_profile_%d' % user_profile_index
  user_profile_directory = os.path.join(user_profile_root_directory,
                                        user_profile_directory_name)

  return user_profile_directory


def get_command_line_for_application(file_to_run='',
                                     user_profile_index=0,
                                     app_path=None,
                                     app_args=None,
                                     needs_http=False,
                                     write_command_line_file=False,
                                     get_arguments_only=False):
  """Returns the complete command line required to execute application."""
  if app_args is None:
    app_args = environment.get_value('APP_ARGS')
  if app_path is None:
    app_path = environment.get_value('APP_PATH')

  if not app_path:
    # No APP_PATH is available for e.g. grey box fuzzers.
    return ''

  additional_command_line_flags = get_additional_command_line_flags(file_to_run)
  app_args_append_testcase = environment.get_value('APP_ARGS_APPEND_TESTCASE')
  app_directory = environment.get_value('APP_DIR')
  app_name = environment.get_value('APP_NAME')
  apps_argument = environment.get_value('APPS_ARG')
  crash_stacks_directory = environment.get_value('CRASH_STACKTRACES_DIR')
  debugger = environment.get_value('DEBUGGER_PATH')
  device_testcases_directory = android.constants.DEVICE_TESTCASES_DIR
  fuzzer_directory = environment.get_value('FUZZER_DIR')
  extension_argument = environment.get_value('EXTENSION_ARG')
  input_directory = environment.get_value('INPUT_DIR')
  launcher = environment.get_value('LAUNCHER_PATH')
  is_android = environment.is_android()
  root_directory = environment.get_value('ROOT_DIR')
  temp_directory = environment.get_value('BOT_TMPDIR')
  user_profile_argument = environment.get_value('USER_PROFILE_ARG')
  window_argument = environment.get_value('WINDOW_ARG')
  user_profile_directory = get_user_profile_directory(user_profile_index)

  # Create user profile directory and setup contents if needed.
  setup_user_profile_directory_if_needed(user_profile_directory)

  # Handle spaces in APP_PATH.
  # If application path has spaces, then we need to quote it.
  if ' ' in app_path:
    app_path = '"%s"' % app_path

  interpreter = shell.get_interpreter(app_name)
  if get_arguments_only:
    # If we are only returning the arguments, do not return the application
    # path or anything else required to run it such as an interpreter.
    app_path = ''
  elif interpreter:
    # Prepend command with interpreter if it is a script.
    app_path = '%s %s' % (interpreter, app_path)

  # Start creating the command line.
  command = ''

  # Rebase the file_to_run and launcher paths to the worker's root.
  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import file_host
    file_to_run = file_host.rebase_to_worker_root(file_to_run)
    launcher = file_host.rebase_to_worker_root(launcher)

  # Default case.
  testcase_path = file_to_run
  testcase_filename = os.path.basename(testcase_path)
  testcase_directory = os.path.dirname(testcase_path)
  testcase_file_url = utils.file_path_to_file_url(testcase_path)
  testcase_http_url = ''

  # Determine where |testcase_file_url| should point depending on platform and
  # whether or not a launcher script is used.
  if file_to_run:
    if launcher:
      # In the case of launcher scripts, the testcase file to be run resides on
      # the host running the launcher script. Thus |testcase_file_url|, which
      # may point to a location on the device for Android job types, does not
      # apply. Instead, the launcher script should be passed the original file
      # to run. By setting |testcase_file_url| to |file_to_run|, we avoid
      # duplicating job definitions solely for supporting launcher scripts.
      testcase_file_url = file_to_run
      # Jobs that have a launcher script which needs to be run on the host will
      # have app_name == launcher. In this case don't prepend launcher to
      # command - just use app_name.
      if os.path.basename(launcher) != app_name:
        launcher_with_interpreter = shell.get_execute_command(launcher)
        command += launcher_with_interpreter + ' '
    elif is_android:
      # Android-specific testcase path fixup for fuzzers that don't rely on
      # launcher scripts.
      local_testcases_directory = environment.get_value('FUZZ_INPUTS')

      # Check if the file to run is in fuzzed testcases folder. If yes, then we
      # can substitute with a local device path. Otherwise, it is part of some
      # data bundle with resource dependencies and we just need to use http
      # host forwarder for that.
      if file_to_run.startswith(local_testcases_directory):
        testcase_relative_path = (
            file_to_run[len(local_testcases_directory) + 1:])
        testcase_path = os.path.join(device_testcases_directory,
                                     testcase_relative_path)
        testcase_file_url = utils.file_path_to_file_url(testcase_path)
      else:
        # Force use of host_forwarder based on comment above.
        needs_http = True

    # Check if the testcase needs to be loaded over http.
    # TODO(ochang): Make this work for trusted/untrusted.
    http_ip = '127.0.0.1'
    http_port_1 = environment.get_value('HTTP_PORT_1', 8000)
    relative_testcase_path = file_to_run[len(input_directory + os.path.sep):]
    relative_testcase_path = relative_testcase_path.replace('\\', '/')
    testcase_http_url = 'http://%s:%d/%s' % (http_ip, http_port_1,
                                             relative_testcase_path)

    if needs_http:
      # TODO(unassigned): Support https.
      testcase_file_url = testcase_http_url
      testcase_path = testcase_http_url

  # Compose app arguments.
  all_app_args = ''

  if user_profile_argument:
    all_app_args += ' %s=%s' % (user_profile_argument, user_profile_directory)
  if extension_argument and EXTENSIONS_PREFIX in testcase_filename:
    all_app_args += ' %s=%s' % (extension_argument, testcase_directory)
  if apps_argument and APPS_PREFIX in testcase_filename:
    all_app_args += ' %s=%s' % (apps_argument, testcase_directory)
  if window_argument:
    all_app_args += ' %s' % window_argument
  if additional_command_line_flags:
    all_app_args += ' %s' % additional_command_line_flags.strip()
  if app_args:
    all_app_args += ' %s' % app_args.strip()
  # Append %TESTCASE% at end if no testcase pattern is found in app arguments.
  if not utils.sub_string_exists_in(
      ['%TESTCASE%', '%TESTCASE_FILE_URL%', '%TESTCASE_HTTP_URL%'],
      all_app_args) and app_args_append_testcase:
    all_app_args += ' %TESTCASE%'
  all_app_args = all_app_args.strip()

  # Build the actual command to run now.
  if debugger:
    command += '%s ' % debugger
  if app_path:
    command += app_path
  if all_app_args:
    command += ' %s' % all_app_args
  command = command.replace('%APP_DIR%', app_directory)
  command = command.replace('%CRASH_STACKTRACES_DIR%', crash_stacks_directory)
  command = command.replace('%DEVICE_TESTCASES_DIR%',
                            device_testcases_directory)
  command = command.replace('%FUZZER_DIR%', fuzzer_directory)
  command = command.replace('%INPUT_DIR%', input_directory)
  command = command.replace('%ROOT_DIR%', root_directory)
  command = command.replace('%TESTCASE%', testcase_path)
  command = command.replace('%TESTCASE_FILE_URL%', testcase_file_url)
  command = command.replace('%TESTCASE_HTTP_URL%', testcase_http_url)
  command = command.replace('%TMP_DIR%', temp_directory)
  command = command.replace('%USER_PROFILE_DIR%', user_profile_directory)

  if is_android and not launcher:
    # Initial setup phase for command line.
    if write_command_line_file:
      android.adb.write_command_line_file(command, app_path)

    return android.app.get_launch_command(all_app_args, testcase_path,
                                          testcase_file_url)

  # Decide which directory we will run the application from.
  # We are using |app_directory| since it helps to locate pdbs
  # in same directory, other dependencies, etc.
  if os.path.exists(app_directory):
    os.chdir(app_directory)

  return str(command)


def setup_user_profile_directory_if_needed(user_profile_directory):
  """Set user profile directory if it does not exist."""
  if os.path.exists(user_profile_directory):
    # User profile directory already exists. Bail out.
    return

  shell.create_directory(user_profile_directory)

  # Create a file in user profile directory based on format:
  # filename;base64 encoded zlib compressed file contents.
  user_profile_file = environment.get_value('USER_PROFILE_FILE')
  if user_profile_file and ';' in user_profile_file:
    user_profile_filename, encoded_file_contents = (
        user_profile_file.split(';', 1))
    user_profile_file_contents = zlib.decompress(
        base64.b64decode(encoded_file_contents))
    user_profile_file_path = os.path.join(user_profile_directory,
                                          user_profile_filename)
    utils.write_data_to_file(user_profile_file_contents, user_profile_file_path)

  # For Firefox, we need to install a special fuzzPriv extension that exposes
  # special functions to javascript, e.g. gc(), etc.
  app_name = environment.get_value('APP_NAME')
  if app_name.startswith('firefox'):
    # Create extensions directory.
    extensions_directory = os.path.join(user_profile_directory, 'extensions')
    shell.create_directory(extensions_directory)

    # Unpack the fuzzPriv extension.
    extension_archive = os.path.join(environment.get_resources_directory(),
                                     'firefox', 'fuzzPriv-extension.zip')
    archive.unpack(extension_archive, extensions_directory)

    # Add this extension in the extensions configuration file.
    extension_config_file_path = os.path.join(user_profile_directory,
                                              'extensions.ini')
    fuzz_extension_directory = os.path.join(extensions_directory,
                                            'domfuzz@squarefree.com')
    extension_config_file_contents = (
        '[ExtensionDirs]\r\n'
        'Extension0=%s\r\n'
        '\r\n'
        '[ThemeDirs]\r\n' % fuzz_extension_directory)
    utils.write_data_to_file(extension_config_file_contents,
                             extension_config_file_path)


def check_for_bad_build(job_type, crash_revision):
  """Return true if the build is bad, i.e. crashes on startup."""
  # Check the bad build check flag to see if we want do this.
  if not environment.get_value('BAD_BUILD_CHECK'):
    return False

  # Create a blank command line with no file to run and no http.
  command = get_command_line_for_application(file_to_run='', needs_http=False)

  # When checking for bad builds, we use the default window size.
  # We don't want to pick a custom size since it can potentially cause a
  # startup crash and cause a build to be detected incorrectly as bad.
  default_window_argument = environment.get_value('WINDOW_ARG', '')
  if default_window_argument:
    command = command.replace(' %s' % default_window_argument, '')

  # TSAN is slow, and boots slow on first startup. Increase the warmup
  # timeout for this case.
  if environment.tool_matches('TSAN', job_type):
    fast_warmup_timeout = environment.get_value('WARMUP_TIMEOUT')
  else:
    fast_warmup_timeout = environment.get_value('FAST_WARMUP_TIMEOUT')

  # Initialize helper variables.
  is_bad_build = False
  build_run_console_output = ''
  app_directory = environment.get_value('APP_DIR')

  # Exit all running instances.
  process_handler.terminate_stale_application_instances()

  # Check if the build is bad.
  return_code, crash_time, output = process_handler.run_process(
      command,
      timeout=fast_warmup_timeout,
      current_working_directory=app_directory)
  crash_result = CrashResult(return_code, crash_time, output)

  # 1. Need to account for startup crashes with no crash state. E.g. failed to
  #    load shared library. So, ignore state for comparison.
  # 2. Ignore leaks as they don't block a build from reporting regular crashes
  #    and also don't impact regression range calculations.
  if (crash_result.is_crash(ignore_state=True) and
      not crash_result.should_ignore() and
      not crash_result.get_type() in ['Direct-leak', 'Indirect-leak']):
    is_bad_build = True
    build_run_console_output = utils.get_crash_stacktrace_output(
        command,
        crash_result.get_stacktrace(symbolized=True),
        crash_result.get_stacktrace(symbolized=False))
    logs.log(
        'Bad build for %s detected at r%d.' % (job_type, crash_revision),
        output=build_run_console_output)

  # Exit all running instances.
  process_handler.terminate_stale_application_instances()

  # Any of the conditions below indicate that bot is in a bad state and it is
  # not caused by the build itself. In that case, just exit.
  build_state = data_handler.get_build_state(job_type, crash_revision)
  if is_bad_build and utils.sub_string_exists_in(BAD_STATE_HINTS, output):
    logs.log_fatal_and_exit(
        'Bad bot environment detected, exiting.',
        output=build_run_console_output,
        snapshot=process_handler.get_runtime_snapshot())

  # If none of the other bots have added information about this build,
  # then add it now.
  if (build_state == data_types.BuildState.UNMARKED and
      not crash_result.should_ignore()):
    data_handler.add_build_metadata(job_type, crash_revision, is_bad_build,
                                    build_run_console_output)

  return is_bad_build
