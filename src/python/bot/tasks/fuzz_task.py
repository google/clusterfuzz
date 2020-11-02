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
"""Fuzz task for handling fuzzing."""

import collections
import datetime
import itertools
import os
import random
import re
import six
import time

from google.cloud import ndb

from base import dates
from base import retry
from base import utils
from bot import testcase_manager
from bot.fuzzers import builtin
from bot.fuzzers import builtin_fuzzers
from bot.fuzzers import engine_common
from bot.fuzzers import utils as fuzzer_utils
from bot.fuzzers.libFuzzer import stats as libfuzzer_stats
from bot.tasks import setup
from bot.tasks import task_creation
from bot.tasks import trials
from build_management import build_manager
from chrome import crash_uploader
from collections import namedtuple
from crash_analysis import crash_analyzer
from crash_analysis.crash_result import CrashResult
from crash_analysis.stack_parsing import stack_analyzer
from datastore import data_handler
from datastore import data_types
from datastore import ndb_utils
from fuzzing import corpus_manager
from fuzzing import coverage_uploader
from fuzzing import fuzzer_selection
from fuzzing import gesture_handler
from fuzzing import leak_blacklist
from google_cloud_utils import big_query
from google_cloud_utils import blobs
from google_cloud_utils import storage
from lib.clusterfuzz.fuzz import engine
from metrics import fuzzer_logs
from metrics import fuzzer_stats
from metrics import logs
from metrics import monitoring_metrics
from platforms import android
from system import environment
from system import process_handler
from system import shell

SelectionMethod = namedtuple('SelectionMethod', 'method_name probability')

FUZZ_TARGET_UPDATE_FAIL_RETRIES = 5
FUZZ_TARGET_UPDATE_FAIL_DELAY = 2
DEFAULT_CHOOSE_PROBABILITY = 9  # 10%
FUZZER_METADATA_REGEX = re.compile(r'metadata::(\w+):\s*(.*)')
FUZZER_FAILURE_THRESHOLD = 0.33
MAX_GESTURES = 30
MAX_NEW_CORPUS_FILES = 500
SELECTION_METHOD_DISTRIBUTION = [
    SelectionMethod('default', .7),
    SelectionMethod('multi_armed_bandit', .3)
]
THREAD_WAIT_TIMEOUT = 1


class FuzzTaskException(Exception):
  """Fuzz task exception."""


class FuzzErrorCode(object):
  FUZZER_TIMEOUT = -1
  FUZZER_SETUP_FAILED = -2
  FUZZER_EXECUTION_FAILED = -3
  DATA_BUNDLE_SETUP_FAILED = -4
  BUILD_SETUP_FAILED = -5


Context = collections.namedtuple('Context', [
    'project_name', 'bot_name', 'job_type', 'fuzz_target', 'redzone',
    'disable_ubsan', 'platform_id', 'crash_revision', 'fuzzer_name',
    'window_argument', 'fuzzer_metadata', 'testcases_metadata',
    'timeout_multiplier', 'test_timeout', 'thread_wait_timeout',
    'data_directory'
])
Redzone = collections.namedtuple('Redzone', ['size', 'weight'])


def get_unsymbolized_crash_stacktrace(stack_file_path):
  """Read unsymbolized crash stacktrace."""
  with open(stack_file_path, 'rb') as f:
    return utils.decode_to_unicode(f.read())


class Crash(object):
  """Represents a crash (before creating a testcase)."""

  @classmethod
  def from_testcase_manager_crash(cls, crash):
    """Create a Crash from a testcase_manager.Crash."""
    try:
      orig_unsymbolized_crash_stacktrace = (
          get_unsymbolized_crash_stacktrace(crash.stack_file_path))
    except Exception:
      logs.log_error(
          'Unable to read stacktrace from file %s.' % crash.stack_file_path)
      return None

    # If there are per-testcase additional flags, we need to store them.
    arguments = testcase_manager.get_command_line_flags(crash.file_path)

    needs_http = '-http-' in os.path.basename(crash.file_path)
    application_command_line = (
        testcase_manager.get_command_line_for_application(
            crash.file_path, needs_http=needs_http))

    # TODO(ochang): Remove once all engines are migrated to new pipeline.
    fuzzing_strategies = libfuzzer_stats.LIBFUZZER_FUZZING_STRATEGIES.search(
        orig_unsymbolized_crash_stacktrace)
    if fuzzing_strategies:
      assert len(fuzzing_strategies.groups()) == 1
      fuzzing_strategies_string = fuzzing_strategies.groups()[0]
      fuzzing_strategies = [
          strategy.strip() for strategy in fuzzing_strategies_string.split(',')
      ]

    return Crash(
        file_path=crash.file_path,
        crash_time=crash.crash_time,
        return_code=crash.return_code,
        resource_list=crash.resource_list,
        gestures=crash.gestures,
        unsymbolized_crash_stacktrace=orig_unsymbolized_crash_stacktrace,
        arguments=arguments,
        application_command_line=application_command_line,
        http_flag=needs_http,
        fuzzing_strategies=fuzzing_strategies)

  @classmethod
  def from_engine_crash(cls, crash, fuzzing_strategies):
    """Create a Crash from a engine.Crash."""
    return Crash(
        file_path=crash.input_path,
        crash_time=crash.crash_time,
        return_code=1,
        resource_list=[],
        gestures=[],
        unsymbolized_crash_stacktrace=utils.decode_to_unicode(crash.stacktrace),
        arguments=' '.join(crash.reproduce_args),
        application_command_line='',  # TODO(ochang): Write actual command line.
        fuzzing_strategies=fuzzing_strategies)

  def __init__(self,
               file_path,
               crash_time,
               return_code,
               resource_list,
               gestures,
               unsymbolized_crash_stacktrace,
               arguments,
               application_command_line,
               http_flag=False,
               fuzzing_strategies=None):
    self.file_path = file_path
    self.crash_time = crash_time
    self.return_code = return_code
    self.resource_list = resource_list
    self.gestures = gestures
    self.arguments = arguments
    self.fuzzing_strategies = fuzzing_strategies

    self.security_flag = False
    self.should_be_ignored = False

    self.filename = os.path.basename(file_path)
    self.http_flag = http_flag
    self.application_command_line = application_command_line
    self.unsymbolized_crash_stacktrace = unsymbolized_crash_stacktrace
    state = stack_analyzer.get_crash_data(self.unsymbolized_crash_stacktrace)
    self.crash_type = state.crash_type
    self.crash_address = state.crash_address
    self.crash_state = state.crash_state
    self.crash_stacktrace = utils.get_crash_stacktrace_output(
        self.application_command_line, state.crash_stacktrace,
        self.unsymbolized_crash_stacktrace)
    self.security_flag = crash_analyzer.is_security_issue(
        self.unsymbolized_crash_stacktrace, self.crash_type, self.crash_address)
    self.key = '%s,%s,%s' % (self.crash_type, self.crash_state,
                             self.security_flag)
    self.should_be_ignored = crash_analyzer.ignore_stacktrace(
        state.crash_stacktrace)

    # self.crash_info gets populated in create_testcase; save what we need.
    self.crash_frames = state.frames
    self.crash_info = None

  def is_archived(self):
    """Return true if archive_testcase_in_blobstore(..) was
      performed."""
    return hasattr(self, 'fuzzed_key')

  def archive_testcase_in_blobstore(self):
    """Calling setup.archive_testcase_and_dependencies_in_gcs(..)
      and hydrate certain attributes. We single out this method because it's
      expensive and we want to do it at the very last minute."""
    if self.is_archived():
      return

    (self.fuzzed_key, self.archived, self.absolute_path,
     self.archive_filename) = (
         setup.archive_testcase_and_dependencies_in_gcs(self.resource_list,
                                                        self.file_path))

  def is_valid(self):
    """Return true if the crash is valid for processing."""
    return self.get_error() is None

  def get_error(self):
    """Return the reason why the crash is invalid."""
    filter_functional_bugs = environment.get_value('FILTER_FUNCTIONAL_BUGS')
    if filter_functional_bugs and not self.security_flag:
      return 'Functional crash is ignored: %s' % self.crash_state

    if self.should_be_ignored:
      return ('False crash: %s\n\n---%s\n\n---%s' %
              (self.crash_state, self.unsymbolized_crash_stacktrace,
               self.crash_stacktrace))

    if self.is_archived() and not self.fuzzed_key:
      return 'Unable to store testcase in blobstore: %s' % self.crash_state

    if not self.crash_state or not self.crash_type:
      return 'Empty crash state or type'

    return None


def find_main_crash(crashes, fuzzer_name, full_fuzzer_name, test_timeout):
  """Find the first reproducible crash or the first valid crash.
    And return the crash and the one_time_crasher_flag."""
  for crash in crashes:
    # Archiving testcase to blobstore when we need to because it's expensive.
    crash.archive_testcase_in_blobstore()

    # We need to check again if the crash is valid. In other words, we check
    # if archiving to blobstore succeeded.
    if not crash.is_valid():
      continue

    # We pass an empty expected crash state since our initial stack from fuzzing
    # can be incomplete. So, make a judgement on reproducibility based on passed
    # security flag and crash state generated from re-running testcase in
    # test_for_reproducibility. Minimize task will later update the new crash
    # type and crash state paramaters.
    if testcase_manager.test_for_reproducibility(
        fuzzer_name,
        full_fuzzer_name,
        crash.file_path,
        None,
        crash.security_flag,
        test_timeout,
        crash.http_flag,
        crash.gestures,
        arguments=crash.arguments):
      return crash, False

  # All crashes are non-reproducible. Therefore, we get the first valid one.
  for crash in crashes:
    if crash.is_valid():
      return crash, True

  return None, None


class CrashGroup(object):
  """Represent a group of identical crashes. The key is
      (crash_type, crash_state, security_flag)."""

  def __init__(self, crashes, context):
    for c in crashes:
      assert crashes[0].crash_type == c.crash_type
      assert crashes[0].crash_state == c.crash_state
      assert crashes[0].security_flag == c.security_flag

    self.crashes = crashes
    if context.fuzz_target:
      fully_qualified_fuzzer_name = context.fuzz_target.fully_qualified_name()
    else:
      fully_qualified_fuzzer_name = context.fuzzer_name

    self.main_crash, self.one_time_crasher_flag = find_main_crash(
        crashes, context.fuzzer_name, fully_qualified_fuzzer_name,
        context.test_timeout)

    self.newly_created_testcase = None

    # Getting existing_testcase after finding the main crash is important.
    # Because finding the main crash can take a long time; it tests
    # reproducibility on every crash.
    #
    # Getting existing testcase at the last possible moment helps avoid race
    # condition among different machines. One machine might finish first and
    # prevent other machines from creating identical testcases.
    self.existing_testcase = data_handler.find_testcase(
        context.project_name, crashes[0].crash_type, crashes[0].crash_state,
        crashes[0].security_flag)

  def is_new(self):
    """Return true if there's no existing testcase."""
    return not self.existing_testcase

  def should_create_testcase(self):
    """Return true if this crash should create a testcase."""
    if not self.existing_testcase:
      # No existing testcase, should create a new one.
      return True

    if not self.existing_testcase.one_time_crasher_flag:
      # Existing testcase is reproducible, don't need to create another one.
      return False

    if not self.one_time_crasher_flag:
      # Current testcase is reproducible, where existing one is not. Should
      # create a new one.
      return True

    # Both current and existing testcases are unreproducible, shouldn't create
    # a new testcase.
    # TODO(aarya): We should probably update last tested stacktrace in existing
    # testcase without any race conditions.
    return False

  def has_existing_reproducible_testcase(self):
    """Return true if this crash has a reproducible testcase."""
    return (self.existing_testcase and
            not self.existing_testcase.one_time_crasher_flag)


class _TrackFuzzTime(object):
  """Track the actual fuzzing time (e.g. excluding preparing binary)."""

  def __init__(self, fuzzer_name, job_type, time_module=time):
    self.fuzzer_name = fuzzer_name
    self.job_type = job_type
    self.time = time_module

  def __enter__(self):
    self.start_time = self.time.time()
    self.timeout = False
    return self

  def __exit__(self, exc_type, value, traceback):
    duration = self.time.time() - self.start_time
    monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'fuzzer': self.fuzzer_name,
            'timeout': self.timeout
        })
    monitoring_metrics.JOB_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'job': self.job_type,
            'timeout': self.timeout
        })


def _track_fuzzer_run_result(fuzzer_name, generated_testcase_count,
                             expected_testcase_count, return_code):
  """Track fuzzer run result"""
  if expected_testcase_count > 0:
    ratio = float(generated_testcase_count) / expected_testcase_count
    monitoring_metrics.FUZZER_TESTCASE_COUNT_RATIO.add(ratio,
                                                       {'fuzzer': fuzzer_name})

  def clamp(val, minimum, maximum):
    return max(minimum, min(maximum, val))

  # Clamp return code to max, min int 32-bit, otherwise it can get detected as
  # type long and we will exception out in infra_libs parsing pipeline.
  min_int32 = -(2**31)
  max_int32 = 2**31 - 1

  return_code = int(clamp(return_code, min_int32, max_int32))

  monitoring_metrics.FUZZER_RETURN_CODE_COUNT.increment({
      'fuzzer': fuzzer_name,
      'return_code': return_code,
  })


def _track_build_run_result(job_type, _, is_bad_build):
  """Track build run result."""
  # FIXME: Add support for |crash_revision| as part of state.
  monitoring_metrics.JOB_BAD_BUILD_COUNT.increment({
      'job': job_type,
      'bad_build': is_bad_build
  })


def _track_testcase_run_result(fuzzer, job_type, new_crash_count,
                               known_crash_count):
  """Track testcase run result."""
  monitoring_metrics.FUZZER_KNOWN_CRASH_COUNT.increment_by(
      known_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.FUZZER_NEW_CRASH_COUNT.increment_by(
      new_crash_count, {
          'fuzzer': fuzzer,
      })
  monitoring_metrics.JOB_KNOWN_CRASH_COUNT.increment_by(known_crash_count, {
      'job': job_type,
  })
  monitoring_metrics.JOB_NEW_CRASH_COUNT.increment_by(new_crash_count, {
      'job': job_type,
  })


def _last_sync_time(sync_file_path):
  """Read and parse the last sync file for the GCS corpus."""
  if not os.path.exists(sync_file_path):
    return None

  file_contents = utils.read_data_from_file(sync_file_path, eval_data=False)
  if not file_contents:
    logs.log_warn('Empty last sync file.', path=sync_file_path)
    return None

  last_sync_time = None
  try:
    last_sync_time = datetime.datetime.utcfromtimestamp(float(file_contents))
  except Exception as e:
    logs.log_error(
        'Malformed last sync file: "%s".' % str(e),
        path=sync_file_path,
        contents=file_contents)

  return last_sync_time


class GcsCorpus(object):
  """Sync state for a corpus."""

  def __init__(self, engine_name, project_qualified_target_name,
               corpus_directory, data_directory):
    if environment.is_trusted_host():
      from bot.untrusted_runner import corpus_manager as remote_corpus_manager
      self.gcs_corpus = remote_corpus_manager.RemoteFuzzTargetCorpus(
          engine_name, project_qualified_target_name)
    else:
      self.gcs_corpus = corpus_manager.FuzzTargetCorpus(
          engine_name, project_qualified_target_name, log_results=False)

    self._corpus_directory = corpus_directory
    self._data_directory = data_directory
    self._project_qualified_target_name = project_qualified_target_name
    self._synced_files = set()

  def _walk(self):
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      for file_path in file_host.list_files(
          self._corpus_directory, recursive=True):
        yield file_path
    else:
      for root, _, files in shell.walk(self._corpus_directory):
        for filename in files:
          yield os.path.join(root, filename)

  def sync_from_gcs(self):
    """Update sync state after a sync from GCS."""
    already_synced = False
    sync_file_path = os.path.join(
        self._data_directory, '.%s_sync' % self._project_qualified_target_name)

    # Get last time we synced corpus.
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
      shell.remove_file(sync_file_path)
      file_host.copy_file_from_worker(worker_sync_file_path, sync_file_path)
    last_sync_time = _last_sync_time(sync_file_path)

    # Check if the corpus was recently synced. If yes, set a flag so that we
    # don't sync it again and save some time.
    if last_sync_time and os.path.exists(self._corpus_directory):
      last_update_time = storage.last_updated(self.gcs_corpus.get_gcs_url())
      if last_update_time and last_sync_time > last_update_time:
        logs.log('Corpus for target %s has no new updates, skipping rsync.' %
                 self._project_qualified_target_name)
        already_synced = True

    time_before_sync_start = time.time()
    result = already_synced or self.gcs_corpus.rsync_to_disk(
        self._corpus_directory)
    self._synced_files.clear()
    self._synced_files.update(self._walk())

    logs.log('%d corpus files for target %s synced to disk.' % (len(
        self._synced_files), self._project_qualified_target_name))

    # On success of rsync, update the last sync file with current timestamp.
    if result and self._synced_files and not already_synced:
      utils.write_data_to_file(time_before_sync_start, sync_file_path)

      if environment.is_trusted_host():
        from bot.untrusted_runner import file_host
        worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
        file_host.copy_file_to_worker(sync_file_path, worker_sync_file_path)

    return result

  def upload_files(self, new_files):
    """Update state after files are uploaded."""
    result = self.gcs_corpus.upload_files(new_files)
    self._synced_files.update(new_files)

    return result

  def get_new_files(self):
    """Return list of new files in the directory that were generated by the
    fuzzer."""
    is_android_kernel_job = environment.platform() == 'ANDROID_KERNEL'
    if is_android_kernel_job:
      # For Android Kernel job, sync back all corpus files containing this
      # device serial.
      device_serial = environment.get_value('ANDROID_SERIAL')
      return [
          f for f in self._walk()
          if os.path.basename(f).startswith(device_serial)
      ]

    new_files = []
    for file_path in self._walk():
      if file_path not in self._synced_files:
        new_files.append(file_path)

    return new_files


def upload_testcase_run_stats(testcase_run):
  """Upload TestcaseRun stats."""
  fuzzer_stats.upload_stats([testcase_run])


def add_additional_testcase_run_data(testcase_run, fully_qualified_fuzzer_name,
                                     job_type, revision):
  """Add additional testcase run data."""
  testcase_run['fuzzer'] = fully_qualified_fuzzer_name
  testcase_run['job'] = job_type
  testcase_run['build_revision'] = revision


def read_and_upload_testcase_run_stats(fuzzer_name, fully_qualified_fuzzer_name,
                                       job_type, revision, testcase_file_paths):
  """Upload per-testcase stats."""
  if fuzzer_name not in builtin_fuzzers.BUILTIN_FUZZERS:
    # Testcase run stats are only applicable to builtin fuzzers (libFuzzer,AFL).
    return

  testcase_runs = []
  for testcase_file_path in testcase_file_paths:
    testcase_run = fuzzer_stats.TestcaseRun.read_from_disk(
        testcase_file_path, delete=True)
    if testcase_run:
      add_additional_testcase_run_data(
          testcase_run, fully_qualified_fuzzer_name, job_type, revision)
      testcase_runs.append(testcase_run)

  for testcase_run in testcase_runs:
    upload_testcase_run_stats(testcase_run)


def get_fuzzer_metadata_from_output(fuzzer_output):
  """Extract metadata from fuzzer output."""
  metadata = {}
  for line in fuzzer_output.splitlines():
    match = FUZZER_METADATA_REGEX.match(line)
    if match:
      metadata[match.group(1)] = match.group(2)

  return metadata


def get_testcase_directories(testcase_directory, data_directory):
  """Return the list of directories containing fuzz testcases."""
  testcase_directories = [testcase_directory]

  # Cloud storage data bundle directory is on NFS. It is a slow file system
  # and browsing through hundreds of files can overload the server if every
  # bot starts doing that. Since, we don't create testcases there anyway, skip
  # adding the directory to the browse list.
  if not setup.is_directory_on_nfs(data_directory):
    testcase_directories.append(data_directory)

  return testcase_directories


def get_testcases(testcase_count, testcase_directory, data_directory):
  """Return fuzzed testcases from the data directories."""
  logs.log('Locating generated test cases.')

  # Get the list of testcase files.
  testcase_directories = get_testcase_directories(testcase_directory,
                                                  data_directory)
  testcase_file_paths = testcase_manager.get_testcases_from_directories(
      testcase_directories)

  # If the fuzzer created a bot-specific files list, add those now.
  bot_testcases_file_path = utils.get_bot_testcases_file_path(data_directory)
  if os.path.exists(bot_testcases_file_path):
    bot_testcases_file_content = utils.read_data_from_file(
        bot_testcases_file_path, eval_data=False)
    shell.remove_file(bot_testcases_file_path)
    if bot_testcases_file_content:
      bot_file_paths = bot_testcases_file_content.splitlines()
      testcase_file_paths += [
          utils.normalize_path(path) for path in bot_file_paths
      ]

  generated_testcase_count = len(testcase_file_paths)

  # Create output strings.
  generated_testcase_string = (
      'Generated %d/%d testcases.' % (generated_testcase_count, testcase_count))

  # Log the number of testcases generated.
  logs.log(generated_testcase_string)

  # If we are running the same command (again and again) on this bot,
  # we want to be careful of scenarios when the fuzzer starts failing
  # or has nothing to do, causing no testcases to be generated. This
  # will put lot of burden on appengine remote api.
  if (environment.get_value('COMMAND_OVERRIDE') and
      generated_testcase_count == 0):
    logs.log('No testcases generated. Sleeping for ~30 minutes.')
    time.sleep(random.uniform(1800, 2100))

  return (testcase_file_paths, generated_testcase_count,
          generated_testcase_string)


def pick_gestures(test_timeout):
  """Return a list of random gestures."""
  if not environment.get_value('ENABLE_GESTURES', True):
    # Gestures disabled.
    return []

  # Probability of choosing gestures.
  if utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY):
    return []

  gesture_count = utils.random_number(1, MAX_GESTURES)
  gestures = gesture_handler.get_gestures(gesture_count)
  if not gestures:
    return []

  # Pick a random trigger time to run the gesture at.
  min_gesture_time = int(
      utils.random_element_from_list([0.25, 0.50, 0.50, 0.50]) * test_timeout)
  max_gesture_time = test_timeout - 1
  gesture_time = utils.random_number(min_gesture_time, max_gesture_time)

  gestures.append('Trigger:%d' % gesture_time)
  return gestures


def pick_redzone():
  """Return a random size for redzone."""
  thread_multiplier = environment.get_value('THREAD_MULTIPLIER', 1)

  if thread_multiplier == 1:
    redzone_list = [
        Redzone(16, 1.0),
        Redzone(32, 1.0),
        Redzone(64, 0.5),
        Redzone(128, 0.5),
        Redzone(256, 0.25),
        Redzone(512, 0.25),
    ]
  else:
    # For beefier boxes, prioritize using bigger redzones.
    redzone_list = [
        Redzone(16, 0.25),
        Redzone(32, 0.25),
        Redzone(64, 0.50),
        Redzone(128, 0.50),
        Redzone(256, 1.0),
        Redzone(512, 1.0),
    ]

  return utils.random_weighted_choice(redzone_list).size


def pick_ubsan_disabled(job_type):
  """Choose whether to disable UBSan in an ASan+UBSan build."""
  # This is only applicable in an ASan build.
  memory_tool_name = environment.get_memory_tool_name(job_type)
  if memory_tool_name not in ['ASAN', 'HWASAN']:
    return False

  # Check if UBSan is enabled in this ASan build. If not, can't disable it.
  if not environment.get_value('UBSAN'):
    return False

  return not utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY)


def pick_timeout_multiplier():
  """Return a random testcase timeout multiplier and adjust timeout."""
  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  custom_timeout_multipliers = environment.get_value(
      'CUSTOM_TIMEOUT_MULTIPLIERS')
  timeout_multiplier = 1.0

  use_multiplier = not utils.random_number(0, DEFAULT_CHOOSE_PROBABILITY)
  if (use_multiplier and not fuzz_test_timeout and
      not custom_timeout_multipliers):
    timeout_multiplier = utils.random_element_from_list([0.5, 1.5, 2.0, 3.0])
  elif use_multiplier and custom_timeout_multipliers:
    # Since they are explicitly set in the job definition, it is fine to use
    # custom timeout multipliers even in the case where FUZZ_TEST_TIMEOUT is
    # set.
    timeout_multiplier = utils.random_element_from_list(
        custom_timeout_multipliers)

  return timeout_multiplier


def set_test_timeout(timeout, multipler):
  """Set the test timeout based on a timeout value and multiplier."""
  test_timeout = int(timeout * multipler)
  environment.set_value('TEST_TIMEOUT', test_timeout)
  return test_timeout


def pick_window_argument():
  """Return a window argument with random size and x,y position."""
  default_window_argument = environment.get_value('WINDOW_ARG', '')
  window_argument_change_chance = not utils.random_number(
      0, DEFAULT_CHOOSE_PROBABILITY)

  window_argument = ''
  if window_argument_change_chance:
    window_argument = default_window_argument
    if window_argument:
      width = utils.random_number(
          100, utils.random_element_from_list([256, 1280, 2048]))
      height = utils.random_number(
          100, utils.random_element_from_list([256, 1024, 1536]))
      left = utils.random_number(0, width)
      top = utils.random_number(0, height)

      window_argument = window_argument.replace('$WIDTH', str(width))
      window_argument = window_argument.replace('$HEIGHT', str(height))
      window_argument = window_argument.replace('$LEFT', str(left))
      window_argument = window_argument.replace('$TOP', str(top))

  # FIXME: Random seed is currently passed along to the next job
  # via WINDOW_ARG. Rename it without breaking existing tests.
  random_seed_argument = environment.get_value('RANDOM_SEED')
  if random_seed_argument:
    if window_argument:
      window_argument += ' '
    seed = utils.random_number(-2147483648, 2147483647)
    window_argument += '%s=%d' % (random_seed_argument.strip(), seed)

  environment.set_value('WINDOW_ARG', window_argument)
  return window_argument


@retry.wrap(
    retries=FUZZ_TARGET_UPDATE_FAIL_RETRIES,
    delay=FUZZ_TARGET_UPDATE_FAIL_DELAY,
    function='tasks.fuzz_task.record_fuzz_target')
def record_fuzz_target(engine_name, binary_name, job_type):
  """Record existence of fuzz target."""
  if not binary_name:
    logs.log_error('Expected binary_name.')
    return None

  project = data_handler.get_project_name(job_type)
  key_name = data_types.fuzz_target_fully_qualified_name(
      engine_name, project, binary_name)

  fuzz_target = ndb.Key(data_types.FuzzTarget, key_name).get()
  if not fuzz_target:
    fuzz_target = data_types.FuzzTarget(
        engine=engine_name, project=project, binary=binary_name)
    fuzz_target.put()

  job_mapping_key = data_types.fuzz_target_job_key(key_name, job_type)
  job_mapping = ndb.Key(data_types.FuzzTargetJob, job_mapping_key).get()
  if job_mapping:
    job_mapping.last_run = utils.utcnow()
  else:
    job_mapping = data_types.FuzzTargetJob(
        fuzz_target_name=key_name,
        job=job_type,
        engine=engine_name,
        last_run=utils.utcnow())
  job_mapping.put()

  logs.log(
      'Recorded use of fuzz target %s.' % key_name,
      project=project,
      engine=engine_name,
      binary_name=binary_name,
      job_type=job_type)
  return fuzz_target


def truncate_fuzzer_output(output, limit):
  """Truncate output in the middle according to limit."""
  if len(output) < limit:
    return output

  separator = '\n...truncated...\n'
  reduced_limit = limit - len(separator)
  left = reduced_limit // 2 + reduced_limit % 2
  right = reduced_limit // 2

  assert reduced_limit > 0

  return ''.join([output[:left], separator, output[-right:]])


def convert_groups_to_crashes(groups):
  """Convert groups to crashes (in an array of dicts) for JobRun."""
  crashes = []
  for group in groups:
    crashes.append({
        'is_new': group.is_new(),
        'count': len(group.crashes),
        'crash_type': group.main_crash.crash_type,
        'crash_state': group.main_crash.crash_state,
        'security_flag': group.main_crash.security_flag,
    })
  return crashes


def upload_job_run_stats(fuzzer_name, job_type, revision, timestamp,
                         new_crash_count, known_crash_count, testcases_executed,
                         groups):
  """Upload job run stats."""
  # New format.
  job_run = fuzzer_stats.JobRun(fuzzer_name, job_type, revision, timestamp,
                                testcases_executed, new_crash_count,
                                known_crash_count,
                                convert_groups_to_crashes(groups))
  fuzzer_stats.upload_stats([job_run])

  _track_testcase_run_result(fuzzer_name, job_type, new_crash_count,
                             known_crash_count)


def store_fuzzer_run_results(testcase_file_paths, fuzzer, fuzzer_command,
                             fuzzer_output, fuzzer_return_code, fuzzer_revision,
                             generated_testcase_count, expected_testcase_count,
                             generated_testcase_string):
  """Store fuzzer run results in database."""
  # Upload fuzzer script output to bucket.
  fuzzer_logs.upload_script_log(fuzzer_output)

  # Save the test results for the following cases.
  # 1. There is no result yet.
  # 2. There is no timestamp associated with the result.
  # 3. Last update timestamp is more than a day old.
  # 4. Return code is non-zero and was not found before.
  # 5. Testcases generated were fewer than expected in this run and zero return
  #    code did occur before and zero generated testcases didn't occur before.
  # TODO(mbarbella): Break this up for readability.
  # pylint: disable=consider-using-in
  save_test_results = (
      not fuzzer.result or not fuzzer.result_timestamp or
      dates.time_has_expired(fuzzer.result_timestamp, days=1) or
      (fuzzer_return_code != 0 and fuzzer_return_code != fuzzer.return_code) or
      (generated_testcase_count != expected_testcase_count and
       fuzzer.return_code == 0 and ' 0/' not in fuzzer.result))
  # pylint: enable=consider-using-in
  if not save_test_results:
    return

  logs.log('Started storing results from fuzzer run.')

  # Store the sample testcase in blobstore first. This can take some time, so
  # do this operation before refreshing fuzzer object.
  sample_testcase = None
  if testcase_file_paths:
    with open(testcase_file_paths[0], 'rb') as sample_testcase_file_handle:
      sample_testcase = blobs.write_blob(sample_testcase_file_handle)

    if not sample_testcase:
      logs.log_error('Could not save testcase from fuzzer run.')

  # Store fuzzer console output.
  bot_name = environment.get_value('BOT_NAME')
  if fuzzer_return_code is not None:
    fuzzer_return_code_string = 'Return code (%d).' % fuzzer_return_code
  else:
    fuzzer_return_code_string = 'Fuzzer timed out.'
  truncated_fuzzer_output = truncate_fuzzer_output(fuzzer_output,
                                                   data_types.ENTITY_SIZE_LIMIT)
  console_output = u'%s: %s\n%s\n%s' % (bot_name, fuzzer_return_code_string,
                                        fuzzer_command, truncated_fuzzer_output)

  # Refresh the fuzzer object.
  fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer.name).get()

  # Make sure fuzzer is same as the latest revision.
  if not fuzzer:
    logs.log_fatal_and_exit('Fuzzer does not exist, exiting.')
  if fuzzer.revision != fuzzer_revision:
    logs.log('Fuzzer was recently updated, skipping results from old version.')
    return

  fuzzer.sample_testcase = sample_testcase
  fuzzer.console_output = console_output
  fuzzer.result = generated_testcase_string
  fuzzer.result_timestamp = datetime.datetime.utcnow()
  fuzzer.return_code = fuzzer_return_code
  fuzzer.put()

  logs.log('Finished storing results from fuzzer run.')


def get_regression(one_time_crasher_flag):
  """Get the right regression value."""
  if one_time_crasher_flag or build_manager.is_custom_binary():
    return 'NA'
  return ''


def get_fixed_or_minimized_key(one_time_crasher_flag):
  """Get the right fixed value."""
  return 'NA' if one_time_crasher_flag else ''


def get_minidump_keys(crash_info):
  """Get minidump_keys."""
  # This is a new crash, so add its minidump to blobstore first and get the
  # blob key information.
  if crash_info:
    return crash_info.store_minidump()
  return ''


def get_testcase_timeout_multiplier(timeout_multiplier, crash, test_timeout,
                                    thread_wait_timeout):
  """Get testcase timeout multiplier."""
  testcase_timeout_multiplier = timeout_multiplier
  if timeout_multiplier > 1 and (crash.crash_time + thread_wait_timeout) < (
      (test_timeout / timeout_multiplier)):
    testcase_timeout_multiplier = 1.0

  return testcase_timeout_multiplier


def create_testcase(group, context):
  """Create a testcase based on crash."""
  crash = group.main_crash
  fully_qualified_fuzzer_name = get_fully_qualified_fuzzer_name(context)
  testcase_id = data_handler.store_testcase(
      crash=crash,
      fuzzed_keys=crash.fuzzed_key,
      minimized_keys=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      regression=get_regression(group.one_time_crasher_flag),
      fixed=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      one_time_crasher_flag=group.one_time_crasher_flag,
      crash_revision=context.crash_revision,
      comment='Fuzzer %s generated testcase crashed in %d seconds (r%d)' %
      (fully_qualified_fuzzer_name, crash.crash_time, context.crash_revision),
      absolute_path=crash.absolute_path,
      fuzzer_name=context.fuzzer_name,
      fully_qualified_fuzzer_name=fully_qualified_fuzzer_name,
      job_type=context.job_type,
      archived=crash.archived,
      archive_filename=crash.archive_filename,
      binary_flag=utils.is_binary_file(crash.file_path),
      http_flag=crash.http_flag,
      gestures=crash.gestures,
      redzone=context.redzone,
      disable_ubsan=context.disable_ubsan,
      minidump_keys=get_minidump_keys(crash.crash_info),
      window_argument=context.window_argument,
      timeout_multiplier=get_testcase_timeout_multiplier(
          context.timeout_multiplier, crash, context.test_timeout,
          context.thread_wait_timeout),
      minimized_arguments=crash.arguments)
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if context.fuzzer_metadata:
    for key, value in six.iteritems(context.fuzzer_metadata):
      testcase.set_metadata(key, value, update_testcase=False)

    testcase.put()

  if crash.fuzzing_strategies:
    testcase.set_metadata(
        'fuzzing_strategies', crash.fuzzing_strategies, update_testcase=True)

  # If there is one, record the original file this testcase was mutated from.
  if (crash.file_path in context.testcases_metadata and
      'original_file_path' in context.testcases_metadata[crash.file_path] and
      context.testcases_metadata[crash.file_path]['original_file_path']):
    testcase_relative_path = utils.get_normalized_relative_path(
        context.testcases_metadata[crash.file_path]['original_file_path'],
        context.data_directory)
    testcase.set_metadata('original_file_path', testcase_relative_path)

  # Track that app args appended by trials are required.
  trial_app_args = environment.get_value('TRIAL_APP_ARGS')
  if trial_app_args:
    testcase.set_metadata('additional_required_app_args', trial_app_args)

  # Create tasks to
  # 1. Minimize testcase (minimize).
  # 2. Find regression range (regression).
  # 3. Find testcase impact on production branches (impact).
  # 4. Check whether testcase is fixed (progression).
  # 5. Get second stacktrace from another job in case of
  #    one-time crashers (stack).
  task_creation.create_tasks(testcase)

  # If this is a new reproducible crash, annotate for upload to Chromecrash.
  if (not (group.one_time_crasher_flag or
           group.has_existing_reproducible_testcase())):
    crash.crash_info = crash_uploader.save_crash_info_if_needed(
        testcase_id, context.crash_revision, context.job_type, crash.crash_type,
        crash.crash_address, crash.crash_frames)

  return testcase


def filter_crashes(crashes):
  """Fitler crashes based on is_valid()."""
  filtered = []

  for crash in crashes:
    if not crash.is_valid():
      logs.log('Ignore crash (reason=%s, type=%s, state=%s).' %
               (crash.get_error(), crash.crash_type, crash.crash_state))
      continue

    filtered.append(crash)

  return filtered


def get_engine(context):
  """Get the fuzzing engine."""
  if context.fuzz_target:
    return context.fuzz_target.engine

  return ''


def get_fully_qualified_fuzzer_name(context):
  """Get the fully qualified fuzzer name."""
  if context.fuzz_target:
    return context.fuzz_target.fully_qualified_name()

  return context.fuzzer_name


def write_crashes_to_big_query(group, context):
  """Write a group of crashes to BigQuery."""
  created_at = int(time.time())

  # Many of ChromeOS fuzz targets run on Linux bots, so we incorrectly set the
  # linux platform for this. We cannot change platform_id in testcase as
  # otherwise linux bots can no longer lease those testcase. So, just change
  # this value in crash stats. This helps cleanup task put correct OS label.
  if environment.is_chromeos_job(context.job_type):
    actual_platform = 'chrome'
  else:
    actual_platform = context.platform_id

  # Write to a specific partition.
  table_id = ('crashes$%s' % (
      datetime.datetime.utcfromtimestamp(created_at).strftime('%Y%m%d')))

  client = big_query.Client(dataset_id='main', table_id=table_id)

  insert_id_prefix = ':'.join(
      [group.crashes[0].key, context.bot_name,
       str(created_at)])

  rows = []
  for index, crash in enumerate(group.crashes):
    created_testcase_id = None
    if crash == group.main_crash and group.newly_created_testcase:
      created_testcase_id = str(group.newly_created_testcase.key.id())

    rows.append(
        big_query.Insert(
            row={
                'crash_type': crash.crash_type,
                'crash_state': crash.crash_state,
                'created_at': created_at,
                'platform': actual_platform,
                'crash_time_in_ms': int(crash.crash_time * 1000),
                'parent_fuzzer_name': get_engine(context),
                'fuzzer_name': get_fully_qualified_fuzzer_name(context),
                'job_type': context.job_type,
                'security_flag': crash.security_flag,
                'project': context.project_name,
                'reproducible_flag': not group.one_time_crasher_flag,
                'revision': str(context.crash_revision),
                'new_flag': group.is_new() and crash == group.main_crash,
                'testcase_id': created_testcase_id
            },
            insert_id='%s:%s' % (insert_id_prefix, index)))

  row_count = len(rows)

  try:
    result = client.insert(rows)
    if result is None:
      # Happens in case the big query function is disabled (local development).
      return

    errors = result.get('insertErrors', [])
    failed_count = len(errors)

    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        row_count - failed_count, {'success': True})
    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        failed_count, {'success': False})

    for error in errors:
      logs.log_error(
          ('Ignoring error writing the crash (%s) to BigQuery.' %
           group.crashes[error['index']].crash_type),
          exception=Exception(error))
  except Exception:
    logs.log_error('Ignoring error writing a group of crashes to BigQuery')
    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        row_count, {'success': False})


def _update_testcase_variant_if_needed(group, context):
  """Update testcase variant if this is not already covered by existing testcase
  variant on this job."""
  assert group.existing_testcase

  variant = data_handler.get_testcase_variant(group.existing_testcase.key.id(),
                                              context.job_type)
  if not variant or variant.status == data_types.TestcaseVariantStatus.PENDING:
    # Either no variant created yet since minimization hasn't finished OR
    # variant analysis is not yet finished. Wait in both cases, since we
    # prefer existing testcase over current one.
    return

  if (variant.status == data_types.TestcaseVariantStatus.REPRODUCIBLE and
      variant.is_similar):
    # Already have a similar reproducible variant, don't need to update.
    return

  variant.reproducer_key = group.main_crash.fuzzed_key
  if group.one_time_crasher_flag:
    variant.status = data_types.TestcaseVariantStatus.FLAKY
  else:
    variant.status = data_types.TestcaseVariantStatus.REPRODUCIBLE
  variant.revision = context.crash_revision
  variant.crash_type = group.main_crash.crash_type
  variant.crash_state = group.main_crash.crash_state
  variant.security_flag = group.main_crash.security_flag
  variant.is_similar = True
  variant.put()


def process_crashes(crashes, context):
  """Process a list of crashes."""
  processed_groups = []
  new_crash_count = 0
  known_crash_count = 0

  def key_fn(crash):
    return crash.key

  # Filter invalid crashes.
  crashes = filter_crashes(crashes)
  group_of_crashes = itertools.groupby(sorted(crashes, key=key_fn), key_fn)

  for _, grouped_crashes in group_of_crashes:
    group = CrashGroup(list(grouped_crashes), context)

    # Archiving testcase to blobstore might fail for all crashes within this
    # group.
    if not group.main_crash:
      logs.log('Unable to store testcase in blobstore: %s' %
               group.crashes[0].crash_state)
      continue

    logs.log(
        'Process the crash group (file=%s, '
        'fuzzed_key=%s, '
        'return code=%s, '
        'crash time=%d, '
        'crash type=%s, '
        'crash state=%s, '
        'security flag=%s, '
        'crash stacktrace=%s)' %
        (group.main_crash.filename, group.main_crash.fuzzed_key,
         group.main_crash.return_code, group.main_crash.crash_time,
         group.main_crash.crash_type, group.main_crash.crash_state,
         group.main_crash.security_flag, group.main_crash.crash_stacktrace))

    if group.should_create_testcase():
      group.newly_created_testcase = create_testcase(
          group=group, context=context)
    else:
      _update_testcase_variant_if_needed(group, context)

    write_crashes_to_big_query(group, context)

    if group.is_new():
      new_crash_count += 1
      known_crash_count += len(group.crashes) - 1
    else:
      known_crash_count += len(group.crashes)
    processed_groups.append(group)

    # Artificial delay to throttle appengine updates.
    time.sleep(1)

  logs.log('Finished processing crashes.')
  logs.log('New crashes: {}, known crashes: {}, processed groups: {}'.format(
      new_crash_count, known_crash_count, processed_groups))
  return new_crash_count, known_crash_count, processed_groups


def get_strategy_distribution_from_ndb():
  """Queries and returns the distribution stored in the ndb table."""
  query = data_types.FuzzStrategyProbability.query()
  distribution = []
  for strategy_entry in list(ndb_utils.get_all_from_query(query)):
    distribution.append({
        'strategy_name': strategy_entry.strategy_name,
        'probability': strategy_entry.probability,
        'engine': strategy_entry.engine
    })
  return distribution


def _get_issue_metadata_from_environment(variable_name):
  """Get issue metadata from environment."""
  values = str(environment.get_value(variable_name, '')).split()
  # Allow a variation with a '_1' to specified. This is needed in cases where
  # this is specified in both the job and the bot environment.
  values.extend(str(environment.get_value(variable_name + '_1', '')).split())
  return [value.strip() for value in values if value.strip()]


def _add_issue_metadata_from_environment(metadata):
  """Add issue metadata from environment."""

  def _append(old, new_values):
    if not old:
      return ','.join(new_values)

    return ','.join(old.split(',') + new_values)

  components = _get_issue_metadata_from_environment('AUTOMATIC_COMPONENTS')
  if components:
    metadata['issue_components'] = _append(
        metadata.get('issue_components'), components)

  labels = _get_issue_metadata_from_environment('AUTOMATIC_LABELS')
  if labels:
    metadata['issue_labels'] = _append(metadata.get('issue_labels'), labels)


def run_engine_fuzzer(engine_impl, target_name, sync_corpus_directory,
                      testcase_directory):
  """Run engine for fuzzing."""
  if environment.is_trusted_host():
    from bot.untrusted_runner import tasks_host
    return tasks_host.engine_fuzz(engine_impl, target_name,
                                  sync_corpus_directory, testcase_directory)

  build_dir = environment.get_value('BUILD_DIR')
  is_blackbox = engine_impl.name == 'blackbox'
  target_path = engine_common.find_fuzzer_path(
      build_dir, target_name, is_blackbox=is_blackbox)
  options = engine_impl.prepare(sync_corpus_directory, target_path, build_dir)

  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  additional_processing_time = engine_impl.fuzz_additional_processing_timeout(
      options)
  fuzz_test_timeout -= additional_processing_time
  if fuzz_test_timeout <= 0:
    raise FuzzTaskException(
        f'Invalid engine timeout: '
        f'{fuzz_test_timeout} - {additional_processing_time}')

  result = engine_impl.fuzz(target_path, options, testcase_directory,
                            fuzz_test_timeout)

  logs.log('Used strategies.', strategies=options.strategies)
  for strategy, value in six.iteritems(options.strategies):
    result.stats['strategy_' + strategy] = value

  # Format logs with header and strategy information.
  log_header = engine_common.get_log_header(result.command,
                                            environment.get_value('BOT_NAME'),
                                            result.time_executed)

  formatted_strategies = engine_common.format_fuzzing_strategies(
      options.strategies)

  result.logs = log_header + '\n' + result.logs + '\n' + formatted_strategies

  fuzzer_metadata = {
      'fuzzer_binary_name': target_name,
  }

  fuzzer_metadata.update(engine_common.get_all_issue_metadata(target_path))
  _add_issue_metadata_from_environment(fuzzer_metadata)

  # Cleanup fuzzer temporary artifacts (e.g. mutations dir, merge dirs. etc).
  fuzzer_utils.cleanup()

  return result, fuzzer_metadata, options.strategies


class FuzzingSession(object):
  """Class for orchestrating fuzzing sessions."""

  def __init__(self, fuzzer_name, job_type, test_timeout):
    self.fuzzer_name = fuzzer_name
    self.job_type = job_type

    # Set up randomly selected fuzzing parameters.
    self.redzone = pick_redzone()
    self.disable_ubsan = pick_ubsan_disabled(job_type)
    self.timeout_multiplier = pick_timeout_multiplier()
    self.window_argument = pick_window_argument()
    self.test_timeout = set_test_timeout(test_timeout, self.timeout_multiplier)

    # Set up during run().
    self.fuzzer = None
    self.testcase_directory = None
    self.data_directory = None

    # Fuzzing engine specific state.
    self.fuzz_target = None
    self.gcs_corpus = None

  @property
  def fully_qualified_fuzzer_name(self):
    """Get the fully qualified fuzzer name."""
    if self.fuzz_target:
      return self.fuzz_target.fully_qualified_name()

    return self.fuzzer_name

  def sync_corpus(self, sync_corpus_directory):
    """Sync corpus from GCS."""
    self.gcs_corpus = GcsCorpus(self.fuzzer_name,
                                self.fuzz_target.project_qualified_name(),
                                sync_corpus_directory, self.data_directory)
    if not self.gcs_corpus.sync_from_gcs():
      raise FuzzTaskException(
          'Failed to sync corpus for fuzzer %s (job %s).' %
          (self.fuzz_target.project_qualified_name(), self.job_type))

  def _save_fuzz_targets_count(self):
    """Save fuzz targets count."""
    count = environment.get_value('FUZZ_TARGET_COUNT')
    if count is None:
      return

    targets_count = ndb.Key(data_types.FuzzTargetsCount, self.job_type).get()
    if not targets_count or targets_count.count != count:
      data_types.FuzzTargetsCount(id=self.job_type, count=count).put()

  def _file_size(self, file_path):
    """Return file size depending on whether file is local or remote (untrusted
    worker)."""
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      stat_result = file_host.stat(file_path)
      return stat_result.st_size if stat_result else None

    return os.path.getsize(file_path)

  def sync_new_corpus_files(self):
    """Sync new files from corpus to GCS."""
    if not self.gcs_corpus:
      return

    new_files = self.gcs_corpus.get_new_files()
    new_files_count = len(new_files)
    logs.log('%d new corpus files generated by fuzzer %s (job %s).' %
             (new_files_count, self.fuzz_target.project_qualified_name(),
              self.job_type))

    filtered_new_files = []
    filtered_new_files_count = 0
    for new_file in new_files:
      if filtered_new_files_count >= MAX_NEW_CORPUS_FILES:
        break
      if self._file_size(new_file) > engine_common.CORPUS_INPUT_SIZE_LIMIT:
        continue
      filtered_new_files.append(new_file)
      filtered_new_files_count += 1

    if filtered_new_files_count < new_files_count:
      logs.log(('Uploading only %d out of %d new corpus files '
                'generated by fuzzer %s (job %s).') %
               (filtered_new_files_count, new_files_count,
                self.fuzz_target.project_qualified_name(), self.job_type))

    self.gcs_corpus.upload_files(filtered_new_files)

  def generate_blackbox_testcases(self, fuzzer, fuzzer_directory,
                                  testcase_count):
    """Run the blackbox fuzzer and generate testcases."""
    # Helper variables.
    error_occurred = False
    fuzzer_revision = fuzzer.revision
    fuzzer_name = fuzzer.name
    sync_corpus_directory = None

    # Clear existing testcases (only if past task failed).
    testcase_directories = get_testcase_directories(self.testcase_directory,
                                                    self.data_directory)
    testcase_manager.remove_testcases_from_directories(testcase_directories)

    # Set an environment variable for fuzzer name.
    # TODO(ochang): Investigate removing this. Only users appear to be chromebot
    # fuzzer and fuzzer_logs, both of which can be removed.
    environment.set_value('FUZZER_NAME', fuzzer_name)

    # Set minimum redzone size, do not detect leaks and zero out the
    # quarantine size before running the fuzzer.
    environment.reset_current_memory_tool_options(
        redzone_size=16, leaks=False, quarantine_size_mb=0)

    if fuzzer.builtin:
      fuzzer_command = 'builtin'
      builtin_fuzzer = builtin_fuzzers.get(fuzzer.name)

      builtin_result = builtin_fuzzer.run(
          self.data_directory, self.testcase_directory, testcase_count)

      fuzzer_output = builtin_result.output
      sync_corpus_directory = builtin_result.corpus_directory

      # Return code is always 0 as builtin fuzzers log errors directly.
      fuzzer_return_code = 0
    else:
      # Make sure we have a file to execute for the fuzzer.
      if not fuzzer.executable_path:
        logs.log_error(
            'Fuzzer %s does not have an executable path.' % fuzzer_name)
        error_occurred = True
        return error_occurred, None, None, None

      # Get the fuzzer executable and chdir to its base directory. This helps to
      # prevent referencing every file using __file__.
      fuzzer_executable = os.path.join(fuzzer_directory, fuzzer.executable_path)
      fuzzer_executable_directory = os.path.dirname(fuzzer_executable)

      # Make sure the fuzzer executable exists on disk.
      if not os.path.exists(fuzzer_executable):
        logs.log_error(
            'File %s does not exist. Cannot generate testcases for fuzzer %s.' %
            (fuzzer_executable, fuzzer_name))
        error_occurred = True
        return error_occurred, None, None, None, None

      # Build the fuzzer command execution string.
      command = shell.get_execute_command(fuzzer_executable)

      # NodeJS and shell script expect space seperator for arguments.
      if command.startswith('node ') or command.startswith('sh '):
        argument_seperator = ' '
      else:
        argument_seperator = '='

      command_format = ('%s --input_dir%s%s --output_dir%s%s --no_of_files%s%d')
      fuzzer_command = str(
          command_format % (command, argument_seperator, self.data_directory,
                            argument_seperator, self.testcase_directory,
                            argument_seperator, testcase_count))
      fuzzer_timeout = environment.get_value('FUZZER_TIMEOUT')

      # Run the fuzzer.
      logs.log('Running fuzzer - %s.' % fuzzer_command)
      fuzzer_return_code, fuzzer_duration, fuzzer_output = (
          process_handler.run_process(
              fuzzer_command,
              current_working_directory=fuzzer_executable_directory,
              timeout=fuzzer_timeout,
              testcase_run=False,
              ignore_children=False))

      # Use the custom return code for timeouts if needed.
      if fuzzer_return_code is None:
        fuzzer_return_code = FuzzErrorCode.FUZZER_TIMEOUT

      # Use the custom return code for execution failures if needed.
      if fuzzer_duration is None:
        fuzzer_return_code = FuzzErrorCode.FUZZER_EXECUTION_FAILED

    # Force GC to save some memory before processing fuzzer output.
    utils.python_gc()

    # For Android, we need to sync our local testcases directory with the one on
    # the device.
    if environment.is_android():
      android.device.push_testcases_to_device()

    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      file_host.push_testcases_to_worker()

    fuzzer_metadata = get_fuzzer_metadata_from_output(fuzzer_output)
    _add_issue_metadata_from_environment(fuzzer_metadata)

    # Filter fuzzer output, set to default value if empty.
    if fuzzer_output:
      fuzzer_output = utils.decode_to_unicode(fuzzer_output)
    else:
      fuzzer_output = u'No output!'

    # Get the list of generated testcases.
    testcase_file_paths, generated_testcase_count, generated_testcase_string = (
        get_testcases(testcase_count, self.testcase_directory,
                      self.data_directory))

    # Check for process return code to identify abnormal termination.
    if fuzzer_return_code:
      if float(
          generated_testcase_count) / testcase_count < FUZZER_FAILURE_THRESHOLD:
        logs.log_error(
            ('Fuzzer failed to generate testcases '
             '(fuzzer={name}, return_code={return_code}).').format(
                 name=fuzzer_name, return_code=fuzzer_return_code),
            output=fuzzer_output)
      else:
        logs.log_warn(
            ('Fuzzer generated less than expected testcases '
             '(fuzzer={name}, return_code={return_code}).').format(
                 name=fuzzer_name, return_code=fuzzer_return_code),
            output=fuzzer_output)

    # Store fuzzer run results.
    store_fuzzer_run_results(testcase_file_paths, fuzzer, fuzzer_command,
                             fuzzer_output, fuzzer_return_code, fuzzer_revision,
                             generated_testcase_count, testcase_count,
                             generated_testcase_string)

    # Upload blackbox fuzzer test cases to GCS on a small number of runs.
    coverage_uploader.upload_testcases_if_needed(
        fuzzer.name, testcase_file_paths, self.testcase_directory,
        self.data_directory)

    # Make sure that there are testcases generated. If not, set the error flag.
    error_occurred = not testcase_file_paths

    _track_fuzzer_run_result(fuzzer_name, generated_testcase_count,
                             testcase_count, fuzzer_return_code)

    return (error_occurred, testcase_file_paths, sync_corpus_directory,
            fuzzer_metadata)

  def do_engine_fuzzing(self, engine_impl):
    """Run fuzzing engine."""
    # For blackbox fuzzers, |FUZZ_TARGET| should be set to the fuzzer name.
    if engine_impl.name == 'blackbox':
      environment.set_value('FUZZ_TARGET', self.fuzzer_name)

    # Record fuzz target.
    fuzz_target_name = environment.get_value('FUZZ_TARGET')
    if not fuzz_target_name:
      raise FuzzTaskException('No fuzz targets found.')

    self.fuzz_target = record_fuzz_target(engine_impl.name, fuzz_target_name,
                                          self.job_type)
    environment.set_value('FUZZER_NAME',
                          self.fuzz_target.fully_qualified_name())

    # Synchronize corpus files with GCS
    sync_corpus_directory = builtin.get_corpus_directory(
        self.data_directory, self.fuzz_target.project_qualified_name())
    self.sync_corpus(sync_corpus_directory)

    # Reset memory tool options.
    environment.reset_current_memory_tool_options(
        redzone_size=self.redzone, disable_ubsan=self.disable_ubsan)

    revision = environment.get_value('APP_REVISION')
    crashes = []
    fuzzer_metadata = {}
    return_code = 1  # Vanilla return-code for engine crashes.

    # Do the actual fuzzing.
    for fuzzing_round in range(environment.get_value('MAX_TESTCASES', 1)):
      logs.log('Fuzzing round {}.'.format(fuzzing_round))
      result, current_fuzzer_metadata, fuzzing_strategies = run_engine_fuzzer(
          engine_impl, self.fuzz_target.binary, sync_corpus_directory,
          self.testcase_directory)
      fuzzer_metadata.update(current_fuzzer_metadata)

      # Prepare stats.
      testcase_run = engine_common.get_testcase_run(result.stats,
                                                    result.command)

      # Upload logs, testcases (if there are crashes), and stats.
      # Use a consistent log time to allow correlating between logs, uploaded
      # testcases, and stats.
      log_time = datetime.datetime.utcfromtimestamp(
          float(testcase_run.timestamp))
      crash_result = CrashResult(return_code, result.time_executed, result.logs)
      log = testcase_manager.prepare_log_for_upload(
          crash_result.get_stacktrace(), return_code)
      testcase_manager.upload_log(log, log_time)

      for crash in result.crashes:
        testcase_manager.upload_testcase(crash.input_path, log_time)

      add_additional_testcase_run_data(testcase_run,
                                       self.fuzz_target.fully_qualified_name(),
                                       self.job_type, revision)
      upload_testcase_run_stats(testcase_run)
      if result.crashes:
        crashes.extend([
            Crash.from_engine_crash(crash, fuzzing_strategies)
            for crash in result.crashes
            if crash
        ])

    logs.log('All fuzzing rounds complete.')
    self.sync_new_corpus_files()

    return crashes, fuzzer_metadata

  def do_blackbox_fuzzing(self, fuzzer, fuzzer_directory, job_type):
    """Run blackbox fuzzing. Currently also used for engine fuzzing."""
    # Set the thread timeout values.
    # TODO(ochang): Remove this hack once engine fuzzing refactor is compelte.
    fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
    if fuzz_test_timeout:
      test_timeout = set_test_timeout(fuzz_test_timeout,
                                      self.timeout_multiplier)
    else:
      test_timeout = self.test_timeout

    thread_timeout = test_timeout

    # Determine number of testcases to process.
    testcase_count = environment.get_value('MAX_TESTCASES')

    # For timeout multipler greater than 1, we need to decrease testcase count
    # to prevent exceeding task lease time.
    if self.timeout_multiplier > 1:
      testcase_count /= self.timeout_multiplier

    # Run the fuzzer to generate testcases. If error occurred while trying
    # to run the fuzzer, bail out.
    (error_occurred, testcase_file_paths, sync_corpus_directory,
     fuzzer_metadata) = self.generate_blackbox_testcases(
         fuzzer, fuzzer_directory, testcase_count)

    if error_occurred:
      return None, None, None, None

    fuzzer_binary_name = fuzzer_metadata.get('fuzzer_binary_name')
    if fuzzer_binary_name:
      self.fuzz_target = record_fuzz_target(fuzzer.name, fuzzer_binary_name,
                                            job_type)

    environment.set_value('FUZZER_NAME', self.fully_qualified_fuzzer_name)

    # Synchronize corpus files with GCS
    if sync_corpus_directory:
      self.sync_corpus(sync_corpus_directory)
      environment.set_value('FUZZ_CORPUS_DIR', sync_corpus_directory)

    # Initialize a list of crashes.
    crashes = []

    # Helper variables.
    max_threads = utils.maximum_parallel_processes_allowed()
    needs_stale_process_cleanup = False
    test_number = 0
    testcases_before_stale_process_cleanup = environment.get_value(
        'TESTCASES_BEFORE_STALE_PROCESS_CLEANUP', 1)
    thread_delay = environment.get_value('THREAD_DELAY')
    thread_error_occurred = False

    # TODO: Remove environment variable once fuzzing engine refactor is
    # complete. Set multi-armed bandit strategy selection distribution as an
    # environment variable so we can access it in launcher.
    if environment.get_value('USE_BANDIT_STRATEGY_SELECTION'):
      selection_method = utils.random_weighted_choice(
          SELECTION_METHOD_DISTRIBUTION, 'probability')
      environment.set_value('STRATEGY_SELECTION_METHOD',
                            selection_method.method_name)
      distribution = get_strategy_distribution_from_ndb()
      if distribution:
        environment.set_value('STRATEGY_SELECTION_DISTRIBUTION', distribution)

    # Reset memory tool options.
    environment.reset_current_memory_tool_options(
        redzone_size=self.redzone, disable_ubsan=self.disable_ubsan)

    # Create a dict to store metadata specific to each testcase.
    testcases_metadata = {}
    for testcase_file_path in testcase_file_paths:
      testcases_metadata[testcase_file_path] = {}

      # Pick up a gesture to run on the testcase.
      testcases_metadata[testcase_file_path]['gestures'] = pick_gestures(
          test_timeout)

    logs.log('Starting to process testcases.')
    logs.log('Redzone is %d bytes.' % self.redzone)
    logs.log('Timeout multiplier is %s.' % str(self.timeout_multiplier))
    logs.log('App launch command is %s.' %
             testcase_manager.get_command_line_for_application())

    # Start processing the testcases.
    while test_number < len(testcase_file_paths):
      thread_index = 0
      threads = []

      temp_queue = process_handler.get_queue()
      if not temp_queue:
        process_handler.terminate_stale_application_instances()
        logs.log_error('Unable to create temporary crash queue.')
        break

      while thread_index < max_threads and test_number < len(
          testcase_file_paths):
        testcase_file_path = testcase_file_paths[test_number]
        gestures = testcases_metadata[testcase_file_path]['gestures']

        env_copy = environment.copy()
        thread = process_handler.get_process()(
            target=testcase_manager.run_testcase_and_return_result_in_queue,
            args=(temp_queue, thread_index, testcase_file_path, gestures,
                  env_copy, True))

        try:
          thread.start()
        except:
          process_handler.terminate_stale_application_instances()
          thread_error_occurred = True
          logs.log_error('Unable to start new thread.')
          break

        threads.append(thread)
        thread_index += 1
        test_number += 1

        if test_number % testcases_before_stale_process_cleanup == 0:
          needs_stale_process_cleanup = True

        time.sleep(thread_delay)

      with _TrackFuzzTime(self.fully_qualified_fuzzer_name,
                          job_type) as tracker:
        tracker.timeout = utils.wait_until_timeout(threads, thread_timeout)

      # Allow for some time to finish processing before terminating the
      # processes.
      process_handler.terminate_hung_threads(threads)

      # It is not necessary to clean up stale instances on every batch, but
      # should be done at regular intervals to ensure we are in a good state.
      if needs_stale_process_cleanup:
        process_handler.terminate_stale_application_instances()
        needs_stale_process_cleanup = False

      while not temp_queue.empty():
        crashes.append(temp_queue.get())

      process_handler.close_queue(temp_queue)

      logs.log('Upto %d' % test_number)

      if thread_error_occurred:
        break

    # Pull testcase directory to host. The testcase file contents could have
    # been changed (by e.g. libFuzzer) and stats files could have been written.
    if environment.is_trusted_host():
      from bot.untrusted_runner import file_host
      file_host.pull_testcases_from_worker()

    # Synchronize corpus files with GCS after fuzzing
    self.sync_new_corpus_files()

    # Currently, the decision to do fuzzing or running the testcase is based on
    # the value of |FUZZ_CORPUS_DIR|. Reset it to None, so that later runs of
    # testForReproducibility run the testcase.
    # FIXME: Change to environment.remove_key call when it supports removing
    # the environment variable on untrusted bot (as part of
    # bot.untrusted_runner import environment).
    environment.set_value('FUZZ_CORPUS_DIR', None)

    # Restore old values before attempting to test for reproducibility.
    set_test_timeout(self.test_timeout, 1.0)

    if crashes:
      crashes = [
          Crash.from_testcase_manager_crash(crash) for crash in crashes if crash
      ]
    return fuzzer_metadata, testcase_file_paths, testcases_metadata, crashes

  def run(self):
    """Run the fuzzing session."""
    failure_wait_interval = environment.get_value('FAIL_WAIT')

    # Update LSAN local blacklist with global blacklist.
    is_lsan_enabled = environment.get_value('LSAN')
    if is_lsan_enabled:
      leak_blacklist.copy_global_to_local_blacklist()

    # Ensure that that the fuzzer still exists.
    logs.log('Setting up fuzzer and data bundles.')
    self.fuzzer = setup.update_fuzzer_and_data_bundles(self.fuzzer_name)
    if not self.fuzzer:
      _track_fuzzer_run_result(self.fuzzer_name, 0, 0,
                               FuzzErrorCode.FUZZER_SETUP_FAILED)
      logs.log_error('Unable to setup fuzzer %s.' % self.fuzzer_name)

      # Artifical sleep to slow down continuous failed fuzzer runs if the bot is
      # using command override for task execution.
      time.sleep(failure_wait_interval)
      return

    self.testcase_directory = environment.get_value('FUZZ_INPUTS')

    # Set up a custom or regular build based on revision. By default, fuzzing
    # is done on trunk build (using revision=None). Otherwise, a job definition
    # can provide a revision to use via |APP_REVISION|.
    target_weights = fuzzer_selection.get_fuzz_target_weights()

    build_setup_result = build_manager.setup_build(
        environment.get_value('APP_REVISION'), target_weights=target_weights)
    # Check if we have an application path. If not, our build failed
    # to setup correctly.
    if not build_setup_result or not build_manager.check_app_path():
      _track_fuzzer_run_result(self.fuzzer_name, 0, 0,
                               FuzzErrorCode.BUILD_SETUP_FAILED)
      return

    dataflow_bucket_path = environment.get_value('DATAFLOW_BUILD_BUCKET_PATH')
    if dataflow_bucket_path:
      # Some fuzzing jobs may use auxiliary builds, such as DFSan instrumented
      # builds accompanying libFuzzer builds to enable DFT-based fuzzing.
      if not build_manager.setup_trunk_build(
          [dataflow_bucket_path], build_prefix='DATAFLOW'):
        logs.log_error('Failed to set up dataflow build.')

    # Save fuzz targets count to aid with CPU weighting.
    self._save_fuzz_targets_count()

    # Check if we have a bad build, i.e. one that crashes on startup.
    # If yes, bail out.
    logs.log('Checking for bad build.')
    crash_revision = environment.get_value('APP_REVISION')
    is_bad_build = testcase_manager.check_for_bad_build(self.job_type,
                                                        crash_revision)
    _track_build_run_result(self.job_type, crash_revision, is_bad_build)
    if is_bad_build:
      return

    # Data bundle directories can also have testcases which are kept in-place
    # because of dependencies.
    self.data_directory = setup.get_data_bundle_directory(self.fuzzer_name)
    if not self.data_directory:
      _track_fuzzer_run_result(self.fuzzer_name, 0, 0,
                               FuzzErrorCode.DATA_BUNDLE_SETUP_FAILED)
      logs.log_error(
          'Unable to setup data bundle %s.' % self.fuzzer.data_bundle_name)
      return

    # For some binaries, we specify trials, which are sets of flags that we only
    # apply some of the time. Adjust APP_ARGS for them if needed.
    trials.setup_additional_args_for_app()

    # TODO(mbarbella): Remove the environment variable check when the old
    # blackbox pipeline has been converted to the engine interface.
    engine_impl = engine.get(self.fuzzer.name)
    if not engine_impl and environment.get_value('USE_BLACKBOX_ENGINE'):
      engine_impl = engine.get('blackbox')

    if engine_impl:
      crashes, fuzzer_metadata = self.do_engine_fuzzing(engine_impl)

      # Not applicable to engine fuzzers.
      testcase_file_paths = []
      testcases_metadata = {}
    else:
      fuzzer_directory = setup.get_fuzzer_directory(self.fuzzer_name)
      fuzzer_metadata, testcase_file_paths, testcases_metadata, crashes = (
          self.do_blackbox_fuzzing(self.fuzzer, fuzzer_directory,
                                   self.job_type))

    if crashes is None:
      # Error occurred in generate_blackbox_testcases.
      # TODO(ochang): Pipe this error a little better.
      return

    logs.log('Finished processing test cases.')

    platform_id = environment.get_platform_id()

    # For Android, bring back device to a good state before analyzing crashes.
    if environment.is_android() and crashes:
      # Remove this variable so that application is fully shutdown before every
      # re-run of testcase. This is critical for reproducibility.
      environment.remove_key('CHILD_PROCESS_TERMINATION_PATTERN')

      # TODO(unassigned): Need to find a way to this efficiently before every
      # testcase is analyzed.
      android.device.initialize_device()

    logs.log('Raw crash count: ' + str(len(crashes)))

    project_name = data_handler.get_project_name(self.job_type)

    # Process and save crashes to datastore.
    bot_name = environment.get_value('BOT_NAME')
    new_crash_count, known_crash_count, processed_groups = process_crashes(
        crashes=crashes,
        context=Context(
            project_name=project_name,
            bot_name=bot_name,
            job_type=self.job_type,
            fuzz_target=self.fuzz_target,
            redzone=self.redzone,
            disable_ubsan=self.disable_ubsan,
            platform_id=platform_id,
            crash_revision=crash_revision,
            fuzzer_name=self.fuzzer_name,
            window_argument=self.window_argument,
            fuzzer_metadata=fuzzer_metadata,
            testcases_metadata=testcases_metadata,
            timeout_multiplier=self.timeout_multiplier,
            test_timeout=self.test_timeout,
            thread_wait_timeout=THREAD_WAIT_TIMEOUT,
            data_directory=self.data_directory))

    read_and_upload_testcase_run_stats(
        self.fuzzer_name, self.fully_qualified_fuzzer_name, self.job_type,
        crash_revision, testcase_file_paths)
    upload_job_run_stats(self.fully_qualified_fuzzer_name, self.job_type,
                         crash_revision, time.time(),
                         new_crash_count, known_crash_count,
                         len(testcase_file_paths), processed_groups)

    # Delete the fuzzed testcases. This is explicitly needed since
    # some testcases might reside on NFS and would otherwise be
    # left forever.
    for testcase_file_path in testcase_file_paths:
      shell.remove_file(testcase_file_path)

    # Explicit cleanup for large vars.
    del testcase_file_paths
    del testcases_metadata
    utils.python_gc()


def execute_task(fuzzer_name, job_type):
  """Runs the given fuzzer for one round."""
  test_timeout = environment.get_value('TEST_TIMEOUT')
  session = FuzzingSession(fuzzer_name, job_type, test_timeout)
  session.run()
