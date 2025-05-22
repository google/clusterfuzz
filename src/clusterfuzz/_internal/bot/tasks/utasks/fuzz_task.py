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
import json
import os
import random
import re
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from google.cloud import ndb

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import builtin
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.bot.fuzzers.libFuzzer import stats as libfuzzer_stats
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks import trials
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task_knobs
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis import crash_result
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import fuzzer_logs
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.platforms import android
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

# pylint: disable=no-member

FUZZER_METADATA_REGEX = re.compile(r'metadata::(\w+):\s*(.*)')
FUZZER_FAILURE_THRESHOLD = 0.33
MAX_NEW_CORPUS_FILES = 500
THREAD_WAIT_TIMEOUT = 1
MAX_CRASHES_UPLOADED = 64

ENGINE_OUTPUT_LIMIT = 10 * 2**20


class FuzzTaskError(Exception):
  """Fuzz task exception."""


class FuzzTargetNotFoundError(Exception):
  """Fuzz target not in build."""


class FuzzErrorCode:
  FUZZER_TIMEOUT = -1
  FUZZER_SETUP_FAILED = -2
  FUZZER_EXECUTION_FAILED = -3
  DATA_BUNDLE_SETUP_FAILED = -4
  BUILD_SETUP_FAILED = -5


Context = collections.namedtuple('Context', [
    'project_name', 'bot_name', 'job_type', 'fuzz_target', 'redzone',
    'disable_ubsan', 'platform_id', 'crash_revision', 'fuzzer_name',
    'window_argument', 'fuzzer_metadata', 'testcases_metadata',
    'timeout_multiplier', 'test_timeout', 'data_directory'
])

GenerateBlackboxTestcasesResult = collections.namedtuple(
    'GenerateBlackboxTestcasesResult',
    ['success', 'testcase_file_paths', 'fuzzer_metadata'])


def get_unsymbolized_crash_stacktrace(stack_file_path):
  """Read unsymbolized crash stacktrace."""
  with open(stack_file_path, 'rb') as f:
    return utils.decode_to_unicode(f.read())


class NoMoreUploadUrlsError(Exception):
  """Error for when we run out upload urls."""


class UploadUrlCollection:
  """Upload URLs collection."""

  def __init__(self, upload_urls: List[uworker_msg_pb2.BlobUploadUrl]):
    self.upload_urls = upload_urls

  def get(self) -> uworker_msg_pb2.BlobUploadUrl:
    if not self.upload_urls:
      raise NoMoreUploadUrlsError

    url = self.upload_urls[0]
    self.upload_urls = self.upload_urls[1:]
    return url


def _get_max_testcases() -> int:
  return environment.get_value('MAX_TESTCASES', 1)


def _get_max_corpus_uploads_per_task():
  number_of_fuzzer_runs = _get_max_testcases()
  return MAX_NEW_CORPUS_FILES * number_of_fuzzer_runs


class Crash:
  """Represents a crash (before creating a testcase)."""

  @classmethod
  def from_testcase_manager_crash(cls, crash):
    """Create a Crash from a testcase_manager.Crash."""
    try:
      orig_unsymbolized_crash_stacktrace = (
          get_unsymbolized_crash_stacktrace(crash.stack_file_path))
    except Exception:
      logs.error(
          f'Unable to read stacktrace from file {crash.stack_file_path}.')
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
        http_flag=False,
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
    self.crash_categories = state.crash_categories
    self.security_flag = crash_analyzer.is_security_issue(
        self.unsymbolized_crash_stacktrace, self.crash_type, self.crash_address)
    self.key = f'{self.crash_type},{self.crash_state},{self.security_flag}'
    self.should_be_ignored = crash_analyzer.ignore_stacktrace(
        state.crash_stacktrace)

    # self.crash_info gets populated in create_testcase; save what we need.
    self.crash_frames = state.frames
    self.crash_info = None
    self.fuzzed_key = None
    self.absolute_path = None
    self.archive_filename = None
    self.archived = False

  @property
  def filename(self):
    return os.path.basename(self.file_path)

  def is_uploaded(self):
    """Return true if archive_testcase_in_blobstore(..) was performed."""
    return self.fuzzed_key is not None

  def archive_testcase_in_blobstore(self,
                                    upload_url: uworker_msg_pb2.BlobUploadUrl):
    """Calling setup.archive_testcase_and_dependencies_in_gcs(..)
      and hydrate certain attributes. We single out this method because it's
      expensive and we want to do it at the very last minute."""
    if self.is_uploaded():
      return

    if upload_url.key:
      # TODO(metzman): Figure out if we need this check and if we can get rid of
      # the archived return value.
      self.fuzzed_key = upload_url.key
    self.archived, self.absolute_path, self.archive_filename = (
        setup.archive_testcase_and_dependencies_in_gcs(
            self.resource_list, self.file_path, upload_url.url))

  def is_valid(self):
    """Return true if the crash is valid for processing."""
    return self.get_error() is None

  def get_error(self):
    """Return the reason why the crash is invalid."""
    filter_functional_bugs = environment.get_value('FILTER_FUNCTIONAL_BUGS')
    if filter_functional_bugs and not self.security_flag:
      return f'Functional crash is ignored: {self.crash_state}'

    if self.should_be_ignored:
      return (f'False crash: {self.crash_state}\n\n'
              f'---{self.unsymbolized_crash_stacktrace}\n\n'
              f'---{self.crash_stacktrace}')

    if self.is_uploaded() and not self.fuzzed_key:
      return f'Unable to store testcase in blobstore: {self.crash_state}'

    if not self.crash_state or not self.crash_type:
      return 'Empty crash state or type'

    return None

  def to_proto(self):
    """Converts this object to a proto."""
    is_valid = self.is_valid()
    crash = uworker_msg_pb2.FuzzTaskCrash()
    crash.is_valid = is_valid
    crash.file_path = self.file_path
    crash.crash_time = self.crash_time
    crash.return_code = self.return_code
    crash.resource_list.extend(self.resource_list)
    crash.gestures.extend(self.gestures)
    crash.arguments = self.arguments
    if self.fuzzing_strategies:
      crash.fuzzing_strategies.extend(self.fuzzing_strategies)
    crash.http_flag = self.http_flag
    crash.application_command_line = self.application_command_line
    crash.unsymbolized_crash_stacktrace = self.unsymbolized_crash_stacktrace
    crash.crash_type = self.crash_type
    crash.crash_address = self.crash_address
    crash.crash_state = self.crash_state
    crash.crash_stacktrace = self.crash_stacktrace
    crash.crash_categories.extend(self.crash_categories)
    crash.security_flag = self.security_flag
    crash.key = self.key
    crash.should_be_ignored = self.should_be_ignored
    crash.archived = self.archived
    if self.fuzzed_key:
      crash.fuzzed_key = self.fuzzed_key
      crash.absolute_path = self.absolute_path
    if self.archive_filename:
      crash.archive_filename = self.archive_filename
    return crash


def find_main_crash(crashes: List[Crash],
                    fuzz_target: Optional[data_types.FuzzTarget],
                    test_timeout: int, upload_urls: UploadUrlCollection):
  """Find the first reproducible crash or the first valid crash. And return the
    crash and the one_time_crasher_flag."""
  for crash in crashes:
    # Archiving testcase to blobstore when we need to because it's expensive.
    crash.archive_testcase_in_blobstore(upload_urls.get())

    # We need to check again if the crash is valid. In other words, we check
    # if archiving to blobstore succeeded.
    if not crash.is_valid():
      continue

    # We pass an empty expected crash state since our initial stack from fuzzing
    # can be incomplete. So, make a judgement on reproducibility based on passed
    # security flag and crash state generated from re-running testcase in
    # test_for_reproducibility. Minimize task will later update the new crash
    # type and crash state parameters.
    if testcase_manager.test_for_reproducibility(
        fuzz_target,
        crash.file_path,
        crash.crash_type,
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


class CrashGroup:
  """Represent a group of identical crashes. The key is
      (crash_type, crash_state, security_flag)."""

  def __init__(self, crashes: List[Crash], context,
               upload_urls: UploadUrlCollection):
    for c in crashes:
      assert crashes[0].crash_type == c.crash_type
      assert crashes[0].crash_state == c.crash_state
      assert crashes[0].security_flag == c.security_flag

    self.crashes = crashes
    self.main_crash, self.one_time_crasher_flag = find_main_crash(
        crashes, context.fuzz_target, context.test_timeout, upload_urls)

    self.newly_created_testcase = None


def _should_create_testcase(group: uworker_msg_pb2.FuzzTaskCrashGroup,
                            existing_testcase):
  """Returns True if this crash should create a testcase."""
  if not existing_testcase:
    return True

  if not existing_testcase.one_time_crasher_flag:
    # Existing testcase is reproducible, don't need to create another one.
    return False

  # TODO(aarya): We should probably update last tested stacktrace in existing
  # testcase without any race conditions.

  # Should create a new testcase if this one is reproducible but existing one is
  # not. Otherwise, this one isn't reproducible either so don't create a new
  # one.
  return not group.one_time_crasher_flag


class _TrackFuzzTime:
  """Track the actual fuzzing time (e.g. excluding preparing binary)."""

  def __init__(self, fuzzer_name, job_type, time_module=time):
    self.fuzzer_name = fuzzer_name
    self.job_type = job_type
    self.time = time_module
    self.start_time = None
    self.timeout = None

  def __enter__(self):
    self.start_time = self.time.time()
    self.timeout = False
    return self

  def __exit__(self, exc_type, value, traceback):
    duration = self.time.time() - self.start_time
    monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'fuzzer': self.fuzzer_name,
            'timeout': self.timeout,
            'platform': environment.platform(),
        })
    monitoring_metrics.JOB_TOTAL_FUZZ_TIME.increment_by(
        int(duration), {
            'job': self.job_type,
            'timeout': self.timeout,
            'platform': environment.platform(),
        })


def _track_fuzzer_run_result(fuzzer_name, job_type, generated_testcase_count,
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
      'platform': environment.platform(),
      'job': job_type,
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
          'platform': environment.platform(),
      })
  monitoring_metrics.FUZZER_NEW_CRASH_COUNT.increment_by(
      new_crash_count, {
          'fuzzer': fuzzer,
          'platform': environment.platform(),
      })
  monitoring_metrics.JOB_KNOWN_CRASH_COUNT.increment_by(known_crash_count, {
      'job': job_type,
      'platform': environment.platform(),
  })
  monitoring_metrics.JOB_NEW_CRASH_COUNT.increment_by(new_crash_count, {
      'job': job_type,
      'platform': environment.platform()
  })


def _last_sync_time(sync_file_path):
  """Read and parse the last sync file for the GCS corpus."""
  if not os.path.exists(sync_file_path):
    return None

  file_contents = utils.read_data_from_file(sync_file_path, eval_data=False)
  if not file_contents:
    logs.warning('Empty last sync file.', path=sync_file_path)
    return None

  last_sync_time = None
  try:
    last_sync_time = datetime.datetime.utcfromtimestamp(float(file_contents))
  except Exception as e:
    logs.error(
        f'Malformed last sync file: "{e}".',
        path=sync_file_path,
        contents=file_contents)

  return last_sync_time


class GcsCorpus:
  """Sync state for a corpus."""

  def __init__(self, engine_name, project_qualified_target_name,
               corpus_directory, data_directory, proto_corpus):
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import \
          corpus_manager as remote_corpus_manager
      self.gcs_corpus = remote_corpus_manager.RemoteFuzzTargetCorpus(
          engine_name, project_qualified_target_name)
    else:
      self.gcs_corpus = corpus_manager.ProtoFuzzTargetCorpus.deserialize(
          proto_corpus)

    self._corpus_directory = corpus_directory
    self._data_directory = data_directory
    self._project_qualified_target_name = project_qualified_target_name
    self._synced_files = set()

  def _walk(self):
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      yield from file_host.list_files(self._corpus_directory, recursive=True)
    else:
      for root, _, files in shell.walk(self._corpus_directory):
        for filename in files:
          yield os.path.join(root, filename)

  def _get_gcs_url(self):
    # TODO(https://github.com/google/clusterfuzz/issues/3726): Get rid of this
    # wrapper when untrusted runner is removed.
    return self.gcs_corpus.get_gcs_url()

  def _sync_to_disk(self, corpus_directory):
    self.gcs_corpus.rsync_to_disk(corpus_directory)
    return True

  def sync_from_gcs(self):
    """Update sync state after a sync from GCS."""
    already_synced = False
    sync_file_path = os.path.join(
        self._data_directory, f'.{self._project_qualified_target_name}_sync')

    # Get last time we synced corpus.
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      worker_sync_file_path = file_host.rebase_to_worker_root(sync_file_path)
      shell.remove_file(sync_file_path)
      file_host.copy_file_from_worker(worker_sync_file_path, sync_file_path)
    last_sync_time = _last_sync_time(sync_file_path)

    # Check if the corpus was recently synced. If yes, set a flag so that we
    # don't sync it again and save some time.
    # TODO(metzman): Consider removing this after migration is complete. It
    # probably doesn't save much time as corpus syncing is super fast after
    # async syncing was added.
    if not environment.is_uworker() and last_sync_time and os.path.exists(
        self._corpus_directory):
      last_update_time = storage.last_updated(self._get_gcs_url())
      if last_update_time and last_sync_time > last_update_time:
        logs.info('Corpus for target %s has no new updates, skipping rsync.' %
                  self._project_qualified_target_name)
        already_synced = True

    time_before_sync_start = time.time()
    result = already_synced or self._sync_to_disk(self._corpus_directory)
    self._synced_files.clear()
    self._synced_files.update(self._walk())
    logs.info(f'{len(self._synced_files)} corpus files for target '
              f'{self._project_qualified_target_name} synced to disk.')

    # On success of rsync, update the last sync file with current timestamp.
    if result and self._synced_files and not already_synced:
      utils.write_data_to_file(time_before_sync_start, sync_file_path)

      if environment.is_trusted_host():
        from clusterfuzz._internal.bot.untrusted_runner import file_host
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


def get_fuzzer_metadata_from_output(fuzzer_output):
  """Extract metadata from fuzzer output."""
  metadata = {}
  for line in fuzzer_output.splitlines():
    match = FUZZER_METADATA_REGEX.match(line)
    if match:
      metadata[match.group(1)] = match.group(2)

  return metadata


def get_testcases(testcase_count, testcase_directory, data_directory):
  """Return fuzzed testcases from the data directories."""
  logs.info('Locating generated test cases.')

  # Get the list of testcase files.
  testcase_directories = [testcase_directory, data_directory]
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
      f'Generated {generated_testcase_count}/{testcase_count} testcases.')

  # Log the number of testcases generated.
  logs.info(generated_testcase_string)

  # If we are running the same command (again and again) on this bot,
  # we want to be careful of scenarios when the fuzzer starts failing
  # or has nothing to do, causing no testcases to be generated. This
  # will put lot of burden on appengine remote api.
  if (environment.get_value('COMMAND_OVERRIDE') and
      generated_testcase_count == 0):
    logs.info('No testcases generated. Sleeping for ~30 minutes.')
    time.sleep(random.uniform(1800, 2100))

  return (testcase_file_paths, generated_testcase_count,
          generated_testcase_string)


def set_test_timeout(timeout, multipler):
  """Set the test timeout based on a timeout value and multiplier."""
  test_timeout = int(timeout * multipler)
  environment.set_value('TEST_TIMEOUT', test_timeout)
  return test_timeout


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


def upload_job_run_stats(fuzzer_name: str, job_type: str, revision: int,
                         timestamp: float, new_crash_count: int,
                         known_crash_count: int, testcases_executed: int,
                         groups: List[Dict[str, Any]]):
  """Upload job run stats."""
  # New format.
  job_run = fuzzer_stats.JobRun(fuzzer_name, job_type, revision, timestamp,
                                testcases_executed, new_crash_count,
                                known_crash_count, groups)
  fuzzer_stats.upload_stats([job_run])

  _track_testcase_run_result(fuzzer_name, job_type, new_crash_count,
                             known_crash_count)


def store_fuzzer_run_results(testcase_file_paths, fuzzer, fuzzer_command,
                             fuzzer_output, fuzzer_return_code,
                             generated_testcase_count, expected_testcase_count,
                             generated_testcase_string, fuzz_task_input):
  """Store fuzzer run results in database."""
  # Upload fuzzer script output to bucket.
  if environment.is_engine_fuzzer_job():
    return None
  fuzzer_logs.upload_script_log(
      fuzzer_output, signed_upload_url=fuzz_task_input.script_log_upload_url)

  # Save the test results for the following cases.
  # 1. There is no result yet.
  # 2. There is no timestamp associated with the result.
  # 3. Last update timestamp is more than a day old.
  # 4. Return code is non-zero and was not found before.
  # 5. Testcases generated were fewer than expected in this run and zero return
  #    code did occur before and zero generated testcases didn't occur before.
  # pylint: disable=consider-using-in
  save_test_results = (
      not fuzzer.result or not fuzzer.result_timestamp or
      dates.time_has_expired(fuzzer.result_timestamp, days=1) or
      (fuzzer_return_code != 0 and fuzzer_return_code != fuzzer.return_code) or
      (generated_testcase_count != expected_testcase_count and
       fuzzer.return_code == 0 and ' 0/' not in fuzzer.result))
  # pylint: enable=consider-using-in
  if not save_test_results:
    return None

  logs.info('Started storing results from fuzzer run.')

  fuzzer_run_results_output = uworker_msg_pb2.StoreFuzzerRunResultsOutput()  # pylint: disable=no-member
  if testcase_file_paths:
    with open(testcase_file_paths[0], 'rb') as sample_testcase_file_handle:
      sample_testcase_file = sample_testcase_file_handle.read()
      storage.upload_signed_url(sample_testcase_file,
                                fuzz_task_input.sample_testcase_upload_url)

  # Store fuzzer console output.
  bot_name = environment.get_value('BOT_NAME')
  if fuzzer_return_code is not None:
    fuzzer_return_code_string = f'Return code ({fuzzer_return_code}).'
  else:
    fuzzer_return_code_string = 'Fuzzer timed out.'
  truncated_fuzzer_output = truncate_fuzzer_output(fuzzer_output,
                                                   data_types.ENTITY_SIZE_LIMIT)
  console_output = (f'{bot_name}: {fuzzer_return_code_string}\n{fuzzer_command}'
                    f'\n{truncated_fuzzer_output}')
  fuzzer_run_results_output.console_output = console_output
  fuzzer_run_results_output.generated_testcase_string = (
      generated_testcase_string)
  fuzzer_run_results_output.fuzzer_return_code = fuzzer_return_code
  return fuzzer_run_results_output


def preprocess_store_fuzzer_run_results(fuzz_task_input):
  """Does preprocessing for store_fuzzer_run_results. More specifically, gets
  URLs to upload a sample testcase and the logs."""
  if environment.is_engine_fuzzer_job():
    return
  fuzz_task_input.sample_testcase_upload_key = blobs.generate_new_blob_name()
  fuzz_task_input.sample_testcase_upload_url = blobs.get_signed_upload_url(
      fuzz_task_input.sample_testcase_upload_key)
  script_log_upload_key = blobs.generate_new_blob_name()
  fuzz_task_input.script_log_upload_url = blobs.get_signed_upload_url(
      script_log_upload_key)


def postprocess_store_fuzzer_run_results(output):
  """Postprocess store_fuzzer_run_results."""
  if environment.is_engine_fuzzer_job(output.uworker_input.job_type):
    return
  if not output.fuzz_task_output.fuzzer_run_results:
    return
  uworker_input = output.uworker_input
  fuzzer = data_types.Fuzzer.query(
      data_types.Fuzzer.name == output.uworker_input.fuzzer_name).get()
  if not fuzzer:
    logs.log_fatal_and_exit('Fuzzer does not exist, exiting.')

  fuzzer_run_results = output.fuzz_task_output.fuzzer_run_results
  if fuzzer.revision != output.fuzz_task_output.fuzzer_revision:
    logs.info('Fuzzer was recently updated, skipping results from old version.')
    return
  fuzzer.sample_testcase = (
      uworker_input.fuzz_task_input.sample_testcase_upload_key)
  fuzzer.console_output = fuzzer_run_results.console_output
  fuzzer.result = fuzzer_run_results.generated_testcase_string
  fuzzer.result_timestamp = datetime.datetime.utcnow()
  fuzzer.return_code = fuzzer_run_results.fuzzer_return_code
  fuzzer.put()

  logs.info('Finished storing results from fuzzer run.')


def postprocess_process_crashes(uworker_input: uworker_msg_pb2.Input,
                                uworker_output: uworker_msg_pb2.Output):
  """Postprocess process_crashes"""
  processed_groups = []
  crash_groups_for_stats = []
  new_crash_count = 0
  known_crash_count = 0

  fuzz_task_output = uworker_output.fuzz_task_output
  fuzz_target = None
  if uworker_input.fuzz_task_input.HasField('fuzz_target'):
    fuzz_target = uworker_io.entity_from_protobuf(
        uworker_input.fuzz_task_input.fuzz_target, data_types.FuzzTarget)

    fully_qualified_fuzzer_name = fuzz_target.fully_qualified_name()
  else:
    fully_qualified_fuzzer_name = uworker_input.fuzzer_name

  for group in fuzz_task_output.crash_groups:
    # Getting existing_testcase after finding the main crash is important.
    # Because finding the main crash can take a long time; it tests
    # reproducibility on every crash.
    #
    # Getting existing testcase at the last possible moment helps avoid race
    # condition among different machines. One machine might finish first and
    # prevent other machines from creating identical testcases.
    existing_testcase = data_handler.find_testcase(
        uworker_input.uworker_env.get('PROJECT_NAME'),
        group.crashes[0].crash_type,
        group.crashes[0].crash_state,
        group.crashes[0].security_flag,
        fuzz_target=fully_qualified_fuzzer_name)

    if _should_create_testcase(group, existing_testcase):
      newly_created_testcase = create_testcase(
          group=group,
          uworker_input=uworker_input,
          uworker_output=uworker_output,
          fully_qualified_fuzzer_name=fully_qualified_fuzzer_name)
    else:
      _update_testcase_variant_if_needed(group, existing_testcase,
                                         fuzz_task_output.crash_revision,
                                         uworker_input.job_type)
      newly_created_testcase = None

    write_crashes_to_big_query(group, newly_created_testcase, existing_testcase,
                               uworker_input, uworker_output,
                               fully_qualified_fuzzer_name)

    if not existing_testcase:
      new_crash_count += 1
      known_crash_count += len(group.crashes) - 1
    else:
      known_crash_count += len(group.crashes)

    processed_groups.append(group)
    crash_groups_for_stats = {
        'is_new': not bool(existing_testcase),
        'count': len(group.crashes),
        'crash_type': group.main_crash.crash_type,
        'crash_state': group.main_crash.crash_state,
        'security_flag': group.main_crash.security_flag,
    }

    # Artificial delay to throttle appengine updates.
    time.sleep(1)

  # TODO(metzman): Replace fuzz_task_output.fully_qualified_fuzzer_name` with
  # `fuzz_task_input.fuzz_target` instead.
  upload_job_run_stats(fuzz_task_output.fully_qualified_fuzzer_name,
                       uworker_input.job_type, fuzz_task_output.crash_revision,
                       fuzz_task_output.job_run_timestamp, new_crash_count,
                       known_crash_count, fuzz_task_output.testcases_executed,
                       crash_groups_for_stats)

  logs.info(f'Finished processing crashes.\nNew crashes: {new_crash_count}, '
            f'known crashes: {known_crash_count}, '
            f'processed groups: {processed_groups}')

  return new_crash_count, known_crash_count, processed_groups


def get_regression(one_time_crasher_flag):
  """Get the right regression value."""
  if one_time_crasher_flag or build_manager.is_custom_binary():
    return 'NA'
  return ''


def get_fixed_or_minimized_key(one_time_crasher_flag):
  """Get the right fixed value."""
  return 'NA' if one_time_crasher_flag else ''


def get_testcase_timeout_multiplier(timeout_multiplier, crash, test_timeout):
  """Get testcase timeout multiplier."""
  testcase_timeout_multiplier = timeout_multiplier
  if timeout_multiplier > 1 and (crash.crash_time + THREAD_WAIT_TIMEOUT) < (
      test_timeout / timeout_multiplier):
    testcase_timeout_multiplier = 1.0

  return testcase_timeout_multiplier


def create_testcase(group: uworker_msg_pb2.FuzzTaskCrashGroup,
                    uworker_input: uworker_msg_pb2.Input,
                    uworker_output: uworker_msg_pb2.Output,
                    fully_qualified_fuzzer_name: str):
  """Create a testcase based on crash."""
  crash = group.main_crash
  comment = (f'Fuzzer {fully_qualified_fuzzer_name} generated testcase crashed '
             f'in {crash.crash_time} seconds '
             f'(r{uworker_output.fuzz_task_output.crash_revision})')
  testcase_id = data_handler.store_testcase(
      crash=crash,
      fuzzed_keys=crash.fuzzed_key or None,
      minimized_keys=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      regression=get_regression(group.one_time_crasher_flag),
      fixed=get_fixed_or_minimized_key(group.one_time_crasher_flag),
      one_time_crasher_flag=group.one_time_crasher_flag,
      crash_revision=int(uworker_output.fuzz_task_output.crash_revision),
      comment=comment,
      absolute_path=crash.absolute_path,
      fuzzer_name=uworker_input.fuzzer_name,
      fully_qualified_fuzzer_name=fully_qualified_fuzzer_name,
      job_type=uworker_input.job_type,
      archived=crash.archived,
      archive_filename=crash.archive_filename,
      http_flag=crash.http_flag,
      gestures=list(crash.gestures),
      redzone=group.context.redzone,
      disable_ubsan=group.context.disable_ubsan,
      window_argument=group.context.window_argument,
      timeout_multiplier=get_testcase_timeout_multiplier(
          group.context.timeout_multiplier, crash, group.context.test_timeout),
      minimized_arguments=crash.arguments,
      # TODO(https://github.com/google/clusterfuzz/issues/4175): Before enabling
      # oss-fuzz-on-demand change this.
      trusted=True)
  testcase = data_handler.get_testcase_by_id(testcase_id)

  if group.context.fuzzer_metadata:
    for key, value in group.context.fuzzer_metadata.items():
      testcase.set_metadata(key, value, update_testcase=False)

    testcase.put()

  if crash.fuzzing_strategies:
    testcase.set_metadata(
        'fuzzing_strategies',
        list(crash.fuzzing_strategies),
        update_testcase=True)

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
  return testcase


def filter_crashes(crashes: List[Crash]) -> List[Crash]:
  """Filter crashes based on is_valid()."""
  filtered = []

  for crash in crashes:
    if not crash.is_valid():
      logs.info(
          (f'Ignore crash (reason={crash.get_error()}, '
           f'type={crash.crash_type}, state={crash.crash_state})'),
          stacktrace=crash.crash_stacktrace)
      continue

    filtered.append(crash)

  return filtered


def get_engine(context):
  """Get the fuzzing engine."""
  if context.fuzz_target:
    return context.fuzz_target.engine

  return ''


def write_crashes_to_big_query(group, newly_created_testcase, existing_testcase,
                               uworker_input: uworker_msg_pb2.Input,
                               output: uworker_msg_pb2.Output,
                               fully_qualified_fuzzer_name):
  """Write a group of crashes to BigQuery."""

  # Many of ChromeOS fuzz targets run on Linux bots, so we incorrectly set the
  # linux platform for this. We cannot change platform_id in testcase as
  # otherwise linux bots can no longer lease those testcase. So, just change
  # this value in crash stats. This helps cleanup task put correct OS label.
  if environment.is_chromeos_job(uworker_input.job_type):
    actual_platform = 'chrome'
  else:
    actual_platform = output.platform_id

  # Write to a specific partition.
  created_at = int(time.time())
  timestamp = datetime.datetime.utcfromtimestamp(created_at).strftime('%Y%m%d')
  table_id = f'crashes${timestamp}'

  client = big_query.Client(dataset_id='main', table_id=table_id)

  insert_id_prefix = ':'.join(
      [group.crashes[0].key, output.bot_name,
       str(created_at)])

  rows = []
  for index, crash in enumerate(group.crashes):
    created_testcase_id = None
    if crash == group.main_crash and newly_created_testcase:
      created_testcase_id = str(newly_created_testcase.key.id())

    rows.append(
        big_query.Insert(
            row={
                'crash_type':
                    crash.crash_type,
                'crash_state':
                    crash.crash_state,
                'created_at':
                    created_at,
                'platform':
                    actual_platform,
                'crash_time_in_ms':
                    int(crash.crash_time * 1000),
                'parent_fuzzer_name':
                    uworker_input.fuzzer_name,
                'fuzzer_name':
                    fully_qualified_fuzzer_name,
                'job_type':
                    uworker_input.job_type,
                'security_flag':
                    crash.security_flag,
                'project':
                    uworker_input.uworker_env.get('PROJECT_NAME', ''),
                'reproducible_flag':
                    not group.one_time_crasher_flag,
                'revision':
                    str(output.fuzz_task_output.crash_revision),
                'new_flag':
                    not existing_testcase and crash == group.main_crash,
                'testcase_id':
                    created_testcase_id
            },
            insert_id=f'{insert_id_prefix}:{index}'))

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
      logs.error(
          ('Ignoring error writing the crash '
           f'({group.crashes[error["index"]].crash_type}) to BigQuery.'),
          exception=Exception(error))
  except Exception:
    logs.error('Ignoring error writing a group of crashes to BigQuery')
    monitoring_metrics.BIG_QUERY_WRITE_COUNT.increment_by(
        row_count, {'success': False})


def _update_testcase_variant_if_needed(group, existing_testcase, crash_revision,
                                       job_type):
  """Update testcase variant if this is not already covered by existing testcase
  variant on this job."""

  variant = data_handler.get_or_create_testcase_variant(
      existing_testcase.key.id(), job_type)
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
  variant.revision = int(crash_revision)
  variant.crash_type = group.main_crash.crash_type
  variant.crash_state = group.main_crash.crash_state
  variant.security_flag = group.main_crash.security_flag
  variant.is_similar = True
  variant.put()


def process_crashes(crashes: List[Crash], context: Context,
                    upload_urls) -> List[uworker_msg_pb2.FuzzTaskCrashGroup]:
  """Process a list of crashes."""

  def key_fn(crash):
    return crash.key

  crash_groups = []

  # Filter invalid crashes.
  crashes = filter_crashes(crashes)
  group_of_crashes = itertools.groupby(sorted(crashes, key=key_fn), key_fn)

  upload_urls = UploadUrlCollection(upload_urls)
  for _, grouped_crashes in group_of_crashes:
    try:
      group = CrashGroup(list(grouped_crashes), context, upload_urls)
    except NoMoreUploadUrlsError:
      # Ignore the remaining crashes.
      logs.error('Ran out of crash upload URLs.')
      break

    # Archiving testcase to blobstore might fail for all crashes within this
    # group.
    if not group.main_crash:
      logs.info('Unable to store testcase in blobstore: '
                f'{group.crashes[0].crash_state}')
      continue

    if 'issue_metadata' in context.fuzzer_metadata:
      context.fuzzer_metadata['issue_metadata'] = json.dumps(
          context.fuzzer_metadata['issue_metadata'])

    group_proto = uworker_msg_pb2.FuzzTaskCrashGroup(
        context=uworker_msg_pb2.FuzzContext(
            redzone=context.redzone,
            disable_ubsan=context.disable_ubsan,
            window_argument=context.window_argument,
            timeout_multiplier=context.timeout_multiplier,
            test_timeout=int(context.test_timeout),
            fuzzer_metadata=context.fuzzer_metadata,
        ),
        main_crash=group.main_crash.to_proto(),
        crashes=[c.to_proto() for c in group.crashes],
        one_time_crasher_flag=group.one_time_crasher_flag,
    )
    crash_groups.append(group_proto)

    logs.info(f'Process the crash group (file={group.main_crash.filename}, '
              f'fuzzed_key={group.main_crash.fuzzed_key}, '
              f'return code={group.main_crash.return_code}, '
              f'crash time={group.main_crash.crash_time}, '
              f'crash type={group.main_crash.crash_type}, '
              f'crash state={group.main_crash.crash_state}, '
              f'security flag={group.main_crash.security_flag}, '
              f'crash stacktrace={group.main_crash.crash_stacktrace})')
  return crash_groups


def _get_issue_metadata_from_environment(variable_name):
  """Get issue metadata from environment."""
  values = str(environment.get_value_string(variable_name, '')).split(',')
  # Allow a variation with a '_1' to specified. This is needed in cases where
  # this is specified in both the job and the bot environment.
  values.extend(
      str(environment.get_value_string(variable_name + '_1', '')).split(','))
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
    from clusterfuzz._internal.bot.untrusted_runner import tasks_host
    logs.info('Running remote engine fuzz.')
    result = tasks_host.engine_fuzz(engine_impl, target_name,
                                    sync_corpus_directory, testcase_directory)
    logs.info('Done remote engine fuzz.')
    return result

  logs.info('Worker engine fuzz.')
  build_dir = environment.get_value('BUILD_DIR')
  target_path = engine_common.find_fuzzer_path(build_dir, target_name)
  if target_path is None:
    raise FuzzTargetNotFoundError(f'{target_path} is not found.')
  options = engine_impl.prepare(sync_corpus_directory, target_path, build_dir)

  fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
  additional_processing_time = engine_impl.fuzz_additional_processing_timeout(
      options)
  adjusted_fuzz_test_timeout = fuzz_test_timeout - additional_processing_time
  if adjusted_fuzz_test_timeout <= 0:
    raise FuzzTaskError(f'Invalid engine timeout: '
                        f'{fuzz_test_timeout} - {additional_processing_time}')

  result = engine_impl.fuzz(target_path, options, testcase_directory,
                            adjusted_fuzz_test_timeout)

  logs.info('Used strategies.', strategies=options.strategies)
  for strategy, value in options.strategies.items():
    result.stats['strategy_' + strategy] = value

  # Format logs with header and strategy information.
  log_header = engine_common.get_log_header(result.command,
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


class FuzzingSession:
  """Class for orchestrating fuzzing sessions."""

  def __init__(self, uworker_input, test_timeout):
    self.fuzzer_name = uworker_input.fuzzer_name
    self.job_type = uworker_input.job_type
    self.uworker_input = uworker_input

    # Set up randomly selected fuzzing parameters.
    self.redzone = fuzz_task_knobs.pick_redzone()
    self.disable_ubsan = fuzz_task_knobs.pick_ubsan_disabled(self.job_type)
    self.timeout_multiplier = fuzz_task_knobs.pick_timeout_multiplier()
    self.window_argument = fuzz_task_knobs.pick_window_argument()
    self.test_timeout = set_test_timeout(test_timeout, self.timeout_multiplier)

    # Set up during run().
    self.fuzzer = None
    self.testcase_directory = None
    self.data_directory = None

    # Fuzzing engine specific state.
    if uworker_input.fuzz_task_input.HasField('fuzz_target'):
      self.fuzz_target = uworker_io.entity_from_protobuf(
          uworker_input.fuzz_task_input.fuzz_target, data_types.FuzzTarget)
    else:
      # We take this branch when no fuzz target is picked. Such as on a new
      # build.
      self.fuzz_target = None

    self.gcs_corpus = None
    self.fuzz_task_output = uworker_msg_pb2.FuzzTaskOutput()  # pylint: disable=no-member

  @property
  def fully_qualified_fuzzer_name(self):
    """Get the fully qualified fuzzer name."""
    if self.fuzz_target:
      return self.fuzz_target.fully_qualified_name()

    return self.fuzzer_name

  def sync_corpus(self, sync_corpus_directory):
    """Sync corpus from GCS."""
    # Corpus should always be set at this point.
    self.gcs_corpus = GcsCorpus(self.fuzzer_name,
                                self.fuzz_target.project_qualified_name(),
                                sync_corpus_directory, self.data_directory,
                                self.uworker_input.fuzz_task_input.corpus)
    if not self.gcs_corpus.sync_from_gcs():
      raise FuzzTaskError(
          'Failed to sync corpus for fuzzer %s (job %s).' %
          (self.fuzz_target.project_qualified_name(), self.job_type))

  def _file_size(self, file_path):
    """Return file size depending on whether file is local or remote (untrusted
    worker)."""
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      stat_result = file_host.stat(file_path)
      return stat_result.st_size if stat_result else None

    return os.path.getsize(file_path)

  def sync_new_corpus_files(self):
    """Sync new files from corpus to GCS."""
    new_files = self.gcs_corpus.get_new_files()
    new_files_count = len(new_files)
    logs.info('%d new corpus files generated by fuzzer %s (job %s).' %
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
      logs.info(('Uploading only %d out of %d new corpus files '
                 'generated by fuzzer %s (job %s).') %
                (filtered_new_files_count, new_files_count,
                 self.fuzz_target.project_qualified_name(), self.job_type))

    self.gcs_corpus.upload_files(filtered_new_files)

  def generate_blackbox_testcases(
      self, fuzzer, job_type, fuzzer_directory,
      testcase_count) -> GenerateBlackboxTestcasesResult:
    """Run the blackbox fuzzer and generate testcases."""
    # Helper variables.
    fuzzer_name = fuzzer.name

    error_return_value = GenerateBlackboxTestcasesResult(False, None, None)

    # Clear existing testcases (only if past task failed).
    testcase_directories = [self.testcase_directory]
    testcase_manager.remove_testcases_from_directories(testcase_directories)

    # Set an environment variable for fuzzer name.
    # TODO(ochang): Investigate removing this. Only users appear to be
    # fuzzer_logs, which can be removed.
    environment.set_value('FUZZER_NAME', fuzzer_name)

    # Set minimum redzone size, do not detect leaks and zero out the
    # quarantine size before running the fuzzer.
    environment.reset_current_memory_tool_options(
        redzone_size=16, leaks=False, quarantine_size_mb=0)

    # Make sure we have a file to execute for the fuzzer.
    if not fuzzer.executable_path:
      logs.error(f'Fuzzer {fuzzer_name} does not have an executable path.')

      return error_return_value

    # Get the fuzzer executable and chdir to its base directory. This helps to
    # prevent referencing every file using __file__.
    fuzzer_executable = os.path.join(fuzzer_directory, fuzzer.executable_path)
    fuzzer_executable_directory = os.path.dirname(fuzzer_executable)

    # Make sure the fuzzer executable exists on disk.
    if not os.path.exists(fuzzer_executable):
      logs.error(
          'File %s does not exist. Cannot generate testcases for fuzzer %s.' %
          (fuzzer_executable, fuzzer_name))
      return error_return_value

    # Build the fuzzer command execution string.
    command = shell.get_execute_command(fuzzer_executable)

    # NodeJS and shell script expect space separator for arguments.
    if command.startswith('node ') or command.startswith('sh '):
      argument_separator = ' '
    else:
      argument_separator = '='

    command_format = '%s --input_dir%s%s --output_dir%s%s --no_of_files%s%d'
    fuzzer_command = str(
        command_format % (command, argument_separator, self.data_directory,
                          argument_separator, self.testcase_directory,
                          argument_separator, testcase_count))
    fuzzer_timeout = environment.get_value('FUZZER_TIMEOUT')

    # Run the fuzzer.
    logs.info(f'Running fuzzer - {fuzzer_command}.')
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
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      file_host.push_testcases_to_worker()

    fuzzer_metadata = get_fuzzer_metadata_from_output(fuzzer_output)
    _add_issue_metadata_from_environment(fuzzer_metadata)

    # Filter fuzzer output, set to default value if empty.
    if fuzzer_output:
      fuzzer_output = utils.decode_to_unicode(fuzzer_output)
    else:
      fuzzer_output = 'No output!'

    # Get the list of generated testcases.
    testcase_file_paths, generated_testcase_count, generated_testcase_string = (
        get_testcases(testcase_count, self.testcase_directory,
                      self.data_directory))

    # Check for process return code to identify abnormal termination.
    if fuzzer_return_code:
      if float(
          generated_testcase_count) / testcase_count < FUZZER_FAILURE_THRESHOLD:
        logs.error(
            ('Fuzzer failed to generate testcases '
             '(fuzzer={name}, return_code={return_code}).').format(
                 name=fuzzer_name, return_code=fuzzer_return_code),
            output=fuzzer_output)
      else:
        logs.warning(
            ('Fuzzer generated less than expected testcases '
             '(fuzzer={name}, return_code={return_code}).').format(
                 name=fuzzer_name, return_code=fuzzer_return_code),
            output=fuzzer_output)

    # Store fuzzer run results.
    fuzzer_run_results = store_fuzzer_run_results(
        testcase_file_paths, fuzzer, fuzzer_command, fuzzer_output,
        fuzzer_return_code, generated_testcase_count, testcase_count,
        generated_testcase_string, self.uworker_input.fuzz_task_input)
    if fuzzer_run_results:
      self.fuzz_task_output.fuzzer_run_results.CopyFrom(fuzzer_run_results)

      _track_fuzzer_run_result(fuzzer_name, job_type, generated_testcase_count,
                               testcase_count, fuzzer_return_code)

    # Make sure that there are testcases generated. If not, set the error flag.
    success = bool(testcase_file_paths)
    return GenerateBlackboxTestcasesResult(success, testcase_file_paths,
                                           fuzzer_metadata)

  def do_engine_fuzzing(self, engine_impl):
    """Run fuzzing engine."""
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

    self.fuzz_task_output.app_revision = environment.get_value('APP_REVISION')
    # Do the actual fuzzing.
    for fuzzing_round in range(_get_max_testcases()):
      logs.info(f'Fuzzing round {fuzzing_round}.')
      try:
        with _TrackFuzzTime(self.fully_qualified_fuzzer_name,
                            self.job_type) as tracker:
          result, cur_fuzzer_metadata, fuzzing_strategies = run_engine_fuzzer(
              engine_impl, self.fuzz_target.binary, sync_corpus_directory,
              self.testcase_directory)
          # Timeouts are only accounted for in libfuzzer, this can be None
          tracker.timeout = bool(result.timed_out)
      except FuzzTargetNotFoundError:
        # Ocassionally fuzz targets are deleted. This is pretty rare. Since
        # ClusterFuzz did nothing wrong, don't bubble up an exception, consider
        # it as we fuzzed and nothing happened so that new targets can be
        # recorded and hopefully fuzzed instead. The old targets will eventually
        # be garbage collected. Log this as an error to keep an eye on it.
        logs.error(f'{self.fuzz_target.binary} is not in the build.')
        return [], {}

      fuzzer_metadata.update(cur_fuzzer_metadata)

      # Prepare stats.
      testcase_run = engine_common.get_testcase_run(result.stats,
                                                    result.command)

      # Upload logs, testcases (if there are crashes), and stats.
      # Use a consistent log time to allow correlating between logs, uploaded
      # testcases, and stats.
      log_time = datetime.datetime.utcfromtimestamp(
          float(testcase_run.timestamp))
      crash_result_obj = crash_result.CrashResult(
          return_code, result.time_executed, result.logs)
      output = crash_result_obj.get_stacktrace()
      # TODO(metzman): Consider uploading this with a signed URL.
      if result.crashes:
        # We only upload the first, because they will clobber each other if we
        # upload more.
        result_crash = result.crashes[0].input_path
      else:
        result_crash = None

      engine_output = _to_engine_output(output, result_crash, return_code,
                                        log_time)
      self.fuzz_task_output.engine_outputs.append(engine_output)

      add_additional_testcase_run_data(testcase_run,
                                       self.fuzz_target.fully_qualified_name(),
                                       self.job_type, revision)
      self.fuzz_task_output.testcase_run_jsons.append(testcase_run.to_json())
      if result.crashes:
        crashes.extend([
            Crash.from_engine_crash(crash, fuzzing_strategies)
            for crash in result.crashes
            if crash
        ])

    logs.info('All fuzzing rounds complete.')
    self.sync_new_corpus_files()

    return crashes, fuzzer_metadata

  def _emit_testcase_generation_time_metric(self, start_time, testcase_count,
                                            fuzzer, job):
    testcase_generation_finish = time.time()
    elapsed_testcase_generation_time = testcase_generation_finish
    elapsed_testcase_generation_time -= start_time
    # Avoid division by zero.
    if testcase_count:
      average_time_per_testcase = elapsed_testcase_generation_time
      average_time_per_testcase = average_time_per_testcase / testcase_count
      monitoring_metrics.TESTCASE_GENERATION_AVERAGE_TIME.add(
          average_time_per_testcase,
          labels={
              'job': job,
              'fuzzer': fuzzer,
              'platform': environment.platform(),
          })

  def do_blackbox_fuzzing(self, fuzzer, fuzzer_directory, job_type):
    """Run blackbox fuzzing. Currently also used for engine fuzzing."""
    # Set the thread timeout values.
    # TODO(ochang): Remove this hack once engine fuzzing refactor is complete.
    fuzz_test_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')
    if fuzz_test_timeout:
      test_timeout = set_test_timeout(fuzz_test_timeout,
                                      self.timeout_multiplier)
    else:
      test_timeout = self.test_timeout

    logs.info(f'test_timeout is : {test_timeout}')
    thread_timeout = test_timeout

    # Determine number of testcases to process.
    testcase_count = _get_max_testcases()

    # For timeout multipler greater than 1, we need to decrease testcase count
    # to prevent exceeding task lease time.
    if self.timeout_multiplier > 1:
      testcase_count /= self.timeout_multiplier

    # Run the fuzzer to generate testcases. If error occurred while trying
    # to run the fuzzer, bail out.
    testcase_generation_start = time.time()
    generate_result = self.generate_blackbox_testcases(
        fuzzer, job_type, fuzzer_directory, testcase_count)
    if not generate_result.success:
      return None, None, None, None

    self._emit_testcase_generation_time_metric(
        testcase_generation_start, testcase_count, fuzzer.name, job_type)

    environment.set_value('FUZZER_NAME', self.fully_qualified_fuzzer_name)

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

    # Reset memory tool options.
    environment.reset_current_memory_tool_options(
        redzone_size=self.redzone, disable_ubsan=self.disable_ubsan)

    # Create a dict to store metadata specific to each testcase.
    testcases_metadata = {}
    testcase_file_paths = generate_result.testcase_file_paths

    for testcase_file_path in testcase_file_paths:
      testcases_metadata[testcase_file_path] = {}

      # Pick up a gesture to run on the testcase.
      testcases_metadata[testcase_file_path]['gestures'] = (
          fuzz_task_knobs.pick_gestures(test_timeout))

    # Prepare selecting trials in main loop below.
    trial_selector = trials.Trials()

    # TODO(machenbach): Move this back to the main loop and make it test-case
    # specific in a way that get's persistet on crashes.
    # For some binaries, we specify trials, which are sets of flags that we
    # only apply some of the time. Adjust APP_ARGS for them if needed.
    trial_selector.setup_additional_args_for_app()

    logs.info('Starting to process testcases.')
    logs.info(f'Redzone is {self.redzone} bytes.')
    logs.info(f'Timeout multiplier is {self.timeout_multiplier}.')
    logs.info('App launch command is '
              f'{testcase_manager.get_command_line_for_application()}.')

    # Start processing the testcases.
    while test_number < len(testcase_file_paths):
      thread_index = 0
      threads = []

      temp_queue = process_handler.get_queue()
      if not temp_queue:
        process_handler.terminate_stale_application_instances()
        logs.error('Unable to create temporary crash queue.')
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
          logs.error('Unable to start new thread.')
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
      logs.info(f'Upto {test_number}')
      if thread_error_occurred:
        break

    # Pull testcase directory to host. The testcase file contents could have
    # been changed (by e.g. libFuzzer) and stats files could have been written.
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      file_host.pull_testcases_from_worker()

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
    return (generate_result.fuzzer_metadata, testcase_file_paths,
            testcases_metadata, crashes)

  def run(self):
    """Run the fuzzing session."""
    start_time = time.time()
    # Update LSAN local blacklist with global blacklist.
    global_blacklisted_functions = (
        self.uworker_input.fuzz_task_input.global_blacklisted_functions)
    if global_blacklisted_functions:
      leak_blacklist.copy_global_to_local_blacklist(
          global_blacklisted_functions)

    # Ensure that that the fuzzer still exists.
    logs.info('Setting up fuzzer and data bundles.')
    self.fuzzer = setup.update_fuzzer_and_data_bundles(
        self.uworker_input.setup_input)
    if not self.fuzzer:
      logs.error(f'Unable to setup fuzzer {self.fuzzer_name}.')

      # Artificial sleep to slow down continuous failed fuzzer runs if the bot
      # is using command override for task execution.
      failure_wait_interval = environment.get_value('FAIL_WAIT')
      time.sleep(failure_wait_interval)
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.FUZZ_NO_FUZZER)  # pylint: disable=no-member

    # Update the session's test_timeout to use the fuzzer's timeout (if any).
    # When the fuzzer has a specified timeout, `update_fuzzer_and_data_bundles`
    # updates the `TEST_TIMEOUT` environment variable. This makes sure that
    # the session's timeout reflects the change as well.
    if self.fuzzer.timeout:
      self.test_timeout = set_test_timeout(self.fuzzer.timeout,
                                           self.timeout_multiplier)

    self.testcase_directory = environment.get_value('FUZZ_INPUTS')

    fuzz_target = self.fuzz_target.binary if self.fuzz_target else None
    build_setup_result = build_manager.setup_build(
        environment.get_value('APP_REVISION'), fuzz_target=fuzz_target)

    engine_impl = engine.get(self.fuzzer.name)
    if engine_impl and build_setup_result:
      # If we did not pick a fuzz target to fuzz with the engine, then return
      # early to save the fuzz targets that are in the build for the next job to
      # pick.
      self.fuzz_task_output.fuzz_targets.extend(build_setup_result.fuzz_targets)
      if not self.fuzz_task_output.fuzz_targets:
        logs.error('No fuzz targets.')
      if not self.fuzz_target:
        return uworker_msg_pb2.Output(  # pylint: disable=no-member
            fuzz_task_output=self.fuzz_task_output,
            error_type=uworker_msg_pb2.ErrorType.FUZZ_NO_FUZZ_TARGET_SELECTED)  # pylint: disable=no-member

    # Check if we have an application path. If not, our build failed
    # to setup correctly.
    if not build_setup_result:
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.FUZZ_BUILD_SETUP_FAILURE)  # pylint: disable=no-member

    # Check if we have a bad build, i.e. one that crashes on startup.
    # If yes, bail out.
    logs.info('Checking for bad build.')
    crash_revision = environment.get_value('APP_REVISION')

    build_data = testcase_manager.check_for_bad_build(self.job_type,
                                                      crash_revision)
    self.fuzz_task_output.build_data.CopyFrom(build_data)
    _track_build_run_result(self.job_type, crash_revision,
                            build_data.is_bad_build)

    if build_data.is_bad_build:
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.UNHANDLED)  # pylint: disable=no-member

    # Data bundle directories can also have testcases which are kept in-place
    # because of dependencies.
    self.data_directory = setup.get_data_bundle_directory(
        self.fuzzer, self.uworker_input.setup_input)
    if not self.data_directory:
      logs.error(f'Unable to setup data bundle {self.fuzzer.data_bundle_name}.')
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.FUZZ_DATA_BUNDLE_SETUP_FAILURE)

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
      return uworker_msg_pb2.Output(  # pylint: disable=no-member
          error_type=uworker_msg_pb2.ErrorType.UNHANDLED)  # pylint: disable=no-member

    logs.info('Finished processing test cases.')

    # For Android, bring back device to a good state before analyzing crashes.
    if environment.is_android() and crashes:
      # Remove this variable so that application is fully shutdown before every
      # re-run of testcase. This is critical for reproducibility.
      environment.remove_key('CHILD_PROCESS_TERMINATION_PATTERN')

      # TODO(unassigned): Need to find a way to do this efficiently before every
      # testcase is analyzed.
      android.device.initialize_device()

    logs.info(f'Raw crash count: {len(crashes)}')

    # Process and save crashes to datastore.
    bot_name = environment.get_value('BOT_NAME')
    project_name = environment.get_value('PROJECT_NAME')
    crash_groups = process_crashes(
        crashes=crashes,
        context=Context(
            project_name=project_name,
            bot_name=bot_name,
            job_type=self.job_type,
            fuzz_target=self.fuzz_target,
            redzone=self.redzone,
            disable_ubsan=self.disable_ubsan,
            platform_id=environment.get_platform_id(),
            crash_revision=crash_revision,
            fuzzer_name=self.fuzzer_name,
            window_argument=self.window_argument,
            fuzzer_metadata=fuzzer_metadata,
            testcases_metadata=testcases_metadata,
            timeout_multiplier=self.timeout_multiplier,
            test_timeout=self.test_timeout,
            data_directory=self.data_directory),
        upload_urls=list(self.uworker_input.fuzz_task_input.crash_upload_urls))

    # Delete the fuzzed testcases. This was once explicitly needed since some
    # testcases resided on NFS and would otherwise be left forever. Now it's
    # unclear if needed but it is kept because it is not harmful.
    for testcase_file_path in testcase_file_paths:
      shell.remove_file(testcase_file_path)

    testcases_executed = len(testcase_file_paths)

    # Explicit cleanup for large vars.
    del testcase_file_paths
    del testcases_metadata
    utils.python_gc()

    # TODO(metzman): Remove this since the tworkers should know what this is
    # based on the input.
    self.fuzz_task_output.fully_qualified_fuzzer_name = (
        self.fully_qualified_fuzzer_name)
    self.fuzz_task_output.crash_revision = str(crash_revision)
    self.fuzz_task_output.job_run_timestamp = time.time()
    self.fuzz_task_output.testcases_executed = testcases_executed
    self.fuzz_task_output.fuzzer_revision = self.fuzzer.revision
    self.fuzz_task_output.crash_groups.extend(crash_groups)

    fuzzing_session_duration = time.time() - start_time
    monitoring_metrics.FUZZING_SESSION_DURATION.add(
        fuzzing_session_duration, {
            'fuzzer': self.fuzzer_name,
            'job': self.job_type,
            'platform': environment.platform()
        })

    return uworker_msg_pb2.Output(fuzz_task_output=self.fuzz_task_output)  # pylint: disable=no-member

  def postprocess(self, uworker_output):
    """Handles postprocessing."""
    # TODO(metzman): Finish this.
    fuzz_task_output = uworker_output.fuzz_task_output
    postprocess_store_fuzzer_run_results(uworker_output)
    logs.info('postprocess: fuzz_task_output.fully_qualified_fuzzer_name '
              f'{fuzz_task_output.fully_qualified_fuzzer_name}')
    uworker_input = uworker_output.uworker_input
    postprocess_process_crashes(uworker_input, uworker_output)
    if not environment.is_engine_fuzzer_job():
      return

    targets_count = ndb.Key(data_types.FuzzTargetsCount, self.job_type).get()
    if not fuzz_task_output.fuzz_targets:
      new_targets_count = 0
    else:
      new_targets_count = len(fuzz_task_output.fuzz_targets)
    if (not targets_count or targets_count.count != new_targets_count):
      data_types.FuzzTargetsCount(
          id=uworker_input.job_type, count=new_targets_count).put()

    _upload_testcase_run_jsons(
        uworker_output.fuzz_task_output.testcase_run_jsons)
    testcase_manager.update_build_metadata(
        uworker_input.job_type, uworker_output.fuzz_task_output.build_data)


def _upload_testcase_run_jsons(testcase_run_jsons):
  for testcase_run in testcase_run_jsons:
    testcase_run = fuzzer_stats.BaseRun.from_json(testcase_run)
    if not testcase_run:
      logs.error('Failed to create testcase_run')
      continue
    upload_testcase_run_stats(testcase_run)
  # TODO(metzman): Find out if this can be a single upload.


def handle_fuzz_build_setup_failure(output):
  _track_fuzzer_run_result(output.uworker_input.fuzzer_name,
                           output.uworker_input.job_type, 0, 0,
                           FuzzErrorCode.BUILD_SETUP_FAILED)


def handle_fuzz_data_bundle_setup_failure(output):
  _track_fuzzer_run_result(output.uworker_input.fuzzer_name,
                           output.uworker_input.job_type, 0, 0,
                           FuzzErrorCode.DATA_BUNDLE_SETUP_FAILED)


def handle_fuzz_no_fuzzer(output):
  _track_fuzzer_run_result(output.uworker_input.fuzzer_name,
                           output.uworker_input.job_type, 0, 0,
                           FuzzErrorCode.FUZZER_SETUP_FAILED)


def handle_fuzz_bad_build(uworker_output):
  testcase_manager.update_build_metadata(
      uworker_output.uworker_input.job_type,
      uworker_output.fuzz_task_output.build_data)


def utask_main(uworker_input):
  """Runs the given fuzzer for one round."""
  # Sets fuzzing logs context before running the fuzzer.
  if uworker_input.fuzz_task_input.HasField('fuzz_target'):
    fuzz_target = uworker_io.entity_from_protobuf(
        uworker_input.fuzz_task_input.fuzz_target, data_types.FuzzTarget)
  else:
    fuzz_target = None
  with logs.fuzzer_log_context(uworker_input.fuzzer_name,
                               uworker_input.job_type, fuzz_target):
    session = _make_session(uworker_input)
    return session.run()


def handle_fuzz_no_fuzz_target_selected(output):
  save_fuzz_targets(output)
  # Try again now that there are some fuzz targets.
  utask_preprocess(output.uworker_input.fuzzer_name,
                   output.uworker_input.job_type,
                   output.uworker_input.uworker_env)


def _make_session(uworker_input):
  test_timeout = environment.get_value('TEST_TIMEOUT')
  return FuzzingSession(
      uworker_input,
      test_timeout,
  )


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.FUZZ_BUILD_SETUP_FAILURE:  # pylint: disable=no-member
        handle_fuzz_build_setup_failure,
    uworker_msg_pb2.ErrorType.FUZZ_DATA_BUNDLE_SETUP_FAILURE:  # pylint: disable=no-member
        handle_fuzz_data_bundle_setup_failure,
    uworker_msg_pb2.ErrorType.FUZZ_NO_FUZZER:  # pylint: disable=no-member
        handle_fuzz_no_fuzzer,
    uworker_msg_pb2.ErrorType.FUZZ_NO_FUZZ_TARGET_SELECTED:  # pylint: disable=no-member
        handle_fuzz_no_fuzz_target_selected,
    uworker_msg_pb2.ErrorType.FUZZ_BAD_BUILD:  # pylint: disable=no-member
        handle_fuzz_bad_build,
}).compose_with(uworker_handle_errors.UNHANDLED_ERROR_HANDLER)


def _pick_fuzz_target():
  """Picks a random fuzz target from job_type for use in fuzzing."""
  if not environment.is_engine_fuzzer_job():
    logs.info('Not engine fuzzer. Not picking fuzz target.')
    return None

  logs.info('Picking fuzz target.')
  target_weights = fuzzer_selection.get_fuzz_target_weights()
  return build_manager.pick_random_fuzz_target(target_weights)


def _get_or_create_fuzz_target(engine_name, fuzz_target_binary, job_type):
  """Gets or creates a FuzzTarget db entity."""
  project = data_handler.get_project_name(job_type)
  qualified_name = data_types.fuzz_target_fully_qualified_name(
      engine_name, project, fuzz_target_binary)
  key = ndb.Key(data_types.FuzzTarget, qualified_name)
  fuzz_target = key.get()
  if fuzz_target:
    return fuzz_target
  fuzz_target = data_types.FuzzTarget(
      engine=engine_name, binary=fuzz_target_binary, project=project)
  fuzz_target.put()
  return fuzz_target


def _preprocess_get_fuzz_target(fuzzer_name, job_type):
  fuzz_target_name = _pick_fuzz_target()
  if fuzz_target_name:
    return _get_or_create_fuzz_target(fuzzer_name, fuzz_target_name, job_type)
  return None


def _utask_preprocess(fuzzer_name, job_type, uworker_env):
  """Preprocess untrusted task."""
  setup_input = setup.preprocess_update_fuzzer_and_data_bundles(fuzzer_name)
  fuzz_task_knobs.do_multiarmed_bandit_strategy_selection(uworker_env)
  environment.set_value('PROJECT_NAME', data_handler.get_project_name(job_type),
                        uworker_env)
  fuzz_target = _preprocess_get_fuzz_target(fuzzer_name, job_type)
  fuzz_task_input = uworker_msg_pb2.FuzzTaskInput()  # pylint: disable=no-member
  if fuzz_target:
    # Add the chosen fuzz target to logs context.
    logs.log_contexts.add_metadata('fuzz_target', fuzz_target.binary)
    fuzz_task_input.fuzz_target.CopyFrom(
        uworker_io.entity_to_protobuf(fuzz_target))
    fuzz_task_input.corpus.CopyFrom(
        corpus_manager.get_fuzz_target_corpus(
            fuzzer_name,
            fuzz_target.project_qualified_name(),
            include_delete_urls=False,
            max_upload_urls=_get_max_corpus_uploads_per_task(),
            max_download_urls=25000,
            use_backup=True).serialize())

  for _ in range(MAX_CRASHES_UPLOADED):
    url = fuzz_task_input.crash_upload_urls.add()
    url.key = blobs.generate_new_blob_name()
    url.url = blobs.get_signed_upload_url(url.key)

  preprocess_store_fuzzer_run_results(fuzz_task_input)

  if environment.get_value('LSAN'):
    # Copy global blacklist into local suppressions file if LSan is enabled.
    fuzz_task_input.global_blacklisted_functions.extend(
        leak_blacklist.get_global_blacklisted_functions())

  return uworker_msg_pb2.Input(  # pylint: disable=no-member
      fuzz_task_input=fuzz_task_input,
      job_type=job_type,
      fuzzer_name=fuzzer_name,
      uworker_env=uworker_env,
      setup_input=setup_input,
  )


def utask_preprocess(fuzzer_name, job_type, uworker_env):
  """Set logs context and preprocess untrusted task."""
  # Delay adding the fuzz target to logs context until it is chosen in
  # preprocess.
  with logs.fuzzer_log_context(fuzzer_name, job_type, fuzz_target=None):
    return _utask_preprocess(fuzzer_name, job_type, uworker_env)


def save_fuzz_targets(output):
  """Saves fuzz targets that were seen in the build to the database."""
  if not output.fuzz_task_output.fuzz_targets:
    return

  logs.info(f'Saving fuzz targets: {output.fuzz_task_output.fuzz_targets}.')
  data_handler.record_fuzz_targets(output.uworker_input.fuzzer_name,
                                   output.fuzz_task_output.fuzz_targets,
                                   output.uworker_input.job_type)


def _to_engine_output(output: str, crash_path: str, return_code: int,
                      log_time: datetime.datetime):
  """Returns an EngineOutput proto."""
  truncated_output = truncate_fuzzer_output(output, ENGINE_OUTPUT_LIMIT)
  if len(output) != len(truncated_output):
    logs.warning('Fuzzer output truncated.')

  proto_timestamp = uworker_io.timestamp_to_proto_timestamp(log_time)
  engine_output = uworker_msg_pb2.EngineOutput(
      output=bytes(truncated_output, 'utf-8'),
      return_code=return_code,
      timestamp=proto_timestamp)

  if crash_path is None:
    return engine_output
  if os.path.getsize(crash_path) > 10 * 1024**2:
    return engine_output
  with open(crash_path, 'rb') as fp:
    engine_output.testcase = fp.read()

  return engine_output


def _upload_engine_output(engine_output):
  timestamp = uworker_io.proto_timestamp_to_timestamp(engine_output.timestamp)
  testcase_manager.upload_log(engine_output.output.decode(),
                              engine_output.return_code, timestamp)
  testcase_manager.upload_testcase(None, engine_output.testcase, timestamp)


def _utask_postprocess(output):
  """Postprocesses fuzz_task."""
  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
    _ERROR_HANDLER.handle(output)
    return

  save_fuzz_targets(output)

  session = _make_session(output.uworker_input)
  # TODO(metzman): Get rid of this method and move functionality to this
  # function.
  session.postprocess(output)
  # TODO(b/374776013): Refactor this code so the uploads happen during
  # utask_main.
  for engine_output in output.fuzz_task_output.engine_outputs:
    _upload_engine_output(engine_output)


def utask_postprocess(output):
  """Sets fuzzing logs context and postprocesses fuzz_task."""
  fuzzer_name = output.uworker_input.fuzzer_name
  job_type = output.uworker_input.job_type
  if output.uworker_input.fuzz_task_input.HasField('fuzz_target'):
    fuzz_target = uworker_io.entity_from_protobuf(
        output.uworker_input.fuzz_task_input.fuzz_target, data_types.FuzzTarget)
  else:
    fuzz_target = None
  with logs.fuzzer_log_context(fuzzer_name, job_type, fuzz_target):
    return _utask_postprocess(output)
