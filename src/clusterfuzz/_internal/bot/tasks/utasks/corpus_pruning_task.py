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
"""Corpus pruning task."""

import collections
import datetime
import json
import os
import random
import shutil
from typing import List
import zipfile

from google.cloud import ndb
from google.protobuf import timestamp_pb2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz.fuzz import engine

# TODO(ochang): Move common libFuzzer code from fuzzer into CF.

# Redzone size for running testcase.
DEFAULT_REDZONE = 32

# Minimum redzone size for use during merging.
MIN_REDZONE = 16

# Timeout for corpus pruning. Note that our priority is to make sure fuzzer's
# own corpus is minimized. If time remains, we spend time on using units from
# shared corpus. This combined timeout should be lower than task lease timeout.
CORPUS_PRUNING_TIMEOUT = 22 * 60 * 60

# Time to allow libFuzzer to timeout on its own.
SINGLE_UNIT_TIMEOUT = 5
TIMEOUT_FLAG = f'-timeout={SINGLE_UNIT_TIMEOUT}'

# Corpus files limit for cases when corpus pruning task failed in the last
# execution.
CORPUS_FILES_LIMIT_FOR_FAILURES = 10000

# Corpus total size limit for cases when corpus pruning task failed in the last
# execution.
CORPUS_SIZE_LIMIT_FOR_FAILURES = 2 * 1024 * 1024 * 1024  # 2 GB.

# Maximum number of units to restore from quarantine in one run.
MAX_QUARANTINE_UNITS_TO_RESTORE = 128

# Memory limits for testcase.
RSS_LIMIT = 2560
RSS_LIMIT_MB_FLAG = '-rss_limit_mb=%d'

# Flag to enforce length limit for a single corpus element.
MAX_LEN_FLAG = '-max_len=%d'

# Flag to control memory leaks detection.
DETECT_LEAKS_FLAG = '-detect_leaks=%d'

# Longer than default sync timeout to fix broken (overly large) corpora without
# losing coverage.
SYNC_TIMEOUT = 2 * 60 * 60

# Number of fuzz targets whose backup corpus is used to cross pollinate with our
# current fuzz target corpus.
CROSS_POLLINATE_FUZZER_COUNT = 3

CorpusPruningResult = collections.namedtuple('CorpusPruningResult', [
    'coverage_info', 'crashes', 'fuzzer_binary_name', 'revision',
    'cross_pollination_stats'
])

CrossPollinationStats = collections.namedtuple('CrossPollinationStats', [
    'project_qualified_name', 'sources', 'initial_corpus_size', 'corpus_size',
    'initial_edge_coverage', 'edge_coverage', 'initial_feature_coverage',
    'feature_coverage'
])


def _get_corpus_file_paths(corpus_path):
  """Return full paths to corpus files in |corpus_path|."""
  return [
      os.path.join(corpus_path, filename)
      for filename in os.listdir(corpus_path)
  ]


def _limit_corpus_size(corpus_url):
  """Limit number of files and size of a corpus."""
  corpus_count = 0
  corpus_size = 0
  deleted_corpus_count = 0
  bucket, _ = storage.get_bucket_name_and_path(corpus_url)
  logs.info('Limiting corpus size.')
  for corpus_file in storage.get_blobs(corpus_url):
    corpus_count += 1
    corpus_size += corpus_file['size']
    if (corpus_count > CORPUS_FILES_LIMIT_FOR_FAILURES or
        corpus_size > CORPUS_SIZE_LIMIT_FOR_FAILURES):
      path_to_delete = storage.get_cloud_storage_file_path(
          bucket, corpus_file['name'])
      storage.delete(path_to_delete)
      deleted_corpus_count += 1
  logs.info('Done limiting corpus size.')

  if deleted_corpus_count:
    logs.info('Removed %d files from oversized corpus: %s.' %
              (deleted_corpus_count, corpus_url))


def _get_time_remaining(start_time):
  """Return time remaining."""
  time_used = int((datetime.datetime.utcnow() - start_time).total_seconds())
  return CORPUS_PRUNING_TIMEOUT - time_used


class CorpusPruningError(Exception):
  """Corpus pruning exception."""


class CrossPollinateFuzzer:
  """Cross Pollinate Fuzzer."""

  def __init__(self, fuzz_target, backup_bucket_name, corpus_engine_name):
    self.fuzz_target = fuzz_target
    self.backup_bucket_name = backup_bucket_name
    self.corpus_engine_name = corpus_engine_name


class Context:
  """Pruning state."""

  def __init__(self, uworker_input, fuzz_target, cross_pollinate_fuzzers):

    self.fuzz_target = fuzz_target
    self.cross_pollinate_fuzzers = cross_pollinate_fuzzers

    self.merge_tmp_dir = None
    self.engine = engine.get(self.fuzz_target.engine)
    if not self.engine:
      raise CorpusPruningError(
          f'Engine not found for fuzz_target: {fuzz_target}')

    self._created_directories = []

    # Set up temporary directories where corpora will be synced to.
    # Initial synced corpus.
    self.initial_corpus_path = self._create_temp_corpus_directory(
        f'{self.fuzz_target.project_qualified_name()}_initial_corpus')
    # Minimized corpus.
    self.minimized_corpus_path = self._create_temp_corpus_directory(
        f'{self.fuzz_target.project_qualified_name()}_minimized_corpus')
    # Synced quarantine corpus.
    self.quarantine_corpus_path = self._create_temp_corpus_directory(
        f'{self.fuzz_target.project_qualified_name()}_quarantine')
    # Synced shared corpus.
    self.shared_corpus_path = self._create_temp_corpus_directory(
        f'{self.fuzz_target.project_qualified_name()}_shared')
    # Bad units.
    self.bad_units_path = self._create_temp_corpus_directory(
        f'{self.fuzz_target.project_qualified_name()}_bad_units')
    self.merge_tmp_dir = self._create_temp_corpus_directory('merge_workdir')

    self.corpus = corpus_manager.ProtoFuzzTargetCorpus(
        self.fuzz_target.engine, self.fuzz_target.project_qualified_name(),
        uworker_input.corpus_pruning_task_input.corpus)
    self.quarantine_corpus = corpus_manager.ProtoFuzzTargetCorpus(
        self.fuzz_target.engine, self.fuzz_target.project_qualified_name(),
        uworker_input.corpus_pruning_task_input.quarantine_corpus)
    self.dated_backup_gcs_url = (
        uworker_input.corpus_pruning_task_input.dated_backup_gcs_url)
    self.dated_backup_signed_url = (
        uworker_input.corpus_pruning_task_input.dated_backup_signed_url)

  def restore_quarantined_units(self):
    """Restore units from the quarantine."""
    logs.info('Restoring units from quarantine.')
    # Limit the number of quarantine units to restore, in case there are a lot.
    quarantine_unit_paths = _get_corpus_file_paths(self.quarantine_corpus_path)
    if len(quarantine_unit_paths) > MAX_QUARANTINE_UNITS_TO_RESTORE:
      logs.info('Getting a random sample of quarantine_unit_paths.')
      quarantine_unit_paths = random.sample(quarantine_unit_paths,
                                            MAX_QUARANTINE_UNITS_TO_RESTORE)

    for unit_path in quarantine_unit_paths:
      unit_filename = os.path.basename(unit_path)
      shutil.move(unit_path,
                  os.path.join(self.initial_corpus_path, unit_filename))

  def _create_temp_corpus_directory(self, name):
    """Create temporary corpus directory. Returns path to the created
    directory."""
    testcases_directory = environment.get_value('FUZZ_INPUTS_DISK')
    directory_path = os.path.join(testcases_directory, name)
    shell.create_directory(directory_path)
    self._created_directories.append(directory_path)

    return directory_path

  def sync_to_disk(self):
    """Sync required corpora to disk."""
    if not self.corpus.rsync_to_disk(self.initial_corpus_path):
      raise CorpusPruningError('Failed to sync corpus to disk.')

    if not self.quarantine_corpus.rsync_to_disk(self.initial_corpus_path):
      logs.error(
          'Failed to sync quarantine corpus to disk.',
          fuzz_target=self.fuzz_target)

    self._cross_pollinate_other_fuzzer_corpuses()

  def sync_to_gcs(self):
    """Sync corpora to GCS post merge."""
    if not self.corpus.rsync_from_disk(self.minimized_corpus_path):
      raise CorpusPruningError('Failed to sync minimized corpus to gcs.')

  def cleanup(self):
    """Cleanup state."""
    for path in self._created_directories:
      shell.remove_directory(path)

  def _cross_pollinate_other_fuzzer_corpuses(self):
    """Add other fuzzer corpuses to shared corpus path for cross-pollination."""
    corpus_backup_date = utils.utcnow().date() - datetime.timedelta(
        days=data_types.CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS)

    for cross_pollinate_fuzzer in self.cross_pollinate_fuzzers:
      project_qualified_name = (
          cross_pollinate_fuzzer.fuzz_target.project_qualified_name())
      backup_bucket_name = cross_pollinate_fuzzer.backup_bucket_name
      corpus_engine_name = cross_pollinate_fuzzer.corpus_engine_name

      corpus_backup_url = corpus_manager.gcs_url_for_backup_file(
          backup_bucket_name, corpus_engine_name, project_qualified_name,
          corpus_backup_date)
      corpus_backup_local_filename = '%s-%s' % (
          project_qualified_name, os.path.basename(corpus_backup_url))
      corpus_backup_local_path = os.path.join(self.shared_corpus_path,
                                              corpus_backup_local_filename)

      if not storage.exists(corpus_backup_url, ignore_errors=True):
        # This can happen in cases when a new fuzz target is checked in or if
        # missed to capture a backup for a particular day (for OSS-Fuzz, this
        # will result in a 403 instead of 404 since that GCS path belongs to
        # other project). So, just log a warning for debugging purposes only.
        logs.warning(
            'Corpus backup does not exist, ignoring: %s.' % corpus_backup_url)
        continue

      if not storage.copy_file_from(corpus_backup_url,
                                    corpus_backup_local_path):
        continue

      corpus_backup_output_directory = os.path.join(self.shared_corpus_path,
                                                    project_qualified_name)
      shell.create_directory(corpus_backup_output_directory)
      with archive.open(corpus_backup_local_path) as reader:
        result = reader.extract_all(corpus_backup_output_directory)
      shell.remove_file(corpus_backup_local_path)

      if result:
        logs.info(
            'Corpus backup url %s successfully unpacked into shared corpus.' %
            corpus_backup_url)
      else:
        logs.error(
            'Failed to unpack corpus backup from url %s.' % corpus_backup_url)


class BaseRunner:
  """Base Runner"""

  def __init__(self, build_directory, context):
    self.build_directory = build_directory
    self.context = context

    self.target_path = engine_common.find_fuzzer_path(
        self.build_directory, self.context.fuzz_target.binary)
    if not self.target_path:
      raise CorpusPruningError(
          f'Failed to get fuzzer path for {self.context.fuzz_target.binary}')
    self.fuzzer_options = options.get_fuzz_target_options(self.target_path)

  def get_fuzzer_flags(self):
    return []

  def process_sanitizer_options(self):
    """Process sanitizer options overrides."""
    if not self.fuzzer_options:
      return

    # Only need to look as ASan, as that's what we prune with.
    overrides = self.fuzzer_options.get_asan_options()
    if not overrides:
      return

    asan_options = environment.get_memory_tool_options('ASAN_OPTIONS')
    if not asan_options:
      return
    asan_options.update(overrides)
    environment.set_memory_tool_options('ASAN_OPTIONS', asan_options)

  def reproduce(self, input_path, arguments, max_time):
    return self.context.engine.reproduce(self.target_path, input_path,
                                         arguments, max_time)

  def minimize_corpus(self, arguments, input_dirs, output_dir, reproducers_dir,
                      max_time):
    return self.context.engine.minimize_corpus(self.target_path, arguments,
                                               input_dirs, output_dir,
                                               reproducers_dir, max_time)


class LibFuzzerRunner(BaseRunner):
  """Runner for libFuzzer."""

  def get_fuzzer_flags(self):
    """Get default libFuzzer options for pruning."""
    rss_limit = RSS_LIMIT
    max_len = engine_common.CORPUS_INPUT_SIZE_LIMIT
    detect_leaks = 1
    arguments = options.FuzzerArguments()
    arguments[constants.TIMEOUT_FLAGNAME] = SINGLE_UNIT_TIMEOUT

    if self.fuzzer_options:
      # Default values from above can be customized for a given fuzz target.
      libfuzzer_arguments = self.fuzzer_options.get_engine_arguments(
          'libfuzzer')

      custom_rss_limit = libfuzzer_arguments.get(
          'rss_limit_mb', constructor=int)
      if custom_rss_limit:
        rss_limit = custom_rss_limit

      custom_max_len = libfuzzer_arguments.get('max_len', constructor=int)
      if custom_max_len and custom_max_len < max_len:
        max_len = custom_max_len

      # Some targets might falsely report leaks all the time, so allow this to
      # be disabled.
      custom_detect_leaks = libfuzzer_arguments.get(
          'detect_leaks', constructor=int)
      if custom_detect_leaks is not None:
        detect_leaks = custom_detect_leaks

    arguments[constants.RSS_LIMIT_FLAGNAME] = rss_limit
    arguments[constants.MAX_LEN_FLAGNAME] = max_len
    arguments[constants.DETECT_LEAKS_FLAGNAME] = detect_leaks
    arguments[constants.VALUE_PROFILE_FLAGNAME] = 1

    return arguments.list()

  def reproduce(self, input_path, arguments, max_time):
    return self.context.engine.reproduce(self.target_path, input_path,
                                         arguments, max_time)

  def minimize_corpus(self, arguments, input_dirs, output_dir, reproducers_dir,
                      max_time):
    return self.context.engine.minimize_corpus(self.target_path, arguments,
                                               input_dirs, output_dir,
                                               reproducers_dir, max_time)


class CentipedeRunner(BaseRunner):
  """Runner implementation for Centipede fuzzing engine."""


class CorpusPrunerBase:
  """Base class for corpus pruning that is engine‐agnostic."""

  def __init__(self, runner):
    self.runner = runner
    self.context = runner.context

  def run(self, initial_corpus_path, minimized_corpus_path, bad_units_path):
    """Running generic corpus prunning"""
    if not shell.get_directory_file_count(initial_corpus_path):
      # Empty corpus, nothing to do.
      return None

    # Unpack seed corpus if needed.
    engine_common.unpack_seed_corpus_if_needed(
        self.runner.target_path, initial_corpus_path, force_unpack=True)

    environment.reset_current_memory_tool_options(
        redzone_size=MIN_REDZONE, leaks=True)
    self.runner.process_sanitizer_options()

    additional_args = self.runner.get_fuzzer_flags()
    logs.info('Running merge...')
    try:
      result = self.runner.minimize_corpus(
          additional_args, [initial_corpus_path], minimized_corpus_path,
          bad_units_path, CORPUS_PRUNING_TIMEOUT)
    except TimeoutError as e:
      raise CorpusPruningError(
          'Corpus pruning timed out while minimizing corpus\n' + repr(e))
    except engine.Error as e:
      raise CorpusPruningError('Corpus pruning failed to minimize corpus\n' +
                               repr(e))

    symbolized_output = stack_symbolizer.symbolize_stacktrace(result.logs)

    if not shell.get_directory_file_count(minimized_corpus_path):
      raise CorpusPruningError('Corpus pruning failed to minimize corpus\n' +
                               symbolized_output)

    logs.info('Corpus merge finished successfully.', output=symbolized_output)
    return result.stats

  def process_bad_units(self, bad_units_path, quarantine_corpus_path):
    del bad_units_path
    del quarantine_corpus_path
    return {}


class LibFuzzerPruner(CorpusPrunerBase):
  """
  LibFuzzerPruner is a specialized pruner for libFuzzer that handles
  quarantining of problematic units and related special cases.
  """

  def _run_single_unit(self, unit_path):
    arguments = self.runner.get_fuzzer_flags()  # Expect libFuzzer flags.
    return self.runner.reproduce(unit_path, arguments, SINGLE_UNIT_TIMEOUT)

  def _quarantine_unit(self, unit_path, quarantine_corpus_path):
    quarantined_unit_path = os.path.join(quarantine_corpus_path,
                                         os.path.basename(unit_path))
    shutil.move(unit_path, quarantined_unit_path)
    return quarantined_unit_path

  def process_bad_units(self, bad_units_path, quarantine_corpus_path):
    """
    Process bad units by running each test case individually,
    quarantining those that timeout, OOM, or crash due to memory sanitizer
    errors.
    """
    crashes = {}

    environment.reset_current_memory_tool_options(redzone_size=DEFAULT_REDZONE)
    self.runner.process_sanitizer_options()

    logs.info('Processing bad units.')
    corpus_file_paths = _get_corpus_file_paths(bad_units_path)
    num_bad_units = 0

    for i, unit_path in enumerate(corpus_file_paths, 1):
      if i % 100 == 0:
        logs.info('Up to %d' % i)

      unit_name = os.path.basename(unit_path)
      if unit_name.startswith('timeout-') or unit_name.startswith('oom-'):
        # Immediately quarantine timeouts/oom testcases.
        self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      try:
        result = self._run_single_unit(unit_path)
      except TimeoutError:
        self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      if not crash_analyzer.is_memory_tool_crash(result.output):
        continue

      state = stack_analyzer.get_crash_data(result.output, symbolize_flag=True)

      # Quarantine the crashing unit.
      unit_path = self._quarantine_unit(unit_path, quarantine_corpus_path)
      num_bad_units += 1

      if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
        continue

      if state.crash_state not in crashes:
        security_flag = crash_analyzer.is_security_issue(
            state.crash_stacktrace, state.crash_type, state.crash_address)
        crashes[state.crash_state] = uworker_msg_pb2.CrashInfo(  # pylint: disable=no-member
            crash_state=state.crash_state,
            crash_type=state.crash_type,
            crash_address=state.crash_address,
            crash_stacktrace=state.crash_stacktrace,
            unit_path=unit_path,
            security_flag=security_flag)
    logs.info(
        f'Found {num_bad_units} bad units, {len(crashes)} unique crashes.')
    return crashes


class CentipedePruner(CorpusPrunerBase):
  """Centipede pruner."""


class CrossPollinator:
  """Cross pollination."""

  def __init__(self, runner):
    self.runner = runner
    self.context = self.runner.context

  def run(self, timeout):
    """Merge testcases from corpus from other fuzz targets."""
    if not shell.get_directory_file_count(self.context.shared_corpus_path):
      logs.info('No files found in shared corpus, skip merge.')
      return None

    # Run pruning on the shared corpus and log the result in case of error.
    logs.info('Merging shared corpus...')
    environment.reset_current_memory_tool_options(redzone_size=DEFAULT_REDZONE)
    self.runner.process_sanitizer_options()

    additional_args = self.runner.get_fuzzer_flags()

    try:
      result = self.runner.minimize_corpus(additional_args,
                                           [self.context.shared_corpus_path],
                                           self.context.minimized_corpus_path,
                                           self.context.bad_units_path, timeout)
      symbolized_output = stack_symbolizer.symbolize_stacktrace(result.logs)
      logs.info(
          'Shared corpus merge finished successfully.',
          output=symbolized_output)
    except TimeoutError as e:
      # Other cross pollinated fuzzer corpuses can have unexpected test cases
      # that time us out. This is expected, so bail out.
      logs.warning('Corpus pruning timed out while merging shared corpus\n' +
                   repr(e))
      return None
    except engine.Error as e:
      # Other cross pollinated fuzzer corpuses can be large, so we can run out
      # of disk space and exception out. This is expected, so bail out.
      logs.warning('Corpus pruning failed to merge shared corpus\n' + repr(e))
      return None

    return result.stats


def _fill_cross_pollination_stats(stats, output):
  """Fills the cross pollination statistics in the corpus pruning output."""
  if not stats:
    return

  statistics = uworker_msg_pb2.CrossPollinationStatistics(  # pylint: disable=no-member
      project_qualified_name=stats.project_qualified_name,
      sources=stats.sources,
      initial_corpus_size=stats.initial_corpus_size,
      corpus_size=stats.corpus_size,
      initial_edge_coverage=stats.initial_edge_coverage,
      edge_coverage=stats.edge_coverage,
      initial_feature_coverage=stats.initial_feature_coverage,
      feature_coverage=stats.feature_coverage)

  output.corpus_pruning_task_output.cross_pollination_stats.CopyFrom(statistics)


def _record_cross_pollination_stats(output):
  """Log stats about cross pollination in BigQuery."""
  # If no stats were gathered due to a timeout or lack of corpus, return.

  if not output.corpus_pruning_task_output.HasField('cross_pollination_stats'):
    return
  stats = output.corpus_pruning_task_output.cross_pollination_stats
  bigquery_row = {
      'project_qualified_name': stats.project_qualified_name,
      'sources': stats.sources,
      'initial_corpus_size': stats.initial_corpus_size,
      'corpus_size': stats.corpus_size,
      'initial_edge_coverage': stats.initial_edge_coverage,
      'edge_coverage': stats.edge_coverage,
      'initial_feature_coverage': stats.initial_feature_coverage,
      'feature_coverage': stats.feature_coverage
  }

  # BigQuery not available in local development. This is necessary because the
  # untrusted runner is in a separate process and can't be easily mocked.
  # Check here instead of earlier to test as much of the function as we can.
  if environment.get_value('LOCAL_DEVELOPMENT') or environment.get_value(
      'PY_UNITTESTS'):
    return

  client = big_query.Client(
      dataset_id='main', table_id='cross_pollination_statistics')
  client.insert([big_query.Insert(row=bigquery_row, insert_id=None)])


def _get_pruner_and_runner(context):
  """Get pruner and runner object acording with the FuzzTarget into the context
  """
  build_directory = environment.get_value('BUILD_DIR')
  if context.fuzz_target.engine.lower() == 'libfuzzer':
    runner = LibFuzzerRunner(build_directory, context)
    pruner = LibFuzzerPruner(runner)
  elif context.fuzz_target.engine.lower() == 'centipede':
    runner = CentipedeRunner(build_directory, context)
    pruner = CentipedePruner(runner)
  else:
    raise CorpusPruningError(
        'Corpus pruner task does not support the given engine.')
  return pruner, runner


def do_corpus_pruning(uworker_input, context, revision) -> CorpusPruningResult:
  """Run corpus pruning."""
  # Set |FUZZ_TARGET| environment variable to help with unarchiving only fuzz
  # target and its related files.
  environment.set_value('FUZZ_TARGET', context.fuzz_target.binary)

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import tasks_host
    return tasks_host.do_corpus_pruning(uworker_input, context, revision)

  if not build_manager.setup_build(
      revision=revision, fuzz_target=context.fuzz_target.binary):
    raise CorpusPruningError('Failed to setup build.')

  start_time = datetime.datetime.utcnow()
  pruner, runner = _get_pruner_and_runner(context)
  fuzzer_binary_name = os.path.basename(runner.target_path)

  logs.info('Getting the initial corpus to process from GCS.')
  context.sync_to_disk()
  initial_corpus_size = shell.get_directory_file_count(
      context.initial_corpus_path)

  logs.info('Restoring a small batch of quarantined units back to corpus.')
  context.restore_quarantined_units()

  # Shrink to a minimized corpus using corpus merge.
  pruner_stats = pruner.run(context.initial_corpus_path,
                            context.minimized_corpus_path,
                            context.bad_units_path)

  logs.info('Syncing the minimized corpus back to GCS.')
  context.sync_to_gcs()

  logs.info('Saved minimize corpus.')

  # Create corpus backup.
  # Temporarily copy the past crash regressions folder into the minimized corpus
  # so that corpus backup archive can have both.
  regressions_input_dir = os.path.join(context.initial_corpus_path,
                                       'regressions')
  regressions_output_dir = os.path.join(context.minimized_corpus_path,
                                        'regressions')
  if shell.get_directory_file_count(regressions_input_dir):
    shutil.copytree(regressions_input_dir, regressions_output_dir)
  backup_succeeded = corpus_manager.backup_corpus(
      context.dated_backup_signed_url, context.corpus,
      context.minimized_corpus_path)
  corpus_backup_location = (
      context.dated_backup_gcs_url if backup_succeeded else None)
  shell.remove_directory(regressions_output_dir)

  minimized_corpus_size_units = shell.get_directory_file_count(
      context.minimized_corpus_path)
  minimized_corpus_size_bytes = shell.get_directory_size(
      context.minimized_corpus_path)

  logs.info(f'Corpus pruned from {initial_corpus_size} '
            f'to {minimized_corpus_size_units} units.')

  # Process bad units found during merge.
  # Mapping of crash state -> CrashInfo
  crashes = pruner.process_bad_units(context.bad_units_path,
                                     context.quarantine_corpus_path)
  if shell.get_directory_file_count(context.quarantine_corpus_path):
    context.quarantine_corpus.rsync_from_disk(context.quarantine_corpus_path)

  # Store corpus stats into CoverageInformation entity.
  project_qualified_name = context.fuzz_target.project_qualified_name()
  today = datetime.datetime.utcnow()
  coverage_info = data_types.CoverageInformation(
      fuzzer=project_qualified_name, date=today)

  quarantine_corpus_size = shell.get_directory_file_count(
      context.quarantine_corpus_path)
  quarantine_corpus_dir_size = shell.get_directory_size(
      context.quarantine_corpus_path)

  # Save the minimize corpus size before cross pollination to put in BigQuery.
  pre_pollination_corpus_size = minimized_corpus_size_units

  # Populate coverage stats.
  coverage_info.corpus_size_units = minimized_corpus_size_units
  coverage_info.corpus_size_bytes = minimized_corpus_size_bytes
  coverage_info.quarantine_size_units = quarantine_corpus_size
  coverage_info.quarantine_size_bytes = quarantine_corpus_dir_size
  coverage_info.corpus_backup_location = corpus_backup_location
  coverage_info.corpus_location = context.corpus.get_gcs_url()
  coverage_info.quarantine_location = context.quarantine_corpus.get_gcs_url()

  # Calculate remaining time to use for shared corpus merging.
  time_remaining = _get_time_remaining(start_time)
  if time_remaining <= 0:
    logs.warning('Not enough time for shared corpus merging.')
    return None

  cross_pollinator = CrossPollinator(runner)
  pollinator_stats = cross_pollinator.run(time_remaining)

  context.sync_to_gcs()

  # Update corpus size stats.
  minimized_corpus_size_units = shell.get_directory_file_count(
      context.minimized_corpus_path)
  minimized_corpus_size_bytes = shell.get_directory_size(
      context.minimized_corpus_path)
  coverage_info.corpus_size_units = minimized_corpus_size_units
  coverage_info.corpus_size_bytes = minimized_corpus_size_bytes

  logs.info('Finished.')

  sources = ','.join([
      fuzzer.fuzz_target.project_qualified_name()
      for fuzzer in context.cross_pollinate_fuzzers
  ])

  cross_pollination_stats = None
  if pruner_stats and pollinator_stats:
    cross_pollination_stats = CrossPollinationStats(
        project_qualified_name, sources, initial_corpus_size,
        pre_pollination_corpus_size, pruner_stats['edge_coverage'],
        pollinator_stats['edge_coverage'], pruner_stats['feature_coverage'],
        pollinator_stats['feature_coverage'])

  return CorpusPruningResult(
      coverage_info=coverage_info,
      crashes=list(crashes.values()),
      fuzzer_binary_name=fuzzer_binary_name,
      revision=environment.get_value('APP_REVISION'),
      cross_pollination_stats=cross_pollination_stats)


def _update_crash_unit_path(context, crash):
  """If running on a trusted host, updates the crash unit_path after copying
  the file locally."""
  if not environment.is_trusted_host():
    return
  from clusterfuzz._internal.bot.untrusted_runner import file_host
  unit_path = os.path.join(context.bad_units_path,
                           os.path.basename(crash.unit_path))
  # Prevent the worker from escaping out of |context.bad_units_path|.
  if not file_host.is_directory_parent(unit_path, context.bad_units_path):
    raise CorpusPruningError('Invalid units path from worker.')

  file_host.copy_file_from_worker(crash.unit_path, unit_path)
  crash.unit_path = unit_path


def _upload_corpus_crashes_zip(context: Context, result: CorpusPruningResult,
                               corpus_crashes_blob_name,
                               corpus_crashes_upload_url):
  """Packs the corpus crashes in a zip file. The file is then uploaded
  using the signed upload url from the input."""
  temp_dir = environment.get_value('BOT_TMPDIR')
  zip_filename = os.path.join(temp_dir, corpus_crashes_blob_name)
  with zipfile.ZipFile(zip_filename, 'w') as zip_file:
    for crash in result.crashes:
      _update_crash_unit_path(context, crash)
      unit_name = os.path.basename(crash.unit_path)
      zip_file.write(crash.unit_path, unit_name, zipfile.ZIP_DEFLATED)

  with open(zip_filename, 'rb') as fp:
    data = fp.read()
    storage.upload_signed_url(data, corpus_crashes_upload_url)
  os.remove(zip_filename)


def _process_corpus_crashes(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  """Process crashes found in the corpus."""
  if not output.corpus_pruning_task_output.crashes:
    return

  corpus_pruning_output = output.corpus_pruning_task_output
  crash_revision = corpus_pruning_output.crash_revision
  fuzz_target = data_handler.get_fuzz_target(output.uworker_input.fuzzer_name)
  job_type = environment.get_value('JOB_NAME')

  minimized_arguments = f'%TESTCASE% {fuzz_target.binary}'
  project_name = data_handler.get_project_name(job_type)

  comment = (f'Fuzzer {fuzz_target.project_qualified_name()} generated corpus'
             f' testcase crashed (r{crash_revision})')

  # Copy the crashes zip file from cloud storage into a temporary directory.
  temp_dir = environment.get_value('BOT_TMPDIR')
  corpus_crashes_blob_name = (
      output.uworker_input.corpus_pruning_task_input.corpus_crashes_blob_name)
  corpus_crashes_zip_local_path = os.path.join(
      temp_dir, f'{corpus_crashes_blob_name}.zip')
  storage.copy_file_from(
      blobs.get_gcs_path(corpus_crashes_blob_name),
      corpus_crashes_zip_local_path)
  with archive.open(corpus_crashes_zip_local_path) as zip_reader:
    for crash in corpus_pruning_output.crashes:
      existing_testcase = data_handler.find_testcase(
          project_name,
          crash.crash_type,
          crash.crash_state,
          crash.security_flag,
          fuzz_target=fuzz_target.project_qualified_name())
      if existing_testcase:
        continue

      unit_name = os.path.basename(crash.unit_path)
      crash_local_unit_path = os.path.join(temp_dir, unit_name)
      # Extract the crash unit_path into crash_local_unit_path
      zip_reader.extract(member=unit_name, path=temp_dir)
      # Upload/store testcase.
      with open(crash_local_unit_path, 'rb') as f:
        key = blobs.write_blob(f)

      # Set the absolute_path property of the Testcase to a file in FUZZ_INPUTS
      # instead of the local quarantine directory.
      absolute_testcase_path = os.path.join(
          environment.get_value('FUZZ_INPUTS'), 'testcase')

      # TODO(https://b.corp.google.com/issues/328691756): Set trusted based on
      # the job when we start doing untrusted fuzzing.
      testcase_id = data_handler.store_testcase(
          crash=crash,
          fuzzed_keys=key,
          minimized_keys='',
          regression='',
          fixed='',
          one_time_crasher_flag=False,
          crash_revision=crash_revision,
          comment=comment,
          absolute_path=absolute_testcase_path,
          fuzzer_name=fuzz_target.engine,
          fully_qualified_fuzzer_name=fuzz_target.fully_qualified_name(),
          job_type=job_type,
          archived=False,
          archive_filename='',
          http_flag=False,
          gestures=None,
          redzone=DEFAULT_REDZONE,
          disable_ubsan=False,
          window_argument=None,
          timeout_multiplier=1.0,
          minimized_arguments=minimized_arguments,
          trusted=True)

      # Set fuzzer_binary_name in testcase metadata.
      testcase = data_handler.get_testcase_by_id(testcase_id)
      testcase.set_metadata('fuzzer_binary_name',
                            corpus_pruning_output.fuzzer_binary_name)

      if output.issue_metadata:
        for key, value in json.loads(output.issue_metadata).items():
          testcase.set_metadata(key, value, update_testcase=False)

        testcase.put()

      # Create additional tasks for testcase (starting with minimization).
      testcase = data_handler.get_testcase_by_id(testcase_id)
      task_creation.create_tasks(testcase)

  os.remove(corpus_crashes_zip_local_path)
  # Cleanup the uploaded zip file.
  blobs.delete_blob(corpus_crashes_blob_name)


def _select_targets_and_jobs_for_pollination(engine_name, current_fuzzer_name):
  """Select jobs to use for cross pollination."""
  target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(engine=engine_name))
  targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(target_jobs)

  targets_and_jobs = [(target, target_job)
                      for target, target_job in zip(targets, target_jobs)
                      if target_job.fuzz_target_name != current_fuzzer_name]
  selected_targets_and_jobs = random.SystemRandom().sample(
      targets_and_jobs, min(
          len(targets_and_jobs), CROSS_POLLINATE_FUZZER_COUNT))

  return selected_targets_and_jobs


def _get_cross_pollinate_fuzzers(
    engine_name: str, current_fuzzer_name: str
) -> List[uworker_msg_pb2.CrossPollinateFuzzerProto]:  # pylint: disable=no-member
  """Return a list of fuzzer objects to use for cross pollination."""
  cross_pollinate_fuzzers = []

  selected_targets_and_jobs = _select_targets_and_jobs_for_pollination(
      engine_name, current_fuzzer_name)

  default_backup_bucket = utils.default_backup_bucket()
  for target, target_job in selected_targets_and_jobs:
    job = data_types.Job.query(data_types.Job.name == target_job.job).get()
    if not job:
      continue

    job_environment = job.get_environment()
    backup_bucket_name = job_environment.get('BACKUP_BUCKET',
                                             default_backup_bucket)
    if not backup_bucket_name:
      continue
    corpus_engine_name = job_environment.get('CORPUS_FUZZER_NAME_OVERRIDE',
                                             engine_name)

    cross_pollinate_fuzzers.append(
        uworker_msg_pb2.CrossPollinateFuzzerProto(  # pylint: disable=no-member
            fuzz_target=uworker_io.entity_to_protobuf(target),
            backup_bucket_name=backup_bucket_name,
            corpus_engine_name=corpus_engine_name,
        ))

  return cross_pollinate_fuzzers


def _get_cross_pollinate_fuzzers_from_protos(cross_pollinate_fuzzers_protos):
  return [
      CrossPollinateFuzzer(
          uworker_io.entity_from_protobuf(proto.fuzz_target,
                                          data_types.FuzzTarget),
          proto.backup_bucket_name,
          proto.corpus_engine_name,
      ) for proto in cross_pollinate_fuzzers_protos
  ]


def _save_coverage_information(output):
  """Saves coverage information in datastore using an atomic transaction."""
  if not output.corpus_pruning_task_output.HasField('coverage_info'):
    return

  cov_info = output.corpus_pruning_task_output.coverage_info

  # Use ndb.transaction with retries below to mitigate risk of a race condition.
  def _try_save_coverage_information():
    """Implements save_coverage_information function."""
    coverage_info = data_handler.get_coverage_information(
        cov_info.project_name,
        cov_info.timestamp.ToDatetime().date(),
        create_if_needed=True)

    # Intentionally skip edge and function coverage values as those would come
    # from fuzzer coverage cron task (see src/go/server/cron/coverage.go).
    coverage_info.corpus_size_units = cov_info.corpus_size_units
    coverage_info.corpus_size_bytes = cov_info.corpus_size_bytes
    coverage_info.corpus_location = cov_info.corpus_location
    if cov_info.corpus_backup_location:
      coverage_info.corpus_backup_location = cov_info.corpus_backup_location
    coverage_info.quarantine_size_units = cov_info.quarantine_size_units
    coverage_info.quarantine_size_bytes = cov_info.quarantine_size_bytes
    coverage_info.quarantine_location = cov_info.quarantine_location
    coverage_info.put()

  try:
    ndb.transaction(
        _try_save_coverage_information,
        retries=data_handler.DEFAULT_FAIL_RETRIES)
  except Exception as e:
    # TODO(metzman): Don't catch every exception, it makes testing almost
    # impossible.
    raise CorpusPruningError(
        'Failed to save corpus pruning result: %s.' % repr(e))


def _get_proto_timestamp(initial_timestamp):
  timestamp = timestamp_pb2.Timestamp()  # pylint: disable=no-member
  timestamp.FromDatetime(initial_timestamp)
  return timestamp


def _extract_coverage_information(context, result):
  """Extracts and stores the coverage information in a proto."""
  coverage_info = uworker_msg_pb2.CoverageInformation()  # pylint: disable=no-member
  coverage_info.project_name = context.fuzz_target.project_qualified_name()
  proto_timestamp = _get_proto_timestamp(result.coverage_info.date)
  coverage_info.timestamp.CopyFrom(proto_timestamp)
  # Intentionally skip edge and function coverage values as those would come
  # from fuzzer coverage cron task.
  coverage_info.corpus_size_units = result.coverage_info.corpus_size_units
  coverage_info.corpus_size_bytes = result.coverage_info.corpus_size_bytes
  coverage_info.corpus_location = result.coverage_info.corpus_location
  if result.coverage_info.corpus_backup_location:
    coverage_info.corpus_backup_location = (
        result.coverage_info.corpus_backup_location)
  coverage_info.quarantine_size_units = (
      result.coverage_info.quarantine_size_units)
  coverage_info.quarantine_size_bytes = (
      result.coverage_info.quarantine_size_bytes)
  coverage_info.quarantine_location = result.coverage_info.quarantine_location
  return coverage_info


def utask_main(uworker_input):
  """Execute corpus pruning task."""
  fuzz_target = uworker_io.entity_from_protobuf(
      uworker_input.corpus_pruning_task_input.fuzz_target,
      data_types.FuzzTarget)
  revision = 0  # Trunk revision

  if not setup.update_fuzzer_and_data_bundles(uworker_input.setup_input):
    logs.error(f'Failed to set up fuzzer {fuzz_target.engine}.')
    return uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.ErrorType.CORPUS_PRUNING_FUZZER_SETUP_FAILED)  # pylint: disable=no-member

  cross_pollinate_fuzzers = _get_cross_pollinate_fuzzers_from_protos(
      uworker_input.corpus_pruning_task_input.cross_pollinate_fuzzers)
  context = Context(uworker_input, fuzz_target, cross_pollinate_fuzzers)

  if uworker_input.global_blacklisted_functions:
    leak_blacklist.copy_global_to_local_blacklist(
        uworker_input.corpus_task_input.global_blacklisted_functions)

  uworker_output = None
  try:
    result = do_corpus_pruning(uworker_input, context, revision)
    issue_metadata = engine_common.get_fuzz_target_issue_metadata(fuzz_target)
    issue_metadata = issue_metadata or {}
    _upload_corpus_crashes_zip(
        context, result,
        uworker_input.corpus_pruning_task_input.corpus_crashes_blob_name,
        uworker_input.corpus_pruning_task_input.corpus_crashes_upload_url)
    uworker_output = uworker_msg_pb2.Output(  # pylint: disable=no-member
        corpus_pruning_task_output=uworker_msg_pb2.CorpusPruningTaskOutput(  # pylint: disable=no-member
            coverage_info=_extract_coverage_information(context, result),
            fuzzer_binary_name=result.fuzzer_binary_name,
            crash_revision=result.revision,
            crashes=result.crashes,
            corpus_backup_uploaded=bool(result.coverage_info.corpus_location)),
        issue_metadata=json.dumps(issue_metadata))
    _fill_cross_pollination_stats(result.cross_pollination_stats,
                                  uworker_output)
  except Exception as e:
    # TODO(metzman): Don't catch every exception, it makes testing almost
    # impossible.
    logs.error(f'Corpus pruning failed: {e}')
    uworker_output = uworker_msg_pb2.Output(  # pylint: disable=no-member
        error_type=uworker_msg_pb2.CORPUS_PRUNING_ERROR)  # pylint: disable=no-member
  finally:
    context.cleanup()

  return uworker_output


def handle_corpus_pruning_failures(output: uworker_msg_pb2.Output):  # pylint: disable=no-member
  task_name = (f'corpus_pruning_{output.uworker_input.fuzzer_name}_'
               f'{output.uworker_input.job_type}')
  data_handler.update_task_status(task_name, data_types.TaskState.ERROR)


def _create_backup_urls(fuzz_target: data_types.FuzzTarget,
                        corpus_pruning_task_input):
  """Creates the backup urls if a backup bucket is provided."""
  backup_bucket_name = environment.get_value('BACKUP_BUCKET')
  if not backup_bucket_name:
    logs.info('No backup bucket provided, corpus backup will be skipped.')
    return

  timestamp = str(utils.utcnow().date())
  engine_name = environment.get_value('CORPUS_FUZZER_NAME_OVERRIDE',
                                      fuzz_target.engine)
  dated_backup_gcs_url = corpus_manager.gcs_url_for_backup_file(
      backup_bucket_name, engine_name, fuzz_target.project_qualified_name(),
      timestamp)
  latest_backup_gcs_url = corpus_manager.gcs_url_for_backup_file(
      backup_bucket_name, engine_name, fuzz_target.project_qualified_name(),
      corpus_manager.LATEST_BACKUP_TIMESTAMP)

  dated_backup_signed_url = storage.get_signed_upload_url(dated_backup_gcs_url)

  corpus_pruning_task_input.dated_backup_gcs_url = dated_backup_gcs_url
  corpus_pruning_task_input.latest_backup_gcs_url = latest_backup_gcs_url
  corpus_pruning_task_input.dated_backup_signed_url = dated_backup_signed_url


def utask_preprocess(fuzzer_name, job_type, uworker_env):
  """Runs preprocessing for corpus pruning task."""
  fuzz_target = data_handler.get_fuzz_target(fuzzer_name)

  task_name = f'corpus_pruning_{fuzzer_name}_{job_type}'

  # Get status of last execution.
  last_execution_metadata = data_handler.get_task_status(task_name)
  last_execution_failed = bool(
      last_execution_metadata and
      last_execution_metadata.status == data_types.TaskState.ERROR)

  # Make sure we're the only instance running for the given fuzzer and
  # job_type.
  if not data_handler.update_task_status(task_name,
                                         data_types.TaskState.STARTED):
    logs.info('A previous corpus pruning task is still running, exiting.')
    return None

  setup_input = (
      setup.preprocess_update_fuzzer_and_data_bundles(fuzz_target.engine))

  # TODO(unassigned): Use coverage information for better selection here.
  cross_pollinate_fuzzers = _get_cross_pollinate_fuzzers(
      fuzz_target.engine, fuzzer_name)

  # If our last execution failed, shrink to a randomized corpus of usable size
  # to prevent corpus from growing unbounded and recurring failures when trying
  # to minimize it.
  if last_execution_failed:
    # TODO(metzman): Is this too expensive to do in preprocess?
    corpus_urls = corpus_manager.get_pruning_corpora_urls(
        fuzz_target.engine, fuzz_target.project_qualified_name())
    for corpus_url in corpus_urls:
      _limit_corpus_size(corpus_url)

  corpus, quarantine_corpus = corpus_manager.get_corpuses_for_pruning(
      fuzz_target.engine, fuzz_target.project_qualified_name())

  (corpus_crashes_blob_name,
   corpus_crashes_upload_url) = blobs.get_blob_signed_upload_url()

  corpus_pruning_task_input = uworker_msg_pb2.CorpusPruningTaskInput(  # pylint: disable=no-member
      fuzz_target=uworker_io.entity_to_protobuf(fuzz_target),
      last_execution_failed=last_execution_failed,
      cross_pollinate_fuzzers=cross_pollinate_fuzzers,
      corpus=corpus.proto_corpus,
      quarantine_corpus=quarantine_corpus.proto_corpus,
      corpus_crashes_blob_name=corpus_crashes_blob_name,
      corpus_crashes_upload_url=corpus_crashes_upload_url)

  _create_backup_urls(fuzz_target, corpus_pruning_task_input)

  if environment.get_value('LSAN'):
    # Copy global blacklist into local suppressions file if LSan is enabled.
    setup_input.global_blacklisted_functions.extend(
        leak_blacklist.get_global_blacklisted_functions())

  return uworker_msg_pb2.Input(  # pylint: disable=no-member
      job_type=job_type,
      fuzzer_name=fuzzer_name,
      uworker_env=uworker_env,
      setup_input=setup_input,
      corpus_pruning_task_input=corpus_pruning_task_input)


_ERROR_HANDLER = uworker_handle_errors.CompositeErrorHandler({
    uworker_msg_pb2.ErrorType.CORPUS_PRUNING_FUZZER_SETUP_FAILED:  # pylint: disable=no-member
        uworker_handle_errors.noop_handler,
    uworker_msg_pb2.ErrorType.CORPUS_PRUNING_ERROR:  # pylint: disable=no-member
        handle_corpus_pruning_failures,
})


def _update_latest_backup(output):
  """Updates the latest_backup with the dated_backup uploaded in utask_main
  if any."""
  if not output.corpus_pruning_task_output.corpus_backup_uploaded:
    return

  dated_backup_gcs_url = (
      output.uworker_input.corpus_pruning_task_input.dated_backup_gcs_url)
  latest_backup_gcs_url = (
      output.uworker_input.corpus_pruning_task_input.latest_backup_gcs_url)

  try:
    if not storage.copy_blob(dated_backup_gcs_url, latest_backup_gcs_url):
      logs.error('backup_corpus: Failed to update latest corpus backup at '
                 f'{latest_backup_gcs_url}.')
  except:
    logs.error('backup_corpus: Failed to update latest corpus backup at '
               f'{latest_backup_gcs_url}.')


def utask_postprocess(output):
  """Trusted: Handles errors and writes anything needed to the db."""
  if output.error_type != uworker_msg_pb2.ErrorType.NO_ERROR:  # pylint: disable=no-member
    _ERROR_HANDLER.handle(output)
    return
  task_name = (f'corpus_pruning_{output.uworker_input.fuzzer_name}_'
               f'{output.uworker_input.job_type}')

  _update_latest_backup(output)
  _record_cross_pollination_stats(output)
  _save_coverage_information(output)
  _process_corpus_crashes(output)
  data_handler.update_task_status(task_name, data_types.TaskState.FINISHED)
