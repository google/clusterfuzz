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
from enum import Enum
import os
import random
import shutil

from google.cloud import ndb

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers.libFuzzer import constants
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import task_creation
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_symbolizer
from clusterfuzz._internal.datastore import corpus_tagging
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.fuzzing import leak_blacklist
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
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
TIMEOUT_FLAG = '-timeout=%d' % SINGLE_UNIT_TIMEOUT

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

CorpusCrash = collections.namedtuple('CorpusCrash', [
    'crash_state',
    'crash_type',
    'crash_address',
    'crash_stacktrace',
    'unit_path',
    'security_flag',
])

CrossPollinationStats = collections.namedtuple('CrossPollinationStats', [
    'project_qualified_name', 'method', 'sources', 'tags',
    'initial_corpus_size', 'corpus_size', 'initial_edge_coverage',
    'edge_coverage', 'initial_feature_coverage', 'feature_coverage'
])


class Pollination(str, Enum):
  RANDOM = 'random'
  TAGGED = 'tagged'


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
  for corpus_file in storage.get_blobs(corpus_url):
    corpus_count += 1
    corpus_size += corpus_file['size']
    if (corpus_count > CORPUS_FILES_LIMIT_FOR_FAILURES or
        corpus_size > CORPUS_SIZE_LIMIT_FOR_FAILURES):
      path_to_delete = storage.get_cloud_storage_file_path(
          bucket, corpus_file['name'])
      storage.delete(path_to_delete)
      deleted_corpus_count += 1

  if deleted_corpus_count:
    logs.log('Removed %d files from oversized corpus: %s.' %
             (deleted_corpus_count, corpus_url))


def _get_time_remaining(start_time):
  """Return time remaining."""
  time_used = int((datetime.datetime.utcnow() - start_time).total_seconds())
  return CORPUS_PRUNING_TIMEOUT - time_used


class CorpusPruningException(Exception):
  """Corpus pruning exception."""


class CrossPollinateFuzzer(object):
  """Cross Pollinate Fuzzer."""

  def __init__(self, fuzz_target, backup_bucket_name, corpus_engine_name):
    self.fuzz_target = fuzz_target
    self.backup_bucket_name = backup_bucket_name
    self.corpus_engine_name = corpus_engine_name


class Context(object):
  """Pruning state."""

  def __init__(self,
               fuzz_target,
               cross_pollinate_fuzzers,
               cross_pollination_method=Pollination.RANDOM,
               tag=None):

    self.fuzz_target = fuzz_target
    self.cross_pollinate_fuzzers = cross_pollinate_fuzzers
    self.cross_pollination_method = cross_pollination_method
    self.tag = tag

    self.merge_tmp_dir = None
    self.engine = engine.get(self.fuzz_target.engine)
    if not self.engine:
      raise CorpusPruningException('Engine {} not found'.format(engine))

    self._created_directories = []

    # Set up temporary directories where corpora will be synced to.
    # Initial synced corpus.
    self.initial_corpus_path = self._create_temp_corpus_directory(
        '%s_initial_corpus' % self.fuzz_target.project_qualified_name())
    # Minimized corpus.
    self.minimized_corpus_path = self._create_temp_corpus_directory(
        '%s_minimized_corpus' % self.fuzz_target.project_qualified_name())
    # Synced quarantine corpus.
    self.quarantine_corpus_path = self._create_temp_corpus_directory(
        '%s_quarantine' % self.fuzz_target.project_qualified_name())
    # Synced shared corpus.
    self.shared_corpus_path = self._create_temp_corpus_directory(
        '%s_shared' % self.fuzz_target.project_qualified_name())
    # Bad units.
    self.bad_units_path = self._create_temp_corpus_directory(
        '%s_bad_units' % self.fuzz_target.project_qualified_name())
    self.merge_tmp_dir = self._create_temp_corpus_directory('merge_workdir')

    self.corpus = corpus_manager.FuzzTargetCorpus(
        self.fuzz_target.engine,
        self.fuzz_target.project_qualified_name(),
        include_regressions=True)
    self.quarantine_corpus = corpus_manager.FuzzTargetCorpus(
        self.fuzz_target.engine,
        self.fuzz_target.project_qualified_name(),
        quarantine=True)

    shared_corpus_bucket = environment.get_value('SHARED_CORPUS_BUCKET')
    self.shared_corpus = corpus_manager.GcsCorpus(shared_corpus_bucket)

  def restore_quarantined_units(self):
    """Restore units from the quarantine."""
    logs.log('Restoring units from quarantine.')
    # Limit the number of quarantine units to restore, in case there are a lot.
    quarantine_unit_paths = _get_corpus_file_paths(self.quarantine_corpus_path)
    if len(quarantine_unit_paths) > MAX_QUARANTINE_UNITS_TO_RESTORE:
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
    if not self.corpus.rsync_to_disk(
        self.initial_corpus_path, timeout=SYNC_TIMEOUT):
      raise CorpusPruningException('Failed to sync corpus to disk.')

    if not self.quarantine_corpus.rsync_to_disk(self.quarantine_corpus_path):
      logs.log_error(
          'Failed to sync quarantine corpus to disk.',
          fuzz_target=self.fuzz_target)

    if not self.shared_corpus.rsync_to_disk(self.shared_corpus_path):
      logs.log_error(
          'Failed to sync shared corpus to disk.', fuzz_target=self.fuzz_target)

    self._cross_pollinate_other_fuzzer_corpuses()

  def sync_to_gcs(self):
    """Sync corpora to GCS post merge."""
    if not self.corpus.rsync_from_disk(self.minimized_corpus_path):
      raise CorpusPruningException('Failed to sync minimized corpus to gcs.')

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
        logs.log_warn(
            'Corpus backup does not exist, ignoring: %s.' % corpus_backup_url)
        continue

      if not storage.copy_file_from(corpus_backup_url,
                                    corpus_backup_local_path):
        continue

      corpus_backup_output_directory = os.path.join(self.shared_corpus_path,
                                                    project_qualified_name)
      shell.create_directory(corpus_backup_output_directory)
      result = archive.unpack(corpus_backup_local_path,
                              corpus_backup_output_directory)
      shell.remove_file(corpus_backup_local_path)

      if result:
        logs.log(
            'Corpus backup url %s successfully unpacked into shared corpus.' %
            corpus_backup_url)
      else:
        logs.log_error(
            'Failed to unpack corpus backup from url %s.' % corpus_backup_url)


class Runner(object):
  """Runner for libFuzzer."""

  def __init__(self, build_directory, context):
    self.build_directory = build_directory
    self.context = context

    self.target_path = engine_common.find_fuzzer_path(
        self.build_directory, self.context.fuzz_target.binary)
    if not self.target_path:
      raise CorpusPruningException(
          'Failed to get fuzzer path for %s.' % self.context.fuzz_target.binary)

    self.fuzzer_options = options.get_fuzz_target_options(self.target_path)

  def get_libfuzzer_flags(self):
    """Get default libFuzzer options."""
    rss_limit = RSS_LIMIT
    max_len = engine_common.CORPUS_INPUT_SIZE_LIMIT
    detect_leaks = 1
    arguments = [TIMEOUT_FLAG]

    if self.fuzzer_options:
      # Default values from above can be customized for a given fuzz target.
      libfuzzer_arguments = self.fuzzer_options.get_engine_arguments(
          'libfuzzer')

      custom_rss_limit = libfuzzer_arguments.get(
          'rss_limit_mb', constructor=int)
      if custom_rss_limit and custom_rss_limit < rss_limit:
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

    arguments.append(RSS_LIMIT_MB_FLAG % rss_limit)
    arguments.append(MAX_LEN_FLAG % max_len)
    arguments.append(DETECT_LEAKS_FLAG % detect_leaks)
    arguments.append(constants.VALUE_PROFILE_ARGUMENT)

    return arguments

  def process_sanitizer_options(self):
    """Process sanitizer options overrides."""
    if not self.fuzzer_options:
      return

    # Only need to look as ASan, as that's what we prune with.
    overrides = self.fuzzer_options.get_asan_options()
    if not overrides:
      return

    asan_options = environment.get_memory_tool_options('ASAN_OPTIONS')
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


class CorpusPruner(object):
  """Class that handles corpus pruning."""

  def __init__(self, runner):
    self.runner = runner
    self.context = self.runner.context

  def _run_single_unit(self, unit_path):
    """Run a single unit, and return the result."""
    arguments = self.runner.get_libfuzzer_flags()
    return self.runner.reproduce(unit_path, arguments, SINGLE_UNIT_TIMEOUT)

  def _quarantine_unit(self, unit_path, quarantine_corpus_path):
    """Moves the given unit to the quarantine, and returns the path to the unit
    in the quarantine."""
    quarantined_unit_path = os.path.join(quarantine_corpus_path,
                                         os.path.basename(unit_path))
    shutil.move(unit_path, quarantined_unit_path)

    return quarantined_unit_path

  def process_bad_units(self, bad_units_path, quarantine_corpus_path, crashes):
    """Process bad units found during merge."""
    # TODO(ochang): A lot of this function is similar to parts of fuzz_task.
    # Ideally fuzz_task can be refactored in a way that lets us share the common
    # code.

    environment.reset_current_memory_tool_options(redzone_size=DEFAULT_REDZONE)
    self.runner.process_sanitizer_options()

    logs.log('Processing bad units.')
    corpus_file_paths = _get_corpus_file_paths(bad_units_path)
    num_bad_units = 0

    # Run each corpus item individually.
    for i, unit_path in enumerate(corpus_file_paths, 1):
      if i % 100 == 0:
        logs.log('Up to %d' % i)

      unit_name = os.path.basename(unit_path)
      if unit_name.startswith('timeout-') or unit_name.startswith('oom-'):
        # Don't waste time re-running timeout or oom testcases.
        self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      try:
        result = self._run_single_unit(unit_path)
      except TimeoutError:
        # Slow unit. Quarantine it.
        self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      if not crash_analyzer.is_memory_tool_crash(result.output):
        # Didn't crash.
        continue

      # Get memory tool crash information.
      state = stack_analyzer.get_crash_data(result.output, symbolize_flag=True)

      # Crashed or caused a leak. Quarantine it.
      unit_path = self._quarantine_unit(unit_path, quarantine_corpus_path)
      num_bad_units += 1

      if crash_analyzer.ignore_stacktrace(state.crash_stacktrace):
        continue

      # Local de-duplication.
      if state.crash_state not in crashes:
        security_flag = crash_analyzer.is_security_issue(
            state.crash_stacktrace, state.crash_type, state.crash_address)
        crashes[state.crash_state] = CorpusCrash(
            state.crash_state, state.crash_type, state.crash_address,
            state.crash_stacktrace, unit_path, security_flag)

    logs.log('Found %d bad units, %d unique crashes.' % (num_bad_units,
                                                         len(crashes)))

  def run(self, initial_corpus_path, minimized_corpus_path, bad_units_path):
    """Run corpus pruning. Output result to directory."""
    if not shell.get_directory_file_count(initial_corpus_path):
      # Empty corpus, nothing to do.
      return None

    # Set memory tool options and fuzzer arguments.
    engine_common.unpack_seed_corpus_if_needed(
        self.runner.target_path, initial_corpus_path, force_unpack=True)

    environment.reset_current_memory_tool_options(
        redzone_size=MIN_REDZONE, leaks=True)
    self.runner.process_sanitizer_options()
    additional_args = self.runner.get_libfuzzer_flags()

    # Execute fuzzer with arguments for corpus pruning.
    logs.log('Running merge...')
    try:
      result = self.runner.minimize_corpus(
          additional_args, [initial_corpus_path], minimized_corpus_path,
          bad_units_path, CORPUS_PRUNING_TIMEOUT)
    except TimeoutError as e:
      raise CorpusPruningException(
          'Corpus pruning timed out while minimizing corpus\n' + repr(e))
    except engine.Error as e:
      raise CorpusPruningException(
          'Corpus pruning failed to minimize corpus\n' + repr(e))

    symbolized_output = stack_symbolizer.symbolize_stacktrace(result.logs)

    # Sanity check that there are files in minimized corpus after merging.
    if not shell.get_directory_file_count(minimized_corpus_path):
      raise CorpusPruningException(
          'Corpus pruning failed to minimize corpus\n' + symbolized_output)

    logs.log('Corpus merge finished successfully.', output=symbolized_output)

    return result.stats


class CrossPollinator(object):
  """Cross pollination."""

  def __init__(self, runner):
    self.runner = runner
    self.context = self.runner.context

  def run(self, timeout):
    """Merge testcases from corpus from other fuzz targets."""
    if not shell.get_directory_file_count(self.context.shared_corpus_path):
      logs.log('No files found in shared corpus, skip merge.')
      return None

    # Run pruning on the shared corpus and log the result in case of error.
    logs.log('Merging shared corpus...')
    environment.reset_current_memory_tool_options(redzone_size=DEFAULT_REDZONE)
    self.runner.process_sanitizer_options()

    additional_args = self.runner.get_libfuzzer_flags()

    try:
      result = self.runner.minimize_corpus(additional_args,
                                           [self.context.shared_corpus_path],
                                           self.context.minimized_corpus_path,
                                           self.context.bad_units_path, timeout)
      symbolized_output = stack_symbolizer.symbolize_stacktrace(result.logs)
      logs.log(
          'Shared corpus merge finished successfully.',
          output=symbolized_output)
    except TimeoutError as e:
      # Other cross pollinated fuzzer corpuses can have unexpected test cases
      # that time us out. This is expected, so bail out.
      logs.log_warn('Corpus pruning timed out while merging shared corpus\n' +
                    repr(e))
      return None
    except engine.Error as e:
      # Other cross pollinated fuzzer corpuses can be large, so we can run out
      # of disk space and exception out. This is expected, so bail out.
      logs.log_warn('Corpus pruning failed to merge shared corpus\n' + repr(e))
      return None

    return result.stats


def _record_cross_pollination_stats(stats):
  """Log stats about cross pollination in BigQuery."""
  # If no stats were gathered due to a timeout or lack of corpus, return.
  if not stats:
    return

  bigquery_row = {
      'project_qualified_name': stats.project_qualified_name,
      'method': stats.method,
      'sources': stats.sources,
      'tags': stats.tags if stats.tags else '',
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


def do_corpus_pruning(context, last_execution_failed, revision):
  """Run corpus pruning."""
  # Set |FUZZ_TARGET| environment variable to help with unarchiving only fuzz
  # target and its related files.
  environment.set_value('FUZZ_TARGET', context.fuzz_target.binary)

  if environment.is_trusted_host():
    from clusterfuzz._internal.bot.untrusted_runner import tasks_host
    return tasks_host.do_corpus_pruning(context, last_execution_failed,
                                        revision)

  if not build_manager.setup_build(revision=revision):
    raise CorpusPruningException('Failed to setup build.')

  build_directory = environment.get_value('BUILD_DIR')
  start_time = datetime.datetime.utcnow()
  runner = Runner(build_directory, context)
  pruner = CorpusPruner(runner)
  fuzzer_binary_name = os.path.basename(runner.target_path)

  # If our last execution failed, shrink to a randomized corpus of usable size
  # to prevent corpus from growing unbounded and recurring failures when trying
  # to minimize it.
  if last_execution_failed:
    for corpus_url in [
        context.corpus.get_gcs_url(),
        context.quarantine_corpus.get_gcs_url()
    ]:
      _limit_corpus_size(corpus_url)

  # Get initial corpus to process from GCS.
  context.sync_to_disk()
  initial_corpus_size = shell.get_directory_file_count(
      context.initial_corpus_path)

  # Restore a small batch of quarantined units back to corpus.
  context.restore_quarantined_units()

  # Shrink to a minimized corpus using corpus merge.
  pruner_stats = pruner.run(context.initial_corpus_path,
                            context.minimized_corpus_path,
                            context.bad_units_path)

  # Sync minimized corpus back to GCS.
  context.sync_to_gcs()

  # Create corpus backup.
  # Temporarily copy the past crash regressions folder into the minimized corpus
  # so that corpus backup archive can have both.
  regressions_input_dir = os.path.join(context.initial_corpus_path,
                                       'regressions')
  regressions_output_dir = os.path.join(context.minimized_corpus_path,
                                        'regressions')
  if shell.get_directory_file_count(regressions_input_dir):
    shutil.copytree(regressions_input_dir, regressions_output_dir)
  backup_bucket = environment.get_value('BACKUP_BUCKET')
  corpus_backup_url = corpus_manager.backup_corpus(
      backup_bucket, context.corpus, context.minimized_corpus_path)
  shell.remove_directory(regressions_output_dir)

  minimized_corpus_size_units = shell.get_directory_file_count(
      context.minimized_corpus_path)
  minimized_corpus_size_bytes = shell.get_directory_size(
      context.minimized_corpus_path)

  logs.log('Corpus pruned from %d to %d units.' % (initial_corpus_size,
                                                   minimized_corpus_size_units))

  # Process bad units found during merge.
  # Mapping of crash state -> CorpusCrash
  crashes = {}
  pruner.process_bad_units(context.bad_units_path,
                           context.quarantine_corpus_path, crashes)
  context.quarantine_corpus.rsync_from_disk(context.quarantine_corpus_path)

  # Store corpus stats into CoverageInformation entity.
  project_qualified_name = context.fuzz_target.project_qualified_name()
  today = datetime.datetime.utcnow().date()
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
  coverage_info.corpus_backup_location = corpus_backup_url
  coverage_info.corpus_location = context.corpus.get_gcs_url()
  coverage_info.quarantine_location = context.quarantine_corpus.get_gcs_url()

  # Calculate remaining time to use for shared corpus merging.
  time_remaining = _get_time_remaining(start_time)
  if time_remaining <= 0:
    logs.log_warn('Not enough time for shared corpus merging.')
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

  logs.log('Finished.')

  sources = ','.join([
      fuzzer.fuzz_target.project_qualified_name()
      for fuzzer in context.cross_pollinate_fuzzers
  ])

  cross_pollination_stats = None
  if pruner_stats and pollinator_stats:
    cross_pollination_stats = CrossPollinationStats(
        project_qualified_name, context.cross_pollination_method, sources,
        context.tag, initial_corpus_size, pre_pollination_corpus_size,
        pruner_stats['edge_coverage'], pollinator_stats['edge_coverage'],
        pruner_stats['feature_coverage'], pollinator_stats['feature_coverage'])

  return CorpusPruningResult(
      coverage_info=coverage_info,
      crashes=list(crashes.values()),
      fuzzer_binary_name=fuzzer_binary_name,
      revision=environment.get_value('APP_REVISION'),
      cross_pollination_stats=cross_pollination_stats)


def _process_corpus_crashes(context, result):
  """Process crashes found in the corpus."""
  # Default Testcase entity values.
  crash_revision = result.revision
  job_type = environment.get_value('JOB_NAME')
  minimized_arguments = '%TESTCASE% ' + context.fuzz_target.binary
  project_name = data_handler.get_project_name(job_type)

  comment = 'Fuzzer %s generated corpus testcase crashed (r%s)' % (
      context.fuzz_target.project_qualified_name(), crash_revision)

  # Generate crash reports.
  for crash in result.crashes:
    existing_testcase = data_handler.find_testcase(
        project_name, crash.crash_type, crash.crash_state, crash.security_flag)
    if existing_testcase:
      continue

    # Upload/store testcase.
    if environment.is_trusted_host():
      from clusterfuzz._internal.bot.untrusted_runner import file_host
      unit_path = os.path.join(context.bad_units_path,
                               os.path.basename(crash.unit_path))
      # Prevent the worker from escaping out of |context.bad_units_path|.
      if not file_host.is_directory_parent(unit_path, context.bad_units_path):
        raise CorpusPruningException('Invalid units path from worker.')

      file_host.copy_file_from_worker(crash.unit_path, unit_path)
    else:
      unit_path = crash.unit_path

    with open(unit_path, 'rb') as f:
      key = blobs.write_blob(f)

    # Set the absolute_path property of the Testcase to a file in FUZZ_INPUTS
    # instead of the local quarantine directory.
    absolute_testcase_path = os.path.join(
        environment.get_value('FUZZ_INPUTS'), 'testcase')

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
        fuzzer_name=context.fuzz_target.engine,
        fully_qualified_fuzzer_name=context.fuzz_target.fully_qualified_name(),
        job_type=job_type,
        archived=False,
        archive_filename='',
        binary_flag=True,
        http_flag=False,
        gestures=None,
        redzone=DEFAULT_REDZONE,
        disable_ubsan=False,
        minidump_keys=None,
        window_argument=None,
        timeout_multiplier=1.0,
        minimized_arguments=minimized_arguments)

    # Set fuzzer_binary_name in testcase metadata.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.set_metadata('fuzzer_binary_name', result.fuzzer_binary_name)

    issue_metadata = engine_common.get_all_issue_metadata_for_testcase(testcase)
    if issue_metadata:
      for key, value in issue_metadata.items():
        testcase.set_metadata(key, value, update_testcase=False)

      testcase.put()

    # Create additional tasks for testcase (starting with minimization).
    testcase = data_handler.get_testcase_by_id(testcase_id)
    task_creation.create_tasks(testcase)


def _select_targets_and_jobs_for_pollination(engine_name, current_fuzzer_name,
                                             method, tag):
  """Select jobs to use for cross pollination."""
  target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(engine=engine_name))

  if method == Pollination.TAGGED:
    similar_tagged_targets = [
        target.fully_qualified_fuzz_target_name
        for target in corpus_tagging.get_targets_with_tag(tag)
        if target.fully_qualified_fuzz_target_name != current_fuzzer_name
    ]
    # Intersect target_jobs and similar_tagged_targets on fully qualified
    # fuzz target name.
    target_jobs = [
        target for target in target_jobs
        if target.fuzz_target_name in similar_tagged_targets
    ]

  targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(target_jobs)

  targets_and_jobs = [(target, target_job)
                      for target, target_job in zip(targets, target_jobs)
                      if target_job.fuzz_target_name != current_fuzzer_name]
  selected_targets_and_jobs = random.SystemRandom().sample(
      targets_and_jobs, min(
          len(targets_and_jobs), CROSS_POLLINATE_FUZZER_COUNT))

  return selected_targets_and_jobs


def _get_cross_pollinate_fuzzers(engine_name, current_fuzzer_name, method, tag):
  """Return a list of fuzzer objects to use for cross pollination."""
  cross_pollinate_fuzzers = []

  selected_targets_and_jobs = _select_targets_and_jobs_for_pollination(
      engine_name, current_fuzzer_name, method, tag)

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
        CrossPollinateFuzzer(
            target,
            backup_bucket_name,
            corpus_engine_name,
        ))

  return cross_pollinate_fuzzers


def _save_coverage_information(context, result):
  """Saves coverage information in datastore using an atomic transaction."""

  # Use ndb.transaction with retries below to mitigate risk of a race condition.
  def _try_save_coverage_information():
    """Implements save_coverage_information function."""
    coverage_info = data_handler.get_coverage_information(
        context.fuzz_target.project_qualified_name(),
        result.coverage_info.date,
        create_if_needed=True)

    # Intentionally skip edge and function coverage values as those would come
    # from fuzzer coverage cron task (see src/go/server/cron/coverage.go).
    coverage_info.corpus_size_units = result.coverage_info.corpus_size_units
    coverage_info.corpus_size_bytes = result.coverage_info.corpus_size_bytes
    coverage_info.corpus_location = result.coverage_info.corpus_location
    coverage_info.corpus_backup_location = (
        result.coverage_info.corpus_backup_location)
    coverage_info.quarantine_size_units = (
        result.coverage_info.quarantine_size_units)
    coverage_info.quarantine_size_bytes = (
        result.coverage_info.quarantine_size_bytes)
    coverage_info.quarantine_location = result.coverage_info.quarantine_location
    coverage_info.put()

  try:
    ndb.transaction(
        _try_save_coverage_information,
        retries=data_handler.DEFAULT_FAIL_RETRIES)
  except Exception as e:
    raise CorpusPruningException(
        'Failed to save corpus pruning result: %s.' % repr(e))


def choose_cross_pollination_strategy(current_fuzzer_name):
  """Chooses cross pollination strategy. In seperate function to mock for
    predictable test behaviror."""
  method = random.choice([Pollination.RANDOM, Pollination.TAGGED])
  if method == Pollination.TAGGED:
    similar_targets = corpus_tagging.get_similarly_tagged_fuzzers(
        current_fuzzer_name)
    if similar_targets:
      return (Pollination.TAGGED, random.choice(list(similar_targets.keys())))

  return (Pollination.RANDOM, None)


def execute_task(full_fuzzer_name, job_type):
  """Execute corpus pruning task."""
  fuzz_target = data_handler.get_fuzz_target(full_fuzzer_name)
  task_name = 'corpus_pruning_%s_%s' % (full_fuzzer_name, job_type)
  revision = 0  # Trunk revision

  # Get status of last execution.
  last_execution_metadata = data_handler.get_task_status(task_name)
  last_execution_failed = (
      last_execution_metadata and
      last_execution_metadata.status == data_types.TaskState.ERROR)

  # Make sure we're the only instance running for the given fuzzer and
  # job_type.
  if not data_handler.update_task_status(task_name,
                                         data_types.TaskState.STARTED):
    logs.log('A previous corpus pruning task is still running, exiting.')
    return

  # Setup fuzzer and data bundle.
  if not setup.update_fuzzer_and_data_bundles(fuzz_target.engine):
    raise CorpusPruningException(
        'Failed to set up fuzzer %s.' % fuzz_target.engine)

  cross_pollination_method, tag = choose_cross_pollination_strategy(
      full_fuzzer_name)

  # TODO(unassigned): Use coverage information for better selection here.
  cross_pollinate_fuzzers = _get_cross_pollinate_fuzzers(
      fuzz_target.engine, full_fuzzer_name, cross_pollination_method, tag)

  context = Context(fuzz_target, cross_pollinate_fuzzers,
                    cross_pollination_method, tag)

  # Copy global blacklist into local suppressions file if LSan is enabled.
  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # TODO(ochang): Copy this to untrusted worker.
    leak_blacklist.copy_global_to_local_blacklist()

  try:
    result = do_corpus_pruning(context, last_execution_failed, revision)
    _record_cross_pollination_stats(result.cross_pollination_stats)
    _save_coverage_information(context, result)
    _process_corpus_crashes(context, result)
  except Exception:
    logs.log_error('Corpus pruning failed.')
    data_handler.update_task_status(task_name, data_types.TaskState.ERROR)
    return
  finally:
    context.cleanup()

  data_handler.update_task_status(task_name, data_types.TaskState.FINISHED)
