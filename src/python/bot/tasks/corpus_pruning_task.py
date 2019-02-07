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
import os
import random
import shutil

from base import utils
from bot.fuzzers import engine_common
from bot.fuzzers import libfuzzer
from bot.fuzzers import options
from bot.tasks import setup
from bot.tasks import task_creation
from build_management import build_manager
from build_management import revisions
from crash_analysis import crash_analyzer
from crash_analysis.stack_parsing import stack_analyzer
from crash_analysis.stack_parsing import stack_symbolizer
from datastore import data_handler
from datastore import data_types
from datastore import fuzz_target_utils
from datastore import ndb
from fuzzing import corpus_manager
from fuzzing import leak_blacklist
from google_cloud_utils import blobs
from google_cloud_utils import storage
from metrics import logs
from system import archive
from system import environment
from system import minijail
from system import shell

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

# Corpus size limit for cases when corpus pruning task failed in the last
# execution.
CORPUS_SIZE_LIMIT_FOR_FAILURES = 10000

# Maximum number of units to restore from quarantine in one run.
MAX_QUARANTINE_UNITS_TO_RESTORE = 128

# Memory limits for testcase.
RSS_LIMIT = 2048
RSS_LIMIT_MB_FLAG = '-rss_limit_mb=%d'

# Flag to disable leak checking.
DISABLE_LEAK_CHECK_FLAG = '-detect_leaks=0'

# Flag to do value profile during merges.
USE_VALUE_PROFILE_FLAG = '-use_value_profile=%d'

# Corpus size limit to allow use of value profile. This prevents corpus from
# growing unbounded.
CORPUS_SIZE_LIMIT_FOR_VALUE_PROFILE = 50000

# Longer than default sync timeout to fix broken (overly large) corpora without
# losing coverage.
SYNC_TIMEOUT = 2 * 60 * 60

# Number of fuzz targets whose backup corpus is used to cross pollinate with our
# current fuzz target corpus.
CROSS_POLLINATE_FUZZER_COUNT = 5

CorpusPruningResult = collections.namedtuple(
    'CorpusPruningResult',
    ['coverage_info', 'crashes', 'fuzzer_binary_name', 'revision'])

CorpusCrash = collections.namedtuple('CorpusCrash', [
    'crash_state',
    'crash_type',
    'crash_address',
    'crash_stacktrace',
    'unit_path',
    'security_flag',
])


def _get_corpus_file_paths(corpus_path):
  """Return full paths to corpus files in |corpus_path|."""
  return [
      os.path.join(corpus_path, filename)
      for filename in os.listdir(corpus_path)
  ]


def _limit_corpus_size(corpus_directory, size_limit):
  """Limit number of files in a corpus directory."""
  files_list = os.listdir(corpus_directory)
  corpus_size = len(files_list)

  if corpus_size <= size_limit:
    # Corpus directory size is within limit, no more work to do.
    return

  files_to_delete = random.sample(files_list, corpus_size - size_limit)
  for file_to_delete in files_to_delete:
    file_to_delete_full_path = os.path.join(corpus_directory, file_to_delete)
    shell.remove_file(file_to_delete_full_path)


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

  def __init__(self, fuzz_target, cross_pollinate_fuzzers, use_minijail):
    self.fuzz_target = fuzz_target
    self.cross_pollinate_fuzzers = cross_pollinate_fuzzers
    self.use_minijail = use_minijail

    self.merge_tmp_dir = None
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
    if not self.use_minijail:
      self.merge_tmp_dir = self._create_temp_corpus_directory('merge_workdir')

    self.corpus = corpus_manager.FuzzTargetCorpus(
        self.fuzz_target.engine, self.fuzz_target.project_qualified_name())
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
    shell.create_directory_if_needed(directory_path)
    self._created_directories.append(directory_path)

    return directory_path

  def sync_to_disk(self):
    """Sync required corpora to disk."""
    if not self.corpus.rsync_to_disk(
        self.initial_corpus_path, timeout=SYNC_TIMEOUT):
      raise CorpusPruningException('Failed to sync corpus to disk.')

    if not self.quarantine_corpus.rsync_to_disk(self.quarantine_corpus_path):
      raise CorpusPruningException('Failed to sync quarantine corpus to disk.')

    if not self.shared_corpus.rsync_to_disk(self.shared_corpus_path):
      raise CorpusPruningException('Failed to sync shared corpus to disk.')
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
      shell.create_directory_if_needed(corpus_backup_output_directory)
      archive.unpack(corpus_backup_local_path, corpus_backup_output_directory)
      shell.remove_file(corpus_backup_local_path)

      if not shell.get_directory_file_count(corpus_backup_output_directory):
        logs.log_error(
            'Failed to unpack corpus backup from url %s.' % corpus_backup_url)
      else:
        logs.log(
            'Corpus backup url %s successfully unpacked into shared corpus.' %
            corpus_backup_url)


class Runner(object):
  """Runner for libFuzzer."""

  def __init__(self, build_directory, context):
    self.build_directory = build_directory
    self.context = context

    self.fuzzer_path = engine_common.find_fuzzer_path(
        self.build_directory, self.context.fuzz_target.binary)
    if not self.fuzzer_path:
      raise CorpusPruningException(
          'Failed to get fuzzer path for %s.' % self.context.fuzz_target.binary)

    fuzz_inputs_disk = environment.get_value('FUZZ_INPUTS_DISK')
    self.runner = libfuzzer.get_runner(
        self.fuzzer_path, temp_dir=fuzz_inputs_disk)

    if context.use_minijail:
      self.runner.chroot.add_binding(
          minijail.ChrootBinding(self.context.initial_corpus_path, '/corpus',
                                 False))
      self.runner.chroot.add_binding(
          minijail.ChrootBinding(self.context.minimized_corpus_path, '/min',
                                 True))
      self.runner.chroot.add_binding(
          minijail.ChrootBinding(self.context.shared_corpus_path, '/shared',
                                 False))
      self.runner.chroot.add_binding(
          minijail.ChrootBinding(self.context.bad_units_path, '/bad_units',
                                 True))

    self.fuzzer_options = options.get_fuzz_target_options(self.fuzzer_path)

  def get_libfuzzer_flags(self):
    """Get default libFuzzer options."""
    if self.fuzzer_options:
      libfuzzer_arguments = self.fuzzer_options.get_engine_arguments(
          'libfuzzer')

      # Allow some flags to be used from .options file for single unit testing.
      # Allow specifying a lower rss_limit.
      rss_limit = libfuzzer_arguments.get('rss_limit_mb', constructor=int)
      if not rss_limit or rss_limit > RSS_LIMIT:
        rss_limit = RSS_LIMIT

      # Some targets might falsely report leaks all the time, so allow this to
      # be disabled.
      detect_leaks = libfuzzer_arguments.get('detect_leaks', default='1')
      arguments = [
          RSS_LIMIT_MB_FLAG % rss_limit,
          '-detect_leaks=%s' % detect_leaks, TIMEOUT_FLAG
      ]
    else:
      arguments = [RSS_LIMIT_MB_FLAG % RSS_LIMIT, TIMEOUT_FLAG]

    corpus_size = shell.get_directory_file_count(
        self.context.initial_corpus_path)
    use_value_profile = int(corpus_size <= CORPUS_SIZE_LIMIT_FOR_VALUE_PROFILE)
    arguments.append(USE_VALUE_PROFILE_FLAG % use_value_profile)

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

  def run_single_testcase(self, *args, **kwargs):
    return self.runner.run_single_testcase(*args, **kwargs)

  def merge(self, *args, **kwargs):
    return self.runner.merge(*args, **kwargs)


class CorpusPruner(object):
  """Class that handles corpus pruning."""

  def __init__(self, runner):
    self.runner = runner
    self.context = self.runner.context

  def _run_single_unit(self, unit_path):
    """Run a single unit, and return the result."""
    arguments = self.runner.get_libfuzzer_flags()
    return self.runner.run_single_testcase(
        unit_path, additional_args=arguments, timeout=SINGLE_UNIT_TIMEOUT)

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
        unit_path = self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      result = self._run_single_unit(unit_path)

      if (not result.timed_out and
          not crash_analyzer.is_memory_tool_crash(result.output)):
        # Didn't crash or time out.
        continue

      if result.timed_out:
        # Slow unit. Quarantine it.
        unit_path = self._quarantine_unit(unit_path, quarantine_corpus_path)
        num_bad_units += 1
        continue

      # Get memory tool crash information.
      state = stack_analyzer.get_crash_data(result.output, symbolize_flag=True)

      # Crashed or caused a leak. Quarantine it.
      unit_path = self._quarantine_unit(unit_path, quarantine_corpus_path)
      num_bad_units += 1

      if crash_analyzer.ignore_stacktrace(state.crash_state, state.crash_type):
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
      return

    # Set memory tool options and fuzzer arguments.
    engine_common.unpack_seed_corpus_if_needed(
        self.runner.fuzzer_path, initial_corpus_path, force_unpack=True)

    environment.reset_current_memory_tool_options(
        redzone_size=MIN_REDZONE, leaks=True)
    self.runner.process_sanitizer_options()
    additional_args = self.runner.get_libfuzzer_flags()

    # Execute fuzzer with arguments for corpus pruning.
    logs.log('Running merge...')
    result = self.runner.merge(
        [minimized_corpus_path, initial_corpus_path],
        CORPUS_PRUNING_TIMEOUT,
        artifact_prefix=bad_units_path,
        tmp_dir=self.context.merge_tmp_dir,
        additional_args=additional_args)

    # Sanity check that we didn't time out.
    symbolized_output = stack_symbolizer.symbolize_stacktrace(result.output)
    if result.timed_out:
      raise CorpusPruningException(
          'Corpus pruning timed out while merging corpus: %s.' %
          symbolized_output)
    # Sanity check that we didn't error out and there are files in minimized
    # corpus after merging.
    if (result.return_code or
        not shell.get_directory_file_count(minimized_corpus_path)):
      raise CorpusPruningException(
          'Corpus pruning failed to merge corpus: %s.' % symbolized_output)
    logs.log('Corpus merge finished successfully.', output=symbolized_output)


class CrossPollinator(object):
  """Cross pollination."""

  def __init__(self, runner):
    self.runner = runner
    self.context = self.runner.context

  def run(self, timeout):
    """Merge testcases from corpus from other fuzz targets."""
    if not shell.get_directory_file_count(self.context.shared_corpus_path):
      logs.log('No files found in shared corpus, skip merge.')
      return

    # Run pruning on the shared corpus and log the result in case of error.
    logs.log('Merging shared corpus...')
    environment.reset_current_memory_tool_options(redzone_size=DEFAULT_REDZONE)
    self.runner.process_sanitizer_options()

    additional_args = self.runner.get_libfuzzer_flags()

    result = self.runner.merge(
        [self.context.minimized_corpus_path, self.context.shared_corpus_path],
        timeout,
        artifact_prefix=self.context.bad_units_path,
        tmp_dir=self.context.merge_tmp_dir,
        additional_args=additional_args)

    symbolized_output = stack_symbolizer.symbolize_stacktrace(result.output)
    if result.timed_out:
      logs.log_error('Corpus pruning timed out while merging shared corpus: %s.'
                     % symbolized_output)
    elif result.return_code:
      logs.log_error('Corpus pruning failed to merge shared corpus: %s.' %
                     symbolized_output)
    else:
      logs.log(
          'Shared corpus merge finished successfully.',
          output=symbolized_output)


def do_corpus_pruning(context, last_execution_failed, revision):
  """Run corpus pruning."""
  # Set |FUZZ_TARGET| environment variable to help with unarchiving only fuzz
  # target and its related files.
  environment.set_value('FUZZ_TARGET', context.fuzz_target.binary)

  if environment.is_trusted_host():
    from bot.untrusted_runner import tasks_host
    return tasks_host.do_corpus_pruning(context, last_execution_failed,
                                        revision)

  build_manager.setup_build(revision=revision)
  build_directory = environment.get_value('BUILD_DIR')
  if not build_directory:
    raise CorpusPruningException('Failed to setup build.')

  start_time = datetime.datetime.utcnow()
  runner = Runner(build_directory, context)
  pruner = CorpusPruner(runner)
  fuzzer_binary_name = os.path.basename(runner.fuzzer_path)

  # Get initial corpus to process from GCS.
  context.sync_to_disk()
  initial_corpus_size = shell.get_directory_file_count(
      context.initial_corpus_path)

  # If our last execution failed, shrink to a randomized corpus of usable size
  # to prevent corpus from growing unbounded and recurring failures when trying
  # to minimize it.
  if last_execution_failed:
    _limit_corpus_size(context.initial_corpus_path,
                       CORPUS_SIZE_LIMIT_FOR_FAILURES)

  # Restore a small batch of quarantined units back to corpus.
  context.restore_quarantined_units()

  # Shrink to a minimized corpus using corpus merge.
  pruner.run(context.initial_corpus_path, context.minimized_corpus_path,
             context.bad_units_path)

  # Sync minimized corpus back to GCS.
  context.sync_to_gcs()

  # Create corpus backup.
  backup_bucket = environment.get_value('BACKUP_BUCKET')
  corpus_backup_url = corpus_manager.backup_corpus(
      backup_bucket, context.corpus, context.minimized_corpus_path)

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
  cross_pollinator.run(time_remaining)

  context.sync_to_gcs()

  # Update corpus size stats.
  minimized_corpus_size_units = shell.get_directory_file_count(
      context.minimized_corpus_path)
  minimized_corpus_size_bytes = shell.get_directory_size(
      context.minimized_corpus_path)
  coverage_info.corpus_size_units = minimized_corpus_size_units
  coverage_info.corpus_size_bytes = minimized_corpus_size_bytes

  logs.log('Finished.')

  result = CorpusPruningResult(
      coverage_info=coverage_info,
      crashes=crashes.values(),
      fuzzer_binary_name=fuzzer_binary_name,
      revision=environment.get_value('APP_REVISION'))

  return result


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
      from bot.untrusted_runner import file_host
      unit_path = os.path.join(context.bad_units_path,
                               os.path.basename(crash.unit_path))
      # Prevent the worker from escaping out of |context.bad_units_path|.
      if not file_host.is_directory_parent(unit_path, context.bad_units_path):
        raise CorpusPruningException('Invalid units path from worker.')

      file_host.copy_file_from_worker(crash.unit_path, unit_path)
    else:
      unit_path = crash.unit_path

    with open(unit_path) as f:
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
        minidump_keys=None,
        window_argument=None,
        timeout_multiplier=1.0,
        minimized_arguments=minimized_arguments)

    # Set fuzzer_binary_name in testcase metadata.
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.set_metadata('fuzzer_binary_name', result.fuzzer_binary_name)

    # Create additional tasks for testcase (starting with minimization).
    testcase = data_handler.get_testcase_by_id(testcase_id)
    task_creation.create_tasks(testcase)


def _get_cross_pollinate_fuzzers(engine, current_fuzzer_name):
  """Return a list of fuzzer objects to use for cross pollination."""
  cross_pollinate_fuzzers = {}

  target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(engine=engine))
  targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(target_jobs)

  for target, target_job in zip(targets, target_jobs):
    if (target_job.fuzz_target_name == current_fuzzer_name or
        target_job.fuzz_target_name in cross_pollinate_fuzzers):
      continue

    job = data_types.Job.query(data_types.Job.name == target_job.job).get()
    if not job:
      continue

    backup_bucket_name = job.get_environment().get('BACKUP_BUCKET')
    if not backup_bucket_name:
      continue

    corpus_engine_name = job.get_environment().get(
        'CORPUS_FUZZER_NAME_OVERRIDE', engine)

    cross_pollinate_fuzzers[target_job.fuzz_target_name] = CrossPollinateFuzzer(
        target,
        backup_bucket_name,
        corpus_engine_name,
    )

  return random.SystemRandom().sample(
      cross_pollinate_fuzzers.values(),
      min(len(cross_pollinate_fuzzers), CROSS_POLLINATE_FUZZER_COUNT))


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
        'Failed to save corpus pruning result: %s.' % str(e))


def execute_task(fuzzer_name_and_revision, job_type):
  """Execute corpus pruning task."""
  if '@' in fuzzer_name_and_revision:
    full_fuzzer_name, revision = fuzzer_name_and_revision.split('@')
    revision = revisions.convert_revision_to_integer(revision)
  else:
    full_fuzzer_name = fuzzer_name_and_revision
    revision = 0

  fuzz_target = data_handler.get_fuzz_target(full_fuzzer_name)
  task_name = 'corpus_pruning_%s_%s' % (full_fuzzer_name, job_type)

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

  use_minijail = environment.get_value('USE_MINIJAIL')

  # TODO(unassigned): Use coverage information for better selection here.
  cross_pollinate_fuzzers = _get_cross_pollinate_fuzzers(
      fuzz_target.engine, full_fuzzer_name)

  context = Context(fuzz_target, cross_pollinate_fuzzers, use_minijail)

  # Copy global blacklist into local suppressions file if LSan is enabled.
  is_lsan_enabled = environment.get_value('LSAN')
  if is_lsan_enabled:
    # TODO(ochang): Copy this to untrusted worker.
    leak_blacklist.copy_global_to_local_blacklist()

  try:
    result = do_corpus_pruning(context, last_execution_failed, revision)
    _save_coverage_information(context, result)
    _process_corpus_crashes(context, result)
  except CorpusPruningException as e:
    logs.log_error('Corpus pruning failed: %s.' % str(e))
    data_handler.update_task_status(task_name, data_types.TaskState.ERROR)
    return
  finally:
    context.cleanup()

  data_handler.update_task_status(task_name, data_types.TaskState.FINISHED)
