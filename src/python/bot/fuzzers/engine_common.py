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
"""Common functionality for engine fuzzers (ie: libFuzzer or AFL)."""

from __future__ import print_function

import contextlib
import glob
import os
import pipes
import random
import shutil
import sys
import time

from base import utils
from bot.fuzzers import options
from bot.fuzzers import strategy
from bot.fuzzers import utils as fuzzer_utils
from metrics import fuzzer_stats
from metrics import logs
from system import archive
from system import environment
from system import minijail
from system import new_process
from system import shell

# Number of testcases to use for the corpus subset strategy.
# See https://crbug.com/682311 for more information.
# Size 100 has a slightly higher chance as it seems to be the best one so far.
CORPUS_SUBSET_NUM_TESTCASES = [10, 20, 50, 75, 75, 100, 100, 100, 125, 125, 150]

# Probability of fuzzing from a subset of the corpus.
CORPUS_SUBSET_PROBABILITY = 0.50

# Suffix used for seed corpus archive generated with build. Does not include
# file extension.
SEED_CORPUS_ARCHIVE_SUFFIX = '_seed_corpus'

# Number of seconds to allow for extra processing.
POSTPROCESSING_TIME = 30.0

# Maximum number of files in the corpus for which we will unpack the seed
# corpus.
MAX_FILES_FOR_UNPACK = 5

# Extension for owners file containing list of people to be notified.
OWNERS_FILE_EXTENSION = '.owners'

# Extension for per-fuzz target labels to be added to issue tracker.
LABELS_FILE_EXTENSION = '.labels'


def current_timestamp():
  """Returns the current timestamp. Needed for mocking."""
  return time.time()


def get_strategy_probability(strategy_name, default):
  """Returns a strategy weight based on env variable |FUZZING_STRATEGIES|"""
  fuzzing_strategies = environment.get_value('FUZZING_STRATEGIES')
  if fuzzing_strategies is None or not isinstance(fuzzing_strategies, dict):
    return default

  if strategy_name not in fuzzing_strategies:
    return 0.0

  return fuzzing_strategies[strategy_name]


def do_corpus_subset():
  """Return whether or not to do corpus subset."""
  return decide_with_probability(
      get_strategy_probability(
          strategy.CORPUS_SUBSET_STRATEGY, default=CORPUS_SUBSET_PROBABILITY))


def decide_with_probability(probability):
  """Decide if we want to do something with the given probability."""
  return random.SystemRandom().random() < probability


def dump_big_query_data(stats, testcase_file_path, fuzzer_name_prefix,
                        fuzzer_name, fuzzer_command):
  """Dump BigQuery stats."""
  build_revision = fuzzer_utils.get_build_revision()
  job = environment.get_value('JOB_NAME')
  testcase_run = fuzzer_stats.TestcaseRun(fuzzer_name_prefix + fuzzer_name, job,
                                          build_revision, current_timestamp())

  testcase_run['command'] = fuzzer_command
  testcase_run.update(stats)
  fuzzer_stats.TestcaseRun.write_to_disk(testcase_run, testcase_file_path)


def find_fuzzer_path(build_directory, fuzzer_name):
  """Find the fuzzer path with the given name."""
  # TODO(ochang): This is necessary for legacy testcases, which include the
  # project prefix in arguments. Remove this in the near future.
  project_name = environment.get_value('PROJECT_NAME')
  legacy_name_prefix = ''
  if project_name:
    legacy_name_prefix = project_name + '_'

  fuzzer_filename = environment.get_executable_filename(fuzzer_name)
  for root, _, files in os.walk(build_directory):
    for filename in files:
      if (legacy_name_prefix + filename == fuzzer_name or
          filename == fuzzer_filename):
        return os.path.join(root, filename)

  logs.log_warn('Fuzzer: %s not found in build_directory: %s.' %
                (fuzzer_name, build_directory))
  return None


def get_command_quoted(command):
  """Return shell quoted command string."""
  return ' '.join(pipes.quote(part) for part in command)


def get_overridable_timeout(default_timeout, override_env_var):
  """Returns a timeout given a |default_timeout| and the environment variable,
  |override_env_var|, that overrides it. Returns the overriden value if
  |override_env_var| is set, otherwise returns default_timeout. Throws an
  assertion error if the return value is negative."""
  timeout_override = environment.get_value(override_env_var)
  timeout = float(timeout_override or default_timeout)
  assert timeout >= 0, timeout
  return timeout


def get_hard_timeout():
  """Get the hard timeout for fuzzing."""
  # Give a small window of time to process (upload) the fuzzer output.
  hard_timeout = (
      environment.get_value('FUZZ_TEST_TIMEOUT') - POSTPROCESSING_TIME)
  return get_overridable_timeout(hard_timeout, 'HARD_TIMEOUT_OVERRIDE')


def get_merge_timeout(default_merge_timeout):
  """Get the maximum amount of time that should be spent merging a corpus."""
  return get_overridable_timeout(default_merge_timeout,
                                 'MERGE_TIMEOUT_OVERRIDE')


def get_issue_owners(fuzz_target_path):
  """Return list of owner emails given a fuzz target path.

  Format of an owners file is described at:
  https://cs.chromium.org/chromium/src/third_party/depot_tools/owners.py
  """
  owners_file_path = fuzzer_utils.get_supporting_file(fuzz_target_path,
                                                      OWNERS_FILE_EXTENSION)

  if environment.is_trusted_host():
    owners_file_path = fuzzer_utils.get_file_from_untrusted_worker(
        owners_file_path)

  if not os.path.exists(owners_file_path):
    return []

  owners = []
  with open(owners_file_path, 'r') as owners_file_handle:
    owners_file_content = owners_file_handle.read()

    for line in owners_file_content.splitlines():
      stripped_line = line.strip()
      if not stripped_line:
        # Ignore empty lines.
        continue
      if stripped_line.startswith('#'):
        # Ignore comment lines.
        continue
      if stripped_line == '*':
        # Not of any use, we can't add everyone as owner with this.
        continue
      if (stripped_line.startswith('per-file') or
          stripped_line.startswith('file:')):
        # Don't have a source checkout, so ignore.
        continue
      if '@' not in stripped_line:
        # Bad email address.
        continue
      owners.append(stripped_line)

  return owners


def get_issue_labels(fuzz_target_path):
  """Return list of issue labels given a fuzz target path."""
  labels_file_path = fuzzer_utils.get_supporting_file(fuzz_target_path,
                                                      LABELS_FILE_EXTENSION)

  if environment.is_trusted_host():
    labels_file_path = fuzzer_utils.get_file_from_untrusted_worker(
        labels_file_path)

  if not os.path.exists(labels_file_path):
    return []

  with open(labels_file_path) as handle:
    return utils.parse_delimited(
        handle, delimiter='\n', strip=True, remove_empty=True)


def print_fuzzing_strategies(fuzzing_strategies):
  """Print the strategies used for logging purposes."""
  if fuzzing_strategies:
    print('cf::fuzzing_strategies: %s' % (','.join(fuzzing_strategies)))


def random_choice(sequence):
  """Return a random element from the non-empty sequence."""
  return random.SystemRandom().choice(sequence)


def read_data_from_file(file_path):
  """Read data from file."""
  with open(file_path, 'rb') as file_handle:
    return file_handle.read()


def recreate_directory(directory_path):
  """Delete directory if exists, create empty directory. Throw an exception if
  either fails."""
  if not shell.remove_directory(directory_path, recreate=True):
    raise Exception('Failed to recreate directory: ' + directory_path)


def strip_minijail_command(command, fuzzer_path):
  """Remove minijail arguments from a fuzzer command.

  Args:
    command: The command.
    fuzzer_path: Absolute path to the fuzzer.

  Returns:
    The stripped command.
  """
  try:
    fuzzer_path_index = command.index(fuzzer_path)
    return command[fuzzer_path_index:]
  except ValueError:
    return command


def write_data_to_file(content, file_path):
  """Writes data to file."""
  with open(file_path, 'wb') as file_handle:
    file_handle.write(str(content))


class MinijailEngineFuzzerRunner(minijail.MinijailProcessRunner):
  """Minijail runner for engine fuzzers."""

  @contextlib.contextmanager
  def _chroot_testcase(self, testcase_path):
    """Context manager for testcases.
    Args:
      testcase_path: Host path to testcase.
    Yields:
      Path to testcase within chroot.
    """
    testcase_directory, testcase_name = os.path.split(testcase_path)
    binding = self.chroot.get_binding(testcase_directory)
    if binding:
      # The host directory that contains this testcase is bound in the chroot.
      yield os.path.join(binding.dest_path, testcase_name)
      return
    # Copy the testcase into the chroot (temporarily).
    shutil.copy(testcase_path, self.chroot.directory)
    copied_testcase_path = os.path.join(self.chroot.directory, testcase_name)
    yield '/' + testcase_name
    # Cleanup
    os.remove(copied_testcase_path)


def signal_term_handler(sig, frame):  # pylint: disable=unused-argument
  try:
    print('SIGTERMed')
  except IOError:  # Pipe may already be closed and we may not be able to print.
    pass

  new_process.kill_process_tree(os.getpid())
  sys.exit(0)


def get_seed_corpus_path(fuzz_target_path):
  """Returns the path of the seed corpus if one exists. Otherwise returns None.
  Logs an error if multiple seed corpora exist for the same target."""
  archive_path_without_extension = fuzzer_utils.get_supporting_file(
      fuzz_target_path, SEED_CORPUS_ARCHIVE_SUFFIX)
  # Get all files that end with _seed_corpus.*
  possible_archive_paths = set(glob.glob(archive_path_without_extension + '.*'))
  # Now get a list of these that are valid seed corpus archives.
  archive_paths = possible_archive_paths.intersection(
      set(archive_path_without_extension + extension
          for extension in archive.ARCHIVE_FILE_EXTENSIONS))

  archive_paths = list(archive_paths)
  if not archive_paths:
    return None

  if len(archive_paths) > 1:
    logs.log_error('Multiple seed corpuses exist for fuzz target %s: %s.' %
                   (fuzz_target_path, ', '.join(archive_paths)))

  return archive_paths[0]


def process_sanitizer_options_overrides(fuzzer_path):
  """Applies sanitizer option overrides from .options file."""
  fuzzer_options = options.get_fuzz_target_options(fuzzer_path)
  if not fuzzer_options:
    return

  asan_options = environment.get_memory_tool_options('ASAN_OPTIONS', {})
  msan_options = environment.get_memory_tool_options('MSAN_OPTIONS', {})
  ubsan_options = environment.get_memory_tool_options('UBSAN_OPTIONS', {})

  asan_overrides = fuzzer_options.get_asan_options()
  if asan_options and asan_overrides:
    asan_options.update(asan_overrides)
    environment.set_memory_tool_options('ASAN_OPTIONS', asan_options)

  msan_overrides = fuzzer_options.get_msan_options()
  if msan_options and msan_overrides:
    msan_options.update(msan_overrides)
    environment.set_memory_tool_options('MSAN_OPTIONS', msan_options)

  ubsan_overrides = fuzzer_options.get_ubsan_options()
  if ubsan_options and ubsan_overrides:
    ubsan_options.update(ubsan_overrides)
    environment.set_memory_tool_options('UBSAN_OPTIONS', ubsan_options)


def unpack_seed_corpus_if_needed(fuzz_target_path,
                                 corpus_directory,
                                 max_bytes=float('inf'),
                                 force_unpack=False,
                                 max_files_for_unpack=MAX_FILES_FOR_UNPACK):
  """If seed corpus available, unpack it into the corpus directory if needed,
  ie: if corpus exists and either |force_unpack| is True, or the number of files
  in corpus_directory is less than |max_files_for_unpack|. Uses
  |fuzz_target_path| to find the seed corpus. If max_bytes is specified, then
  seed corpus files larger than |max_bytes| will not be unpacked.
  """
  seed_corpus_archive_path = get_seed_corpus_path(fuzz_target_path)
  if not seed_corpus_archive_path:
    return

  num_corpus_files = len(shell.get_files_list(corpus_directory))
  if not force_unpack and num_corpus_files > max_files_for_unpack:
    return

  if force_unpack:
    logs.log('Forced unpack: %s.' % seed_corpus_archive_path)

  start_time = time.time()
  archive_iterator = archive.iterator(seed_corpus_archive_path)
  # Unpack seed corpus recursively into the root of the main corpus directory.
  idx = 0
  for seed_corpus_file in archive_iterator:
    # Ignore directories.
    if seed_corpus_file.name.endswith('/'):
      continue

    # Allow callers to opt-out of unpacking large files.
    if seed_corpus_file.size > max_bytes:
      continue

    output_filename = '%016d' % idx
    output_file_path = os.path.join(corpus_directory, output_filename)
    with open(output_file_path, 'wb') as file_handle:
      shutil.copyfileobj(seed_corpus_file.handle, file_handle)

    idx += 1

  logs.log('Unarchiving seed corpus %s took %s seconds.' %
           (seed_corpus_archive_path, time.time() - start_time))
