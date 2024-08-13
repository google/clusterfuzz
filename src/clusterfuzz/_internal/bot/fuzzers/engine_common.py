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

import contextlib
import glob
import json
import os
import random
import re
import shlex
import shutil
import sys
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.metrics import fuzzer_stats
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import minijail
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell

# Maximum allowed size of a corpus file.
CORPUS_INPUT_SIZE_LIMIT = 5 * 1024 * 1024

# Number of testcases to use for the corpus subset strategy.
# See https://crbug.com/682311 for more information.
# Size 100 has a slightly higher chance as it seems to be the best one so far.
CORPUS_SUBSET_NUM_TESTCASES = [10, 20, 50, 75, 75, 100, 100, 100, 125, 125, 150]

# Suffix used for seed corpus archive generated with build. Does not include
# file extension.
SEED_CORPUS_ARCHIVE_SUFFIX = '_seed_corpus'

# Maximum number of files in the corpus for which we will unpack the seed
# corpus.
MAX_FILES_FOR_UNPACK = 5

# Extension for owners file containing list of people to be notified.
OWNERS_FILE_EXTENSION = '.owners'

# Extension for per-fuzz target labels to be added to issue tracker.
LABELS_FILE_EXTENSION = '.labels'

# Extension for per-fuzz target components to be added to issue tracker.
COMPONENTS_FILE_EXTENSION = '.components'

# Extension for additional metadata to be added to issue descriptions.
METADATA_FILE_EXTENSION = '.issue_metadata'

# Number of radamsa mutations.
RADAMSA_MUTATIONS = 2000

# Maximum number of seconds to run radamsa for.
RADAMSA_TIMEOUT = 3


class Generator:
  """Generators we can use."""
  NONE = 0
  RADAMSA = 1


def select_generator(strategy_pool, fuzzer_path):
  """Pick a generator to generate new testcases before fuzzing or return
  Generator.NONE if no generator selected."""
  if environment.is_lib() or environment.platform() == 'FUCHSIA':
    # Unsupported.
    return Generator.NONE

  # We can't use radamsa binary on Windows. Disable ML for now until we know it
  # works on Win.
  # These generators don't produce testcases that LPM fuzzers can use.
  if (environment.platform() == 'WINDOWS' or is_lpm_fuzz_target(fuzzer_path)):
    return Generator.NONE
  if strategy_pool.do_strategy(strategy.CORPUS_MUTATION_RADAMSA_STRATEGY):
    return Generator.RADAMSA

  return Generator.NONE


def generate_new_testcase_mutations(
    corpus_directory, new_testcase_mutations_directory, candidate_generator):
  """Generate new testcase mutations, using existing corpus directory or other
  methods.

  Returns true if mutations are successfully generated using radamsa.
  A false return signifies either no generator use or unsuccessful generation of
  testcase mutations."""
  generation_timeout = get_new_testcase_mutations_timeout()
  pre_mutations_filecount = shell.get_directory_file_count(
      new_testcase_mutations_directory)

  # Generate new testcase mutations using Radamsa.
  if candidate_generator == Generator.RADAMSA:
    generate_new_testcase_mutations_using_radamsa(
        corpus_directory, new_testcase_mutations_directory, generation_timeout)

  # If new mutations are successfully generated, return true.
  if shell.get_directory_file_count(
      new_testcase_mutations_directory) > pre_mutations_filecount:
    return True

  return False


# Filename length limit on ext4.
FILENAME_LENGTH_LIMIT = 255

RADAMSA_FILENAME_REGEX = re.compile(r'radamsa-\d+-(.*)', re.DOTALL)


def get_radamsa_output_filename(initial_filename, i):
  """Get the name of a file mutated by radamsa."""
  # Don't add the radamsa prefix to a file that already has it to avoid hitting
  # filename/path length limits.
  match = RADAMSA_FILENAME_REGEX.search(initial_filename)
  if match:
    base_filename = match.group(1)
  else:
    base_filename = initial_filename
  prefix = 'radamsa-%05d-' % (i + 1)
  # FIXME: AFL will still break if the filename is near 255 chars since it
  # naively appends. AFL needs to rename every file to a sensible length (not
  # just those created by radamsa).
  return prefix + base_filename[:FILENAME_LENGTH_LIMIT - len(prefix)]


def generate_new_testcase_mutations_using_radamsa(
    corpus_directory, new_testcase_mutations_directory, generation_timeout):
  """Generate new testcase mutations based on Radamsa."""
  radamsa_path = get_radamsa_path()
  if not radamsa_path:
    # Mutations using radamsa are not supported on current platform, bail out.
    return

  radamsa_runner = new_process.ProcessRunner(radamsa_path)
  files_list = shell.get_files_list(corpus_directory)
  filtered_files_list = [
      f for f in files_list if os.path.getsize(f) <= CORPUS_INPUT_SIZE_LIMIT
  ]
  if not filtered_files_list:
    # No mutations to do on an empty corpus or one with very large files.
    return

  old_corpus_size = shell.get_directory_file_count(
      new_testcase_mutations_directory)
  expected_completion_time = time.time() + generation_timeout

  for i in range(RADAMSA_MUTATIONS):
    original_file_path = random_choice(filtered_files_list)
    original_filename = os.path.basename(original_file_path)
    output_path = os.path.join(
        new_testcase_mutations_directory,
        get_radamsa_output_filename(original_filename, i))

    result = radamsa_runner.run_and_wait(
        ['-o', output_path, original_file_path], timeout=RADAMSA_TIMEOUT)

    if (os.path.exists(output_path) and
        os.path.getsize(output_path) > CORPUS_INPUT_SIZE_LIMIT):
      # Skip large files to avoid further mutations and impact fuzzing
      # efficiency.
      shell.remove_file(output_path)
    elif result.return_code or result.timed_out:
      logs.warning(
          'Radamsa failed to mutate or timed out.', output=result.output)

    # Check if we exceeded our timeout. If yes, do no more mutations and break.
    if time.time() > expected_completion_time:
      break

  new_corpus_size = shell.get_directory_file_count(
      new_testcase_mutations_directory)
  logs.info('Added %d tests using Radamsa mutations.' %
            (new_corpus_size - old_corpus_size))


def get_radamsa_path():
  """Return path to radamsa binary for current platform."""
  bin_directory_path = os.path.join(
      os.path.dirname(os.path.realpath(__file__)), 'bin')
  platform = environment.platform()
  if platform == 'LINUX':
    return os.path.join(bin_directory_path, 'linux', 'radamsa')

  if platform == 'MAC':
    return os.path.join(bin_directory_path, 'mac', 'radamsa')

  return None


def get_new_testcase_mutations_timeout():
  """Get the timeout for new testcase mutations."""
  return get_overridable_timeout(10 * 60, 'MUTATIONS_TIMEOUT_OVERRIDE')


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


def decide_with_probability(probability):
  """Decide if we want to do something with the given probability."""
  return random.SystemRandom().random() < probability


def get_probability():
  """Obtain a random number."""
  return random.SystemRandom().random()


def get_testcase_run(stats, fuzzer_command):
  """Get testcase run for stats."""
  build_revision = fuzzer_utils.get_build_revision()
  job = environment.get_value('JOB_NAME')
  # fuzzer name is filled by fuzz_task.
  testcase_run = fuzzer_stats.TestcaseRun(None, job, build_revision,
                                          current_timestamp())

  testcase_run['command'] = fuzzer_command
  if stats is not None:
    testcase_run.update(stats)
  return testcase_run


def dump_big_query_data(stats, testcase_file_path, fuzzer_command):
  """Dump BigQuery stats."""
  testcase_run = get_testcase_run(stats, fuzzer_command)
  fuzzer_stats.TestcaseRun.write_to_disk(testcase_run, testcase_file_path)


def find_fuzzer_path(build_directory, fuzzer_name):
  """Find the fuzzer path with the given name."""
  if not build_directory:
    # Grey-box fuzzers might not have the build directory for a particular job
    # configuration when doing variant task testing (e.g. Android on-device
    # fuzz target might not exist on host). In this case, treat it similar to
    # target not found by returning None.
    logs.warning('No build directory found for fuzzer: %s' % fuzzer_name)
    return None

  if environment.platform() == 'FUCHSIA':
    # Fuchsia targets are not on disk.
    return fuzzer_name

  # TODO(ochang): This is necessary for legacy testcases, which include the
  # project prefix in arguments. Remove this in the near future.
  project_name = environment.get_value('PROJECT_NAME')
  legacy_name_prefix = ''
  if project_name:
    legacy_name_prefix = project_name + '_'

  fuzzer_filename = environment.get_executable_filename(fuzzer_name)
  for root, _, files in shell.walk(build_directory):
    for filename in files:
      if (legacy_name_prefix + filename == fuzzer_name or
          filename == fuzzer_filename):
        return os.path.join(root, filename)

  # This is an expected case when doing regression testing with old builds
  # that do not have that fuzz target. It can also happen when a host sends a
  # message to an untrusted worker that just restarted and lost information on
  # build directory.
  logs.warning('Fuzzer: %s not found in build_directory: %s.' %
               (fuzzer_name, build_directory))
  return None


def get_command_quoted(command):
  """Return shell quoted command string."""
  return ' '.join(shlex.quote(part) for part in command)


def get_overridable_timeout(default_timeout, override_env_var):
  """Returns a timeout given a |default_timeout| and the environment variable,
  |override_env_var|, that overrides it. Returns the overriden value if
  |override_env_var| is set, otherwise returns default_timeout. Throws an
  assertion error if the return value is negative."""
  timeout_override = environment.get_value(override_env_var)
  timeout = float(timeout_override or default_timeout)
  assert timeout >= 0, timeout
  return timeout


def get_hard_timeout(total_timeout=None):
  """Get the hard timeout for fuzzing."""
  if total_timeout is None:
    total_timeout = environment.get_value('FUZZ_TEST_TIMEOUT')

  return get_overridable_timeout(total_timeout, 'HARD_TIMEOUT_OVERRIDE')


def get_merge_timeout(default_merge_timeout):
  """Get the maximum amount of time that should be spent merging a corpus."""
  return get_overridable_timeout(default_merge_timeout,
                                 'MERGE_TIMEOUT_OVERRIDE')


def is_lpm_fuzz_target(fuzzer_path):
  """Returns True if |fuzzer_path| is a libprotobuf-mutator based fuzz
  target."""
  # TODO(metzman): Use this function to disable running LPM targets with AFL.
  with open(fuzzer_path, 'rb') as file_handle:
    return utils.search_bytes_in_file(b'TestOneProtoInput', file_handle)


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
  with open(owners_file_path) as owners_file_handle:
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


def get_issue_metadata(fuzz_target_path, extension):
  """Get issue metadata."""
  metadata_file_path = fuzzer_utils.get_supporting_file(fuzz_target_path,
                                                        extension)

  if environment.is_trusted_host():
    metadata_file_path = fuzzer_utils.get_file_from_untrusted_worker(
        metadata_file_path)

  if not os.path.exists(metadata_file_path):
    return []

  with open(metadata_file_path) as handle:
    return utils.parse_delimited(
        handle, delimiter='\n', strip=True, remove_empty=True)


def get_issue_labels(fuzz_target_path):
  """Return list of issue labels given a fuzz target path."""
  return get_issue_metadata(fuzz_target_path, LABELS_FILE_EXTENSION)


def get_issue_components(fuzz_target_path):
  """Return list of issue components given a fuzz target path."""
  return get_issue_metadata(fuzz_target_path, COMPONENTS_FILE_EXTENSION)


def get_additional_issue_metadata(fuzz_target_path):
  """Return the additional metadata fields given a fuzz target path. The data
  will be a JSON-formatted dictionary."""
  metadata_file_path = fuzzer_utils.get_supporting_file(
      fuzz_target_path, METADATA_FILE_EXTENSION)

  if environment.is_trusted_host():
    metadata_file_path = fuzzer_utils.get_file_from_untrusted_worker(
        metadata_file_path)

  if not os.path.exists(metadata_file_path):
    return {}

  with open(metadata_file_path) as handle:
    try:
      return json.load(handle)
    except (ValueError, TypeError):
      logs.error('Invalid metadata file format.', path=metadata_file_path)
      return {}


def get_all_issue_metadata(fuzz_target_path):
  """Get issue related metadata for a target."""
  metadata = {}

  issue_labels = get_issue_labels(fuzz_target_path)
  if issue_labels:
    metadata['issue_labels'] = ','.join(issue_labels)

  issue_components = get_issue_components(fuzz_target_path)
  if issue_components:
    metadata['issue_components'] = ','.join(issue_components)

  issue_owners = get_issue_owners(fuzz_target_path)
  if issue_owners:
    metadata['issue_owners'] = ','.join(issue_owners)

  issue_metadata = get_additional_issue_metadata(fuzz_target_path)
  if issue_metadata:
    # issue_metadata is a dictionary. Treat it as string for storage purpose
    # so that it is consistent with the definition in proto structure
    metadata['issue_metadata'] = json.dumps(issue_metadata)

  return metadata


def get_fuzz_target_issue_metadata(fuzz_target):
  """Get issue related metadata given a testcase."""
  if fuzz_target is None:
    return None

  if environment.is_trusted_host():
    # Not applicable.
    return None

  build_dir = environment.get_value('BUILD_DIR')
  target_path = find_fuzzer_path(build_dir, fuzz_target.binary)
  if not target_path:
    logs.error('Failed to find target path for ' + fuzz_target.binary)
    return None

  return get_all_issue_metadata(target_path)


def get_project_qualified_fuzzer_name(target_path):
  """Return project qualified fuzzer name for a given target path."""
  return data_types.fuzz_target_project_qualified_name(
      utils.current_project(), os.path.basename(target_path))


def format_fuzzing_strategies(fuzzing_strategies):
  """Format the strategies used for logging purposes."""
  if not fuzzing_strategies:
    return ''

  if isinstance(fuzzing_strategies, list):
    # Legacy format. TODO(ochang): Remove this once it's not used.
    value = ','.join(fuzzing_strategies)
  else:
    # New format.
    assert isinstance(fuzzing_strategies, dict)
    value = ','.join(f'{key}:{val}' for key, val in fuzzing_strategies.items())

  return 'cf::fuzzing_strategies: ' + value


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
    raise OSError('Failed to recreate directory: ' + directory_path)


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
    file_handle.write(str(content).encode('utf-8'))


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
  except OSError:  # Pipe may already be closed and we may not be able to print.
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
  archive_paths = possible_archive_paths.intersection({
      archive_path_without_extension + extension
      for extension in archive.ARCHIVE_FILE_EXTENSIONS
  })

  archive_paths = list(archive_paths)
  if not archive_paths:
    return None

  if len(archive_paths) > 1:
    logs.error('Multiple seed corpuses exist for fuzz target %s: %s.' %
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
  hwasan_options = environment.get_memory_tool_options('HWASAN_OPTIONS', {})

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

  hwasan_overrides = fuzzer_options.get_hwasan_options()
  if hwasan_options and hwasan_overrides:
    hwasan_options.update(hwasan_overrides)
    environment.set_memory_tool_options('HWASAN_OPTIONS', hwasan_options)


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
    logs.info('Forced unpack: %s.' % seed_corpus_archive_path)

  try:
    reader = archive.open(seed_corpus_archive_path)
  except:
    logs.error(f'Failed reading archive: {seed_corpus_archive_path}')
    return

  idx = 0
  with reader:
    for file in reader.list_members():
      if file.is_dir:
        continue

      if file.size_bytes > max_bytes:
        continue

      output_filename = '%016d' % idx
      output_file_path = os.path.join(corpus_directory, output_filename)
      with open(output_file_path, 'wb') as file_handle:
        with reader.open(file.name) as file:
          shutil.copyfileobj(file, file_handle)

      idx += 1

  logs.info('Unarchiving %d files from seed corpus %s.' %
            (idx, seed_corpus_archive_path))


def get_log_header(command, time_executed):
  """Get the log header."""
  quoted_command = get_command_quoted(command)
  return f'Command: {quoted_command}\nTime ran: {time_executed}\n'
