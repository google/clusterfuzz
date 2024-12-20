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
"""Sync server - sync testcases from various repositories onto our GCS."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

import os
import re
import subprocess
import tarfile
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

ENGINE_FUZZER_NAMES = ['afl', 'centipede', 'googlefuzztest', 'libFuzzer']
MAX_TESTCASE_DIRECTORY_SIZE = 10 * 1024 * 1024  # in bytes.
MAX_TESTCASES = 25000
TESTCASES_REPORT_INTERVAL = 2500
STORED_TESTCASES_LIST = []


def unpack_crash_testcases(crash_testcases_directory):
  """Unpacks the old crash testcases in the provided directory."""
  count = 0
  # Make sure that it is a unique crash testcase. Ignore duplicates,
  # uploaded repros. Check if the testcase is fixed. If not, skip.
  # Only use testcases that have bugs associated with them.
  # Sort latest first.
  testcases = data_types.Testcase.query(
      ndb_utils.is_false(
          data_types.Testcase.open), data_types.Testcase.status == 'Processed',
      data_types.Testcase.bug_information !=
      '').order(-data_types.Testcase.timestamp)
  for testcase in testcases:
    count += 1
    if count >= MAX_TESTCASES:
      logs.info(f'{MAX_TESTCASES} testcases reached.')
      break
    if count % TESTCASES_REPORT_INTERVAL == 0:
      logs.info(f'Processed {count} testcases.')

    testcase_id = testcase.key.id()

    # If we have already stored the testcase, then just skip.
    if testcase_id in STORED_TESTCASES_LIST:
      continue

    # Check if the testcase has a minimized repro. If not, skip.
    if not testcase.minimized_keys or testcase.minimized_keys == 'NA':
      continue

    # Existing IPC testcases are un-interesting and unused in further
    # mutations. Due to size bloat, ignoring these for now.
    if testcase.absolute_path.endswith(testcase_manager.IPCDUMP_EXTENSION):
      continue

    # Ignore testcases that are archives (e.g. Langfuzz fuzzer tests).
    if archive.get_archive_type(testcase.absolute_path):
      continue

    # Skip in-process fuzzer testcases, since these are only applicable to
    # fuzz targets and don't run with blackbox binaries.
    if testcase.fuzzer_name and testcase.fuzzer_name in ENGINE_FUZZER_NAMES:
      continue

    # Un-pack testcase.
    try:
      testcase_download_url = setup.get_signed_testcase_download_url(testcase)
      setup.unpack_testcase(testcase, testcase_download_url)
    except Exception:
      logs.error('Failed to unpack testcase %d.' % testcase.key.id())
      continue

    # Move this to our crash testcases directory.
    crash_testcase_directory = os.path.join(crash_testcases_directory,
                                            str(testcase_id))
    input_directory = environment.get_value('FUZZ_INPUTS')
    shell.move(input_directory, crash_testcase_directory)

    # Re-create input directory for unpacking testcase in next iteration.
    shell.create_directory(input_directory)

    STORED_TESTCASES_LIST.append(testcase_id)

  # Remove testcase directories that exceed the max size limit.
  logs.info('Removing large directories.')
  for directory_name in os.listdir(crash_testcases_directory):
    directory_path = os.path.join(crash_testcases_directory, directory_name)
    if not os.path.isdir(directory_path):
      continue

    if shell.get_directory_size(directory_path) <= MAX_TESTCASE_DIRECTORY_SIZE:
      continue

    shell.remove_directory(directory_path)

  # Rename all fuzzed testcase files as regular files.
  logs.info('Renaming testcase files.')
  for root, _, files in os.walk(crash_testcases_directory):
    for filename in files:
      if not filename.startswith(testcase_manager.FUZZ_PREFIX):
        continue

      file_path = os.path.join(root, filename)
      stripped_file_name = os.path.basename(file_path)[len(
          testcase_manager.FUZZ_PREFIX):]
      stripped_file_path = os.path.join(
          os.path.dirname(file_path), stripped_file_name)
      try:
        os.rename(file_path, stripped_file_path)
      except Exception as e:
        raise RuntimeError(f'Failed to rename testcase {file_path}') from e

  # Remove empty files and dirs to avoid the case where a fuzzer randomly
  # chooses an empty dir/file and generates zero testcases.
  shell.remove_empty_files(crash_testcases_directory)
  shell.remove_empty_directories(crash_testcases_directory)


def clone_git_repository(tests_directory, name, repo_url):
  """Clone a git repo."""
  logs.info('Syncing %s tests.' % name)

  directory = os.path.join(tests_directory, name)
  if not os.path.exists(directory):
    subprocess.check_call(
        ['git', 'clone', '--depth=1', repo_url, name], cwd=tests_directory)

  if os.path.exists(directory):
    subprocess.check_call(['git', 'pull'], cwd=directory)
  else:
    raise RuntimeError(f'Unable to checkout {name} tests.')


def create_symbolic_link(tests_directory, source_subdirectory,
                         target_subdirectory):
  """Create symbolic link."""
  source_directory = os.path.join(tests_directory, source_subdirectory)
  target_directory = os.path.join(tests_directory, target_subdirectory)
  if not os.path.exists(source_directory):
    raise RuntimeError(
        f'Unable to find source directory {source_directory} for symlink.')

  if os.path.exists(target_directory):
    # Symbolic link already exists, bail out.
    return

  target_parent_directory = os.path.dirname(target_directory)
  if not os.path.exists(target_parent_directory):
    # Create parent dirs if needed, otherwise symbolic link creation will fail.
    os.makedirs(target_parent_directory)

  subprocess.check_call(['ln', '-s', source_directory, target_directory])


def create_gecko_tests_directory(tests_directory, gecko_checkout_subdirectory,
                                 gecko_tests_subdirectory):
  """Create Gecko tests directory from a Gecko source checkout using links."""
  gecko_checkout_directory = os.path.join(tests_directory,
                                          gecko_checkout_subdirectory)
  if not os.path.exists(gecko_checkout_directory):
    raise RuntimeError(
        f'Unable to find Gecko source directory {gecko_checkout_directory}.')

  web_platform_sub_directory = 'testing%sweb-platform%s' % (os.sep, os.sep)
  for root, directories, _ in os.walk(gecko_checkout_directory):
    for directory in directories:
      if not re.match('.*tests?$', directory):
        continue

      directory_absolute_path = os.path.join(root, directory)
      sub_directory = utils.strip_from_left(directory_absolute_path,
                                            gecko_checkout_directory + os.sep)
      source_subdirectory = gecko_checkout_subdirectory + os.sep + sub_directory
      target_subdirectory = gecko_tests_subdirectory + os.sep + sub_directory

      if sub_directory.startswith(web_platform_sub_directory):
        # Exclude web-platform tests already included in blink layout tests.
        continue

      create_symbolic_link(tests_directory, source_subdirectory,
                           target_subdirectory)


def create_fuzzilli_tests_directory(tests_directory):
  """Create Fuzzilli tests directory from the autozilli GCS archives."""
  logs.info('Syncing fuzzilli tests.')
  fuzzilli_tests_directory = os.path.join(tests_directory, 'fuzzilli')
  remote_archive_tmpl = 'gs://autozilli/autozilli-%d.tgz'

  # Ensure we have an empty directory with no leftovers from a previous run.
  shell.remove_directory(fuzzilli_tests_directory, recreate=True)

  def filter_members(member, path):
    # We only need JS files and the settings.json from the archive.
    if member.name.endswith('fzil') or member.name.startswith('fuzzdir/stats'):
      return None
    return tarfile.data_filter(member, path)

  for i in range(1, 10):
    # Download archives number 1-9.
    remote_archive = remote_archive_tmpl % i
    logs.info(f'Processing {remote_archive}')
    local_archive = os.path.join(fuzzilli_tests_directory, 'tmp.tgz')
    subprocess.check_call(['gsutil', 'cp', remote_archive, local_archive])

    # Extract relevant files.
    with tarfile.open(local_archive) as tar:
      tar.extractall(path=fuzzilli_tests_directory, filter=filter_members)

    # Clean up.
    os.rename(
        os.path.join(fuzzilli_tests_directory, 'fuzzdir'),
        os.path.join(fuzzilli_tests_directory, f'fuzzdir-{i}'))
    shell.remove_file(local_archive)


def sync_tests(tests_archive_bucket: str, tests_archive_name: str,
               tests_directory: str):
  """Main sync routine."""
  shell.create_directory(tests_directory)

  # Sync old crash tests.
  logs.info('Syncing old crash tests.')
  crash_testcases_directory = os.path.join(tests_directory, 'CrashTests')
  shell.create_directory(crash_testcases_directory)
  unpack_crash_testcases(crash_testcases_directory)

  clone_git_repository(tests_directory, 'src',
                       'https://chromium.googlesource.com/chromium/src')

  clone_git_repository(tests_directory, 'v8',
                       'https://chromium.googlesource.com/v8/v8')

  clone_git_repository(tests_directory, 'ChakraCore',
                       'https://github.com/Microsoft/ChakraCore.git')

  clone_git_repository(tests_directory, 'gecko-dev',
                       'https://github.com/mozilla/gecko-dev.git')

  clone_git_repository(tests_directory, 'webgl-conformance-tests',
                       'https://github.com/KhronosGroup/WebGL.git')

  clone_git_repository(tests_directory, 'WebKit',
                       'https://github.com/WebKit/WebKit.git')

  create_gecko_tests_directory(tests_directory, 'gecko-dev', 'gecko-tests')

  create_fuzzilli_tests_directory(tests_directory)

  # Upload tests archive to google cloud storage.
  logs.info('Uploading tests archive to cloud.')
  tests_archive_local = os.path.join(tests_directory, tests_archive_name)
  tests_archive_remote = 'gs://{bucket_name}/{archive_name}'.format(
      bucket_name=tests_archive_bucket, archive_name=tests_archive_name)
  shell.remove_file(tests_archive_local)
  create_symbolic_link(tests_directory, 'gecko-dev/js/src/tests',
                       'spidermonkey')
  create_symbolic_link(tests_directory, 'ChakraCore/test', 'chakra')

  # FIXME: Find a way to rename LayoutTests to web_tests without breaking
  # compatibility with older testcases.
  create_symbolic_link(tests_directory, 'src/third_party/blink/web_tests',
                       'LayoutTests')

  subprocess.check_call(
      [
          'zip',
          '-r',
          tests_archive_local,
          'CrashTests',
          'LayoutTests',
          'WebKit/JSTests/es6',
          'WebKit/JSTests/stress',
          'WebKit/LayoutTests',
          'fuzzilli',
          'gecko-tests',
          'v8/test/mjsunit',
          'spidermonkey',
          'chakra',
          'webgl-conformance-tests',
          '-x',
          '*.cc',
          '-x',
          '*.cpp',
          '-x',
          '*.py',
          '-x',
          '*.txt',
          '-x',
          '*-expected.*',
          '-x',
          '*.git*',
          '-x',
          '*.svn*',
      ],
      cwd=tests_directory)
  subprocess.check_call(
      ['gsutil', 'cp', tests_archive_local, tests_archive_remote])

  logs.info('Sync complete.')
  monitoring_metrics.CHROME_TEST_SYNCER_SUCCESS.increment()


def main():
  # Make sure environment is correctly configured.
  logs.configure('run_bot')
  environment.set_bot_environment()

  tests_archive_bucket = environment.get_value('TESTS_ARCHIVE_BUCKET')
  tests_archive_name = environment.get_value('TESTS_ARCHIVE_NAME')
  tests_directory = environment.get_value('TESTS_DIR')

  # Intervals are in seconds.
  sync_interval = environment.get_value('SYNC_INTERVAL')
  fail_wait = environment.get_value('FAIL_WAIT')

  while True:
    sleep_secs = sync_interval

    try:
      with monitor.wrap_with_monitoring(), ndb_init.context():
        sync_tests(tests_archive_bucket, tests_archive_name, tests_directory)
    except Exception as e:
      logs.error(f'Failed to sync tests: {e}')
      sleep_secs = fail_wait

    logs.info(f'Sleeping for {sleep_secs} seconds.')
    time.sleep(sleep_secs)


if __name__ == '__main__':
  main()
