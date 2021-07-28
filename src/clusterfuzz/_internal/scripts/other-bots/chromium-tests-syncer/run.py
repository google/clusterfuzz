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
import time

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

MAX_TESTCASE_DIRECTORY_SIZE = 10 * 1024 * 1024  # in bytes.
STORED_TESTCASES_LIST = []


def unpack_crash_testcases(crash_testcases_directory):
  """Unpacks the old crash testcases in the provided directory."""
  for testcase in ndb_utils.get_all_from_model(data_types.Testcase):
    testcase_id = testcase.key.id()

    # 1. If we have already stored the testcase, then just skip.
    if testcase_id in STORED_TESTCASES_LIST:
      continue

    # 2. Make sure that it is a unique crash testcase. Ignore duplicates,
    # uploaded repros.
    if testcase.status != 'Processed':
      continue

    # 3. Check if the testcase is fixed. If not, skip.
    if testcase.open:
      continue

    # 4. Check if the testcase has a minimized repro. If not, skip.
    if not testcase.minimized_keys or testcase.minimized_keys == 'NA':
      continue

    # 5. Only use testcases that have bugs associated with them.
    if not testcase.bug_information:
      continue

    # 6. Existing IPC testcases are un-interesting and unused in further
    # mutations. Due to size bloat, ignoring these for now.
    if testcase.absolute_path.endswith(testcase_manager.IPCDUMP_EXTENSION):
      continue

    # 7. Ignore testcases that are archives (e.g. Langfuzz fuzzer tests).
    if archive.get_archive_type(testcase.absolute_path):
      continue

    # 8. Skip in-process fuzzer testcases, since these are only applicable to
    # fuzz targets and don't run with blackbox binaries.
    if testcase.fuzzer_name and testcase.fuzzer_name in ['afl', 'libFuzzer']:
      continue

    # Un-pack testcase.
    try:
      _, input_directory, _ = setup.unpack_testcase(testcase)
    except Exception:
      logs.log_error('Failed to unpack testcase %d.' % testcase.key.id())
      continue

    # Move this to our crash testcases directory.
    crash_testcase_directory = os.path.join(crash_testcases_directory,
                                            str(testcase_id))
    shell.move(input_directory, crash_testcase_directory)

    # Re-create input directory for unpacking testcase in next iteration.
    shell.create_directory(input_directory)

    STORED_TESTCASES_LIST.append(testcase_id)

  # Remove testcase directories that exceed the max size limit.
  for directory_name in os.listdir(crash_testcases_directory):
    directory_path = os.path.join(crash_testcases_directory, directory_name)
    if not os.path.isdir(directory_path):
      continue

    if shell.get_directory_size(directory_path) <= MAX_TESTCASE_DIRECTORY_SIZE:
      continue

    shell.remove_directory(directory_path)

  # Rename all fuzzed testcase files as regular files.
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
      except:
        raise Exception('Failed to rename testcase %s.' % file_path)

  # Remove empty files and dirs to avoid the case where a fuzzer randomly
  # chooses an empty dir/file and generates zero testcases.
  shell.remove_empty_files(crash_testcases_directory)
  shell.remove_empty_directories(crash_testcases_directory)


def clone_git_repository(tests_directory, name, repo_url):
  """Clone a git repo."""
  logs.log('Syncing %s tests.' % name)

  directory = os.path.join(tests_directory, name)
  if not os.path.exists(directory):
    subprocess.check_call(
        ['git', 'clone', '--depth=1', repo_url, name], cwd=tests_directory)

  if os.path.exists(directory):
    subprocess.check_call(['git', 'pull'], cwd=directory)
  else:
    raise Exception('Unable to checkout %s tests.' % name)


def checkout_svn_repository(tests_directory, name, repo_url):
  """Checkout a SVN repo."""
  logs.log('Syncing %s tests.' % name)

  directory = os.path.join(tests_directory, name)
  if not os.path.exists(directory):
    subprocess.check_call(
        ['svn', 'checkout', repo_url, directory], cwd=tests_directory)

  if os.path.exists(directory):
    subprocess.check_call(['svn', 'update', directory], cwd=tests_directory)
  else:
    raise Exception('Unable to checkout %s tests.' % name)


def create_symbolic_link(tests_directory, source_subdirectory,
                         target_subdirectory):
  """Create symbolic link."""
  source_directory = os.path.join(tests_directory, source_subdirectory)
  target_directory = os.path.join(tests_directory, target_subdirectory)
  if not os.path.exists(source_directory):
    raise Exception('Unable to find source directory %s for symbolic link.' %
                    source_directory)

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
    raise Exception(
        'Unable to find Gecko source directory %s.' % gecko_checkout_directory)

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


def main():
  """Main sync routine."""
  tests_archive_bucket = environment.get_value('TESTS_ARCHIVE_BUCKET')
  tests_archive_name = environment.get_value('TESTS_ARCHIVE_NAME')
  tests_directory = environment.get_value('TESTS_DIR')
  sync_interval = environment.get_value('SYNC_INTERVAL')  # in seconds.

  shell.create_directory(tests_directory)

  # Sync old crash tests.
  logs.log('Syncing old crash tests.')
  crash_testcases_directory = os.path.join(tests_directory, 'CrashTests')
  shell.create_directory(crash_testcases_directory)
  unpack_crash_testcases(crash_testcases_directory)

  # Sync web tests.
  logs.log('Syncing web tests.')
  src_directory = os.path.join(tests_directory, 'src')
  gclient_file_path = os.path.join(tests_directory, '.gclient')
  if not os.path.exists(gclient_file_path):
    subprocess.check_call(
        ['fetch', '--no-history', 'chromium', '--nosvn=True'],
        cwd=tests_directory)
  if os.path.exists(src_directory):
    subprocess.check_call(['gclient', 'revert'], cwd=src_directory)
    subprocess.check_call(['git', 'pull'], cwd=src_directory)
    subprocess.check_call(['gclient', 'sync'], cwd=src_directory)
  else:
    raise Exception('Unable to checkout web tests.')

  clone_git_repository(tests_directory, 'v8',
                       'https://chromium.googlesource.com/v8/v8')

  clone_git_repository(tests_directory, 'ChakraCore',
                       'https://github.com/Microsoft/ChakraCore.git')

  clone_git_repository(tests_directory, 'gecko-dev',
                       'https://github.com/mozilla/gecko-dev.git')

  clone_git_repository(tests_directory, 'webgl-conformance-tests',
                       'https://github.com/KhronosGroup/WebGL.git')

  checkout_svn_repository(
      tests_directory, 'WebKit/LayoutTests',
      'http://svn.webkit.org/repository/webkit/trunk/LayoutTests')

  checkout_svn_repository(
      tests_directory, 'WebKit/JSTests/stress',
      'http://svn.webkit.org/repository/webkit/trunk/JSTests/stress')

  checkout_svn_repository(
      tests_directory, 'WebKit/JSTests/es6',
      'http://svn.webkit.org/repository/webkit/trunk/JSTests/es6')

  create_gecko_tests_directory(tests_directory, 'gecko-dev', 'gecko-tests')

  # Upload tests archive to google cloud storage.
  logs.log('Uploading tests archive to cloud.')
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
          'WebKit',
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

  logs.log('Completed cycle, sleeping for %s seconds.' % sync_interval)
  time.sleep(sync_interval)


if __name__ == '__main__':
  # Make sure environment is correctly configured.
  logs.configure('run_bot')
  environment.set_bot_environment()

  fail_wait = environment.get_value('FAIL_WAIT')

  # Continue this forever.
  while True:
    try:
      with ndb_init.context():
        main()
    except Exception:
      logs.log_error('Failed to sync tests.')
      time.sleep(fail_wait)
