# Copyright 2025 Google LLC
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
"""Reproduces a testcase locally."""

import argparse
import os
from typing import Optional
from typing import Tuple

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

_DEFAULT_TEST_TIMEOUT = 60
_EXECUTABLE_PERMISSIONS = 0o750


def _setup_fuzzer(fuzzer_name: str) -> bool:
  """Sets up the fuzzer binaries and environment.

  Args:
    fuzzer_name: The name of the fuzzer to set up.

  Returns:
    True if setup was successful, False otherwise.
  """
  fuzzer = data_types.Fuzzer.query(
      data_types.Fuzzer.name == fuzzer_name).get()
  if not fuzzer:
    logs.error(f'Fuzzer {fuzzer_name} not found.')
    return False

  if fuzzer.untrusted_content:
    logs.warning('You are about to run an untrusted fuzzer locally. '
                 'This can be dangerous.')

  environment.set_value('UNTRUSTED_CONTENT', fuzzer.untrusted_content)

  if fuzzer.data_bundle_name:
    logs.info(
        f'Fuzzer {fuzzer_name} uses data bundle: {fuzzer.data_bundle_name}')

  if fuzzer.launcher_script:
    logs.error('Fuzzers with launch script not supported yet.')
    return False

  if fuzzer.builtin:
    logs.info(f'Fuzzer {fuzzer_name} is builtin, no setup required.')
    return True

  fuzzer_directory: str = setup.get_fuzzer_directory(fuzzer.name)

  try:
    if not shell.remove_directory(fuzzer_directory, recreate=True):
      logs.error(f'Failed to clear fuzzer directory: {fuzzer_directory}')
      return False
  except Exception as e:
    logs.error(f'Error clearing fuzzer directory {fuzzer_directory}: {e}')
    return False

  archive_path = os.path.join(fuzzer_directory, fuzzer.filename)
  if not blobs.read_blob_to_disk(fuzzer.blobstore_key, archive_path):
    logs.error('Failed to download fuzzer archive from blobstore: '
               f'{fuzzer.blobstore_key}')
    return False

  try:
    with archive.open(archive_path) as reader:
      reader.extract_all(fuzzer_directory)
  except archive.ArchiveError as e:
    logs.error(f'Failed to unpack fuzzer archive {fuzzer.filename}: {e}')
    return False
  except Exception as e:
    logs.error(
        f'Unexpected error unpacking fuzzer archive {fuzzer.filename}: {e}')
    return False
  finally:
    if os.path.exists(archive_path):
      try:
        shell.remove_file(archive_path)
      except Exception as e:
        logs.warning(
            f'Failed to remove temporary archive file {archive_path}: {e}')

  fuzzer_path = os.path.join(fuzzer_directory, fuzzer.executable_path)
  if not os.path.exists(fuzzer_path):
    logs.error(
        f'Fuzzer executable {fuzzer.executable_path} not found in archive. '
        'Check fuzzer configuration.')
    return False

  try:
    os.chmod(fuzzer_path, _EXECUTABLE_PERMISSIONS)
  except OSError as e:
    logs.error(
        f'Failed to set permissions on fuzzer executable {fuzzer_path}: {e}')
    return False

  return True


def _setup_testcase_locally(testcase: data_types.Testcase) -> Tuple[bool, Optional[str]]:
  """Sets up the testcase file locally.

  Args:
    testcase: The Testcase object.

  Returns:
    A tuple containing:
        - bool: True if the testcase was downloaded successfully.
        - Optional[str]: The local file path to the testcase, or None on failure.
  """
  try:
    shell.clear_testcase_directories()
  except Exception as e:
    logs.error(f'Error clearing testcase directories: {e}')
    return False, None

  try:
    _, testcase_file_path = setup._get_testcase_file_and_path(testcase)
    if testcase.minimized_keys and testcase.minimized_keys != 'NA':
      blob_key = testcase.minimized_keys
    else:
      blob_key = testcase.fuzzed_keys
    if not blobs.read_blob_to_disk(blob_key, testcase_file_path):
      logs.error(f'Failed to download testcase from blobstore: {blob_key}')
      # Returning None for path when download fails
      return False, None
    setup.prepare_environment_for_testcase(testcase)
  except Exception as e:
    logs.error(f'Error setting up testcase locally: {e}')
    return False, None

  return True, testcase_file_path


def _reproduce_testcase(args: argparse.Namespace) -> None:
  """Reproduces a testcase locally based on the provided arguments.

  Args:
    args: Parsed command-line arguments.
  """
  testcase = data_handler.get_testcase_by_id(
      args.testcase_id)
  if not testcase:
    logs.error(f'Testcase with ID {args.testcase_id} not found.')
    return

  job = data_types.Job.query(
      data_types.Job.name == testcase.job_type).get()
  if not job:
    logs.error(f'Job type {testcase.job_type} not found for testcase.')
    return

  # The job name is not set in update_environment_for_job,
  # so it was needed to manually set it here.
  environment.set_value('JOB_NAME', job.name)
  commands.update_environment_for_job(job.get_environment_string())

  if not _setup_fuzzer(testcase.fuzzer_name):
    logs.error(f'Failed to setup fuzzer {testcase.fuzzer_name}. Exiting.')
    return

  testcase_setup_successful, testcase_file_path = _setup_testcase_locally(
      testcase)
  if not testcase_setup_successful or testcase_file_path is None:
    logs.error('Could not setup testcase locally. Exiting.')
    return

  fuzz_target = testcase.get_fuzz_target()
  target_binary = fuzz_target.binary if fuzz_target else None

  try:
    build_manager.setup_build(
        revision=testcase.crash_revision, fuzz_target=target_binary)
  except Exception as e:
    logs.error(
        f'Error setting up build for revision {testcase.crash_revision}: {e}')
    return

  bad_build_result: uworker_msg_pb2.BuildData = (
      testcase_manager.check_for_bad_build(job.name, testcase.crash_revision))
  if bad_build_result.is_bad_build:
    logs.error('Bad build detected. Exiting.')
    return

  # After checking for bad build, sets the app args as they
  # were found in the crash for start testing the reproducibility
  environment.set_value('APP_ARGS', testcase.minimized_arguments)
  try:
    test_timeout = int(
        environment.get_value('TEST_TIMEOUT', _DEFAULT_TEST_TIMEOUT))
  except ValueError:
    logs.warning(
        f"Invalid TEST_TIMEOUT value: {environment.get_value('TEST_TIMEOUT')}. "
        f"Using default: {_DEFAULT_TEST_TIMEOUT}")
    test_timeout = _DEFAULT_TEST_TIMEOUT

  result = testcase_manager.test_for_crash_with_retries(
      fuzz_target=fuzz_target,
      testcase=testcase,
      testcase_path=testcase_file_path,
      test_timeout=test_timeout,
      http_flag=testcase.http_flag,
      use_gestures=testcase.gestures,
      compare_crash=True,
  )

  if result.is_crash():
    logs.info(f'Crash occurred. Output:\n\n{result.output}')
  else:
    logs.info('No crash occurred. Exiting.')
    return

  logs.info('Testing for reproducibility...')
  reproduces = testcase_manager.test_for_reproducibility(
      fuzz_target=fuzz_target,
      testcase_path=testcase_file_path,
      crash_type=testcase.crash_type,
      expected_state=None,
      expected_security_flag=testcase.security_flag,
      test_timeout=test_timeout,
      http_flag=testcase.http_flag,
      gestures=testcase.gestures,
      arguments=testcase.minimized_arguments,
  )

  if reproduces:
    logs.info('The testcase reliably reproduces.')
  else:
    logs.info('The testcase does not reliably reproduce.')

def _setup_reproduce(args) -> None:
  """Sets up the environment for reproducing a testcase.

  Args:
    args: Parsed command-line arguments.
  """
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(args.config_dir)
  local_config.ProjectConfig().set_environment()
  environment.set_bot_environment()
  logs.configure('run_bot')
  init.run()

def execute(args: argparse.Namespace) -> None:
  """Initializes the environment and reproduces a testcase locally.

  Args:
    args: Parsed command-line arguments.
  """
  _setup_reproduce(args)
  with ndb_init.context():
    _reproduce_testcase(args)
