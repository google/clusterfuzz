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

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import init
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment

_DEFAULT_TEST_TIMEOUT = 60


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


def _reproduce_testcase(args: argparse.Namespace) -> None:
  """Reproduces a testcase locally based on the provided arguments.

  Args:
    args: Parsed command-line arguments.
  """
  testcase = data_handler.get_testcase_by_id(args.testcase_id)
  if not testcase:
    logs.error(f'Testcase with ID {args.testcase_id} not found.')
    return

  job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
  if not job:
    logs.error(f'Job type {testcase.job_type} not found for testcase.')
    return

  # The job name is not set in update_environment_for_job,
  # so it was needed to manually set it here.
  environment.set_value('JOB_NAME', job.name)
  commands.update_environment_for_job(job.get_environment_string())

  if not setup.setup_local_fuzzer(testcase.fuzzer_name):
    logs.error(f'Failed to setup fuzzer {testcase.fuzzer_name}. Exiting.')
    return

  testcase_file_path = setup.setup_local_testcase(testcase)
  if testcase_file_path is None:
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

  bad_build_result: uworker_msg_pb2.BuildData = (  # pylint: disable=no-member
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

  if args.test_reproducibility:
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


def execute(args: argparse.Namespace) -> None:
  """Initializes the environment and reproduces a testcase locally.

  Args:
    args: Parsed command-line arguments.
  """
  _setup_reproduce(args)
  with ndb_init.context():
    _reproduce_testcase(args)
