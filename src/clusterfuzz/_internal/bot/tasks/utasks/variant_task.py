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
"""Variant task for analyzing testcase variants with a different job."""

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks.utasks import uworker_handle_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment


def _get_variant_testcase_for_job(testcase, job_type):
  """Return a testcase entity for variant task use. This changes the fuzz target
  params for a particular fuzzing engine."""
  if testcase.job_type == job_type:
    # Update stack operation on same testcase.
    return testcase

  if not environment.is_engine_fuzzer_job(testcase.job_type):
    # For blackbox fuzzer testcases, there is no change of fuzzer required.
    return testcase

  engine_name = environment.get_engine_for_job(job_type)
  project = data_handler.get_project_name(job_type)
  binary_name = testcase.get_metadata('fuzzer_binary_name')
  fully_qualified_fuzzer_name = data_types.fuzz_target_fully_qualified_name(
      engine_name, project, binary_name)

  variant_testcase = data_types.clone_entity(testcase)
  variant_testcase.key = testcase.key
  variant_testcase.fuzzer_name = engine_name
  variant_testcase.overridden_fuzzer_name = fully_qualified_fuzzer_name
  variant_testcase.job_type = job_type

  # Remove put() method to avoid updates. DO NOT REMOVE THIS.
  variant_testcase.put = lambda: None

  return variant_testcase


def utask_preprocess(testcase_id, job_type, uworker_env):
  """Run a test case with a different job type to see if they reproduce."""
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return None

  if (environment.is_engine_fuzzer_job(testcase.job_type) !=
      environment.is_engine_fuzzer_job(job_type)):
    # We should never reach here. But in case we do, we should bail out as
    # otherwise we will run into exceptions.
    return None

  # Use a cloned testcase entity with different fuzz target paramaters for
  # a different fuzzing engine.
  original_job_type = testcase.job_type
  testcase = _get_variant_testcase_for_job(testcase, job_type)
  variant = data_handler.get_or_create_testcase_variant(testcase_id, job_type)
  testcase_download_url = setup.get_signed_testcase_download_url(testcase)
  testcase_upload_metadata = data_types.TestcaseUploadMetadata.query(
      data_types.TestcaseUploadMetadata.testcase_id == int(testcase_id)).get()
  return uworker_io.UworkerInput(
      job_type=job_type,
      original_job_type=original_job_type,
      testcase=testcase,
      testcase_upload_metadata=testcase_upload_metadata,
      uworker_env=uworker_env,
      variant=variant,
      testcase_id=testcase_id,
      testcase_download_url=testcase_download_url,
  )


def utask_main(uworker_input):
  """The main part of the variant task. Downloads the testcase and build checks
  if the build can reproduce the error."""
  if environment.is_engine_fuzzer_job(uworker_input.testcase.job_type):
    # Remove put() method to avoid updates. DO NOT REMOVE THIS.
    # Repeat this because the in-memory executor may allow puts.
    # TODO(metzman): Remove this when we use batch.
    uworker_input.testcase.put = lambda: None

  # Setup testcase and its dependencies.
  _, testcase_file_path, error = setup.setup_testcase(
      uworker_input.testcase,
      uworker_input.job_type,
      metadata=uworker_input.testcase_upload_metadata,
      testcase_download_url=uworker_input.testcase_download_url)
  if error:
    return error

  # Set up a custom or regular build. We explicitly omit the crash revision
  # since we want to test against the latest build here.
  try:
    build_manager.setup_build()
  except errors.BuildNotFoundError:
    logs.log_warn('Matching build not found.')
    return uworker_io.UworkerOutput(error=uworker_msg_pb2.ErrorType.UNHANDLED)

  # Check if we have an application path. If not, our build failed to setup
  # correctly.
  if not build_manager.check_app_path():
    return uworker_io.UworkerOutput(
        error=uworker_msg_pb2.ErrorType.VARIANT_BUILD_SETUP,
        testcase=uworker_input.testcase)

  # Disable gestures if we're running on a different platform from that of
  # the original test case.
  use_gestures = (
      uworker_input.testcase.platform == environment.platform().lower())

  # Reproduce the crash.
  app_path = environment.get_value('APP_PATH')
  command = testcase_manager.get_command_line_for_application(
      testcase_file_path,
      app_path=app_path,
      needs_http=uworker_input.testcase.http_flag)
  test_timeout = environment.get_value('TEST_TIMEOUT', 10)
  revision = environment.get_value('APP_REVISION')
  result = testcase_manager.test_for_crash_with_retries(
      uworker_input.testcase,
      testcase_file_path,
      test_timeout,
      http_flag=uworker_input.testcase.http_flag,
      use_gestures=use_gestures,
      compare_crash=False)

  if result.is_crash() and not result.should_ignore():
    crash_state = result.get_state()
    crash_type = result.get_type()
    security_flag = result.is_security_issue()

    gestures = uworker_input.testcase.gestures if use_gestures else None
    one_time_crasher_flag = not testcase_manager.test_for_reproducibility(
        uworker_input.testcase.fuzzer_name,
        uworker_input.testcase.actual_fuzzer_name(), testcase_file_path,
        crash_type, crash_state, security_flag, test_timeout,
        uworker_input.testcase.http_flag, gestures)
    if one_time_crasher_flag:
      status = data_types.TestcaseVariantStatus.FLAKY
    else:
      status = data_types.TestcaseVariantStatus.REPRODUCIBLE

    crash_comparer = CrashComparer(crash_state,
                                   uworker_input.testcase.crash_state)
    is_similar = (
        crash_comparer.is_similar() and
        security_flag == uworker_input.testcase.security_flag)

    unsymbolized_crash_stacktrace = result.get_stacktrace(symbolized=False)
    symbolized_crash_stacktrace = result.get_stacktrace(symbolized=True)
    crash_stacktrace_output = utils.get_crash_stacktrace_output(
        command, symbolized_crash_stacktrace, unsymbolized_crash_stacktrace)
  else:
    status = data_types.TestcaseVariantStatus.UNREPRODUCIBLE
    is_similar = False
    crash_type = None
    crash_state = None
    security_flag = False
    crash_stacktrace_output = 'No crash occurred.'

  # Regular case of variant analysis.
  uworker_input.variant.status = status
  uworker_input.variant.revision = revision
  uworker_input.variant.crash_type = crash_type
  uworker_input.variant.crash_state = crash_state
  uworker_input.variant.security_flag = security_flag
  uworker_input.variant.is_similar = is_similar
  uworker_input.variant.platform = environment.platform().lower()

  return uworker_io.UworkerOutput(
      testcase=uworker_input.testcase,
      variant=uworker_input.variant,
      crash_stacktrace_output=crash_stacktrace_output)


def handle_build_setup_error(output):
  testcase = data_handler.get_testcase_by_id(output.uworker_input.testcase_id)
  data_handler.update_testcase_comment(
      testcase, data_types.TaskState.ERROR,
      f'Build setup failed with job: {output.uworker_input.testcase_id}')


HANDLED_ERRORS = [
    uworker_msg_pb2.ErrorType.VARIANT_BUILD_SETUP,
    uworker_msg_pb2.ErrorType.TESTCASE_SETUP,
    uworker_msg_pb2.ErrorType.UNHANDLED
]


def utask_postprocess(output):
  """Handle the output from utask_main."""
  if output.testcase and environment.is_engine_fuzzer_job(
      output.testcase.job_type):
    # Remove put() method to avoid updates. DO NOT REMOVE THIS.
    output.testcase.put = lambda: None

  if output.error is not None:
    uworker_handle_errors.handle(output, HANDLED_ERRORS)
    return

  if output.uworker_input.original_job_type == output.uworker_input.job_type:
    # This case happens when someone clicks 'Update last tested stacktrace using
    # trunk build' button.
    output.testcase.last_tested_crash_stacktrace = (
        data_handler.filter_stacktrace(output.crash_stacktrace_output))
    output.testcase.set_metadata(
        'last_tested_crash_revision',
        output.variant.revision,
        update_testcase=True)
  else:
    # Explicitly skipping crash stacktrace for now as it make entities larger
    # and we plan to use only crash paramaters in UI.
    output.variant.put()
