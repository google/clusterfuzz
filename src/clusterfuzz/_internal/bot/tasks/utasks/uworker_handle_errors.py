# Copyright 2023 Google LLC
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
"""Module for handling errors in utasks."""
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.bot.tasks.utasks import minimize_task
from clusterfuzz._internal.bot.tasks.utasks import progression_task
from clusterfuzz._internal.bot.tasks.utasks import variant_task
from clusterfuzz._internal.protos import uworker_msg_pb2


def noop(*args, **kwargs):
  del args
  del kwargs


def handle(output, handled_errors):
  """Handles the errors bubbled up from the uworker."""
  if output.error not in handled_errors:
    error = '<None>' if output.error is None else output.error
    raise RuntimeError('Can\'t handle ' + error)
  return get_handle_all_errors_mapping()[output.error](output)


def get_all_handled_errors():
  return set(get_handle_all_errors_mapping().keys())


def get_handle_all_errors_mapping():
  """Returns a mapping of all uworker errors to their postprocess handlers."""
  mapping = {
      uworker_msg_pb2.ErrorType.MINIMIZE_SETUP:
          minimize_task.handle_minimize_setup_error,
      uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH:
          analyze_task.handle_noncrash,
      uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP:
          analyze_task.handle_build_setup_error,
      uworker_msg_pb2.ErrorType.ANALYZE_NO_REVISIONS_LIST:
          analyze_task.handle_analyze_no_revisions_list_error,
      uworker_msg_pb2.ANALYZE_NO_REVISION_INDEX:
          analyze_task.handle_analyze_no_revision_index,
      uworker_msg_pb2.ErrorType.FUZZ_NO_FUZZER:
          fuzz_task.handle_fuzz_no_fuzzer,
      uworker_msg_pb2.ErrorType.FUZZ_BUILD_SETUP_FAILURE:
          fuzz_task.handle_fuzz_build_setup_failure,
      uworker_msg_pb2.ErrorType.FUZZ_DATA_BUNDLE_SETUP_FAILURE:
          fuzz_task.handle_fuzz_data_bundle_setup_failure,
      uworker_msg_pb2.ErrorType.TESTCASE_SETUP:
          setup.handle_setup_testcase_error,
      uworker_msg_pb2.ErrorType.VARIANT_BUILD_SETUP:
          variant_task.handle_build_setup_error,
      uworker_msg_pb2.ErrorType.PROGRESSION_REVISION_LIST_ERROR:
          progression_task.handle_progression_revision_list_error,
      uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_NOT_FOUND:
          progression_task.handle_progression_build_not_found,
      uworker_msg_pb2.ErrorType.PROGRESSION_BAD_STATE_MIN_MAX:
          progression_task.handle_progression_bad_state_min_max,
      uworker_msg_pb2.ErrorType.PROGRESSION_NO_CRASH:
          progression_task.handle_progression_no_crash,
      uworker_msg_pb2.ErrorType.PROGRESSION_TIMEOUT:
          progression_task.handle_progression_timeout,
      uworker_msg_pb2.ErrorType.PROGRESSION_BAD_BUILD:
          progression_task.handle_progression_bad_build,
      uworker_msg_pb2.ErrorType.PROGRESSION_BUILD_SETUP:
          progression_task.handle_progression_build_setup_error,
      uworker_msg_pb2.ErrorType.UNHANDLED:
          noop,
  }
  return mapping
