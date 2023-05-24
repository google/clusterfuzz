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
from clusterfuzz._internal.protos import uworker_msg_pb2


def noop(*args, **kwargs):
  del args
  del kwargs


def handle(output):
  """Handles the errors bubbled up from the uworker."""
  return MAPPING[output.error](output)


MAPPING = {
    uworker_msg_pb2.ErrorType.ANALYZE_NO_CRASH:
        analyze_task.handle_noncrash,
    uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP:
        analyze_task.handle_build_setup_error,
    uworker_msg_pb2.ErrorType.TESTCASE_SETUP:
        setup.handle_setup_testcase_error,
    uworker_msg_pb2.ErrorType.UNHANDLED:
        noop,
}
