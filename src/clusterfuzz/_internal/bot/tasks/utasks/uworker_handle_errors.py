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
from clusterfuzz._internal.bot.tasks.utasks import uworker_errors


def noop(*args, **kwargs):
  del args
  del kwargs


def handle(error_or_output):
  # TODO(metzman): Once every task supports utasks we can stop handling errors
  # objects directly and only handle utask output objects.
  if isinstance(error_or_output, uworker_errors.Error):
    error_type = error_or_output.type
  else:
    error_type = error_or_output.error.type
  return MAPPING[error_type](error_or_output)


MAPPING = {
    uworker_errors.Type.ANALYZE_NO_CRASH:
        analyze_task.handle_noncrash,
    uworker_errors.Type.ANALYZE_BUILD_SETUP:
        analyze_task.handle_build_setup_error,
    uworker_errors.Type.TESTCASE_SETUP:
        setup.handle_testcase_setup_error,
    uworker_errors.Type.NO_FUZZER:
        noop,
}
