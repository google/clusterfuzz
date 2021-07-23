# Copyright 2020 Google LLC
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
"""Handler for the crash query api."""

from flask import request

from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.datastore import data_handler
from handlers import base_handler
from libs import auth
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Handler for crash querying."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    """Handle a post request."""
    if not auth.get_current_user():
      raise helpers.AccessDeniedException()

    project = request.get('project')
    fuzz_target = request.get('fuzz_target')
    stacktrace = request.get('stacktrace')

    state = stack_analyzer.get_crash_data(
        stacktrace,
        symbolize_flag=False,
        fuzz_target=fuzz_target,
        already_symbolized=True,
        detect_ooms_and_hangs=True)
    security_flag = crash_analyzer.is_security_issue(
        state.crash_stacktrace, state.crash_type, state.crash_address)

    result = {
        'state': state.crash_state,
        'type': state.crash_type,
        'security': security_flag,
    }

    duplicate_testcase = data_handler.find_testcase(
        project, state.crash_type, state.crash_state, security_flag)
    if duplicate_testcase:
      result['result'] = 'duplicate'
      result['duplicate_id'] = duplicate_testcase.key.id()

      bug_id = (
          duplicate_testcase.bug_information or
          duplicate_testcase.group_bug_information)
      if bug_id:
        result['bug_id'] = str(bug_id)
    else:
      result['result'] = 'new'

    return self.render_json(result)
