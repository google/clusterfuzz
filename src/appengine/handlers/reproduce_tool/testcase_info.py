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
"""Handler for serving serialized test cases for the reproduce tool."""

from flask import request

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from handlers import base_handler
from libs import access
from libs import handler


def _prepare_testcase_dict(testcase):
  """Prepare a dictionary containing all information needed by the tool."""
  # By calling _to_dict directly here we prevent the need to modify this as
  # the testcase and other models changes over time.
  # pylint: disable=protected-access
  testcase_dict = testcase._to_dict()
  fuzz_target = data_handler.get_fuzz_target(testcase.actual_fuzzer_name())
  if fuzz_target:
    fuzz_target_dict = fuzz_target._to_dict()
  else:
    fuzz_target_dict = None
  # pylint: enable=protected-access

  # Several nonstandard bits of information are required for the tool to run.
  # Append these to the test case dict and serialize them as well.
  job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
  testcase_dict['job_definition'] = job.get_environment_string()
  testcase_dict['serialized_fuzz_target'] = fuzz_target_dict

  return testcase_dict


class Handler(base_handler.Handler):
  """Handler that returns a serialized testcase as JSON."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    """Serve the testcase JSON."""
    testcase_id = request.get('testcaseId')
    testcase = access.check_access_and_get_testcase(testcase_id)

    testcase_dict = _prepare_testcase_dict(testcase)
    return self.render_json(testcase_dict)
