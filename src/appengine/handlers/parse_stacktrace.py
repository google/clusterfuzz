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
"""Handler for parsing stacktrace."""

import os

from crash_analysis.stack_parsing import stack_analyzer
from datastore import data_types
from handlers import base_handler
from libs import handler


def parse(stacktrace, job_name):
  """Parse a stacktrace and return state, address, and type in dict."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if job:
    os.environ.update(job.get_environment())

  state = stack_analyzer.get_crash_data(stacktrace, symbolize_flag=False)

  return {
      'crash_type': state.crash_type,
      'crash_address': state.crash_address,
      'crash_state': state.crash_state
  }


class Handler(base_handler.Handler):
  """Handler that parses stacktrace."""

  @handler.post(handler.JSON, handler.JSON)
  def post(self):
    """Remove the issue from the testcase."""
    self.render_json(
        parse(self.request.get('stacktrace'), self.request.get('job')))
