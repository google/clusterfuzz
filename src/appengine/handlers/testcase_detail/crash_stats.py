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
"""Handler for showing crash stats inside the testcase detail page."""

from flask import request

from handlers import base_handler
from libs import crash_stats
from libs import handler
from libs import helpers


def get_result(testcase, end, block, days, group_by):
  """Get slots for crash stats."""
  query = crash_stats.Query()
  query.group_by = group_by
  query.sort_by = 'total_count'
  query.set_time_params(end, days, block)

  query.filter('crash_type', testcase.crash_type)
  query.filter('crash_state', testcase.crash_state)
  query.filter('security_flag', testcase.security_flag)

  _, rows = crash_stats.get(query, crash_stats.Query(), 0, 1)

  if not rows:
    return {'end': end, 'days': days, 'block': block, 'groups': []}

  return rows[0]


class Handler(base_handler.Handler):
  """Serve crash stats data on testcase detail."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_testcase_access
  def post(self, testcase):
    """Server crash stats."""
    end = helpers.cast(request.get('end'), int, "'end' is not an int.")
    days = helpers.cast(request.get('days'), int, "'days' is not an int.")
    group_by = helpers.cast(
        request.get('groupBy'), str, "'groupBy' is not a string.")
    block = helpers.cast(request.get('block'), str, "'block' is not a string.")
    return self.render_json(get_result(testcase, end, block, days, group_by))
