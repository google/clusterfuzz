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
"""Common functionality for the crash stats page and the crash stats in the
  testcase detail page. This can't be with common.crash_stats because it imports
  specific libraries on appengine."""

from clusterfuzz._internal.metrics import crash_stats
from libs import helpers
from libs.query import big_query_query

# We don't allow showing more than 3 days when viewing by hours because it'd
# break the UI.
MAX_DAYS_FOR_BY_HOURS = 3


class Query(big_query_query.Query):
  """A query class for crash stats. It contains two additional fields."""

  def __init__(self):
    self.end = None
    self.days = None
    self.block = None
    self.group_by = None
    super(Query, self).__init__()

  def set_time_params(self, end, days, block):
    """Set time-related params."""
    if block == 'hour' and days > MAX_DAYS_FOR_BY_HOURS:
      raise helpers.EarlyExitException(
          ('When viewing by hours, selecting more than %d days is not allowed.'
           % MAX_DAYS_FOR_BY_HOURS), 400)

    # `hour` is inclusive. It includes the count between [hour, hour + 1). But,
    # on the UI, the end time is the last border. Therefore, we have to -1.
    self.end = end - 1
    self.days = days
    self.block = block


def get(query, group_query, offset, limit):
  """Query from BigQuery given the query object."""
  return crash_stats.get(
      end=query.end,
      days=query.days,
      block=query.block,
      group_by=query.group_by,
      where_clause=query.get_where_clause(),
      group_having_clause=group_query.get_where_clause(),
      sort_by=query.sort_by,
      offset=offset,
      limit=limit)
