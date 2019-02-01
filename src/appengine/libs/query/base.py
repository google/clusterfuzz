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
"""Represent the interface for Query. This is important because our access
  control logic needs a unified way to specify conditions for both BigQuery
  query and Datastore query.

  This must be compatible with libs.filters and libs.crash_access."""


class Query(object):
  """Represent the interface for Query."""

  def filter(self, field, value, operator='='):
    """Filter by a single value."""
    raise NotImplementedError

  def filter_in(self, field, values):
    """Filter by multiple values."""
    raise NotImplementedError

  def union(self, *queries):
    """Union all queries with OR conditions."""
    raise NotImplementedError

  def new_subquery(self):
    """Instantiate a query that is compatible with the current query."""
    raise NotImplementedError
