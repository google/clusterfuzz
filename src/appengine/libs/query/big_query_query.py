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
"""Query handles constructing BigQuery's SQL."""

from collections.abc import Sequence
import json
from typing import Any

from libs.query import base


class Query(base.Query):
  """Represent a query for BigQuery's query. Named parameter mode is used."""

  def __init__(self) -> None:
    self.conditions: list[str] = []
    self.or_groups: list[Sequence[Query]] = []
    self.sort_by: str | None = None

  def raw_filter(self, cond: str) -> None:
    """Add raw filter directly."""
    self.conditions.append(cond)

  def filter(self, field: str, value: Any, operator: str = '=') -> None:
    """Filter by a single value."""
    # json.dumps converts Python literals to BigQuery literals perfectly well.
    # See tests.
    self.conditions.append('%s %s %s' % (field, operator, json.dumps(value)))

  def filter_in(self, field: str, values: Sequence[Any]) -> None:
    """Filter by multiple values."""
    literals = [json.dumps(v) for v in values]
    self.conditions.append('%s IN (%s)' % (field, ', '.join(literals)))

  def union(self, *queries: Any) -> None:
    """Combine queries with OR conditions."""
    self.or_groups.append(queries)

  def new_subquery(self) -> 'Query':
    """Generate a new subquery."""
    return Query()

  def get_where_clause(self) -> str:
    """Get the where clause."""
    subquery_wheres = []
    for or_queries in self.or_groups:
      or_cond = ' OR '.join([sub.get_where_clause() for sub in or_queries])
      subquery_wheres.append('(%s)' % or_cond)

    all_conds = self.conditions + subquery_wheres

    if not all_conds:
      return ''

    return '(%s)' % ' AND '.join(all_conds)
