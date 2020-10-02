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
"""Query handles pagination and OR conditions with its best effort."""

from google.cloud.ndb import exceptions

from libs.query import base


def _get_key_fn(attribute_name):
  """Return the function to get attr of an item. This is used in sorting."""

  def get_key(item):
    return getattr(item, attribute_name)

  return get_key


def compute_projection(projection, order_property):
  """Set projection."""
  if projection is None:
    return None

  combined_projection = set(projection)
  combined_projection.add(order_property)
  return list(combined_projection)


def _combine(q1, q2):
  """Combine KeyQuery q1 and q2. We ignore or_filters because we assume q1 and
    q2 are flat. In other words, they are results of _KeyQuery.flatten(..)."""
  assert not q1.or_filters
  assert not q2.or_filters
  assert q1.order_property == q2.order_property
  assert q1.order_desc == q2.order_desc

  result = _KeyQuery(q1.model)
  result.filters = q1.filters + q2.filters
  result.order_property = q1.order_property
  result.order_desc = q1.order_desc
  return result


class _Run(object):
  """Encapsulate a query and its run."""

  def __init__(self, query, **kwargs):
    self.query = query
    self.result = query.iter(**kwargs)


class _KeyQuery(object):
  """Query only keys. It supports an OR condition."""

  def __init__(self, model):
    self.model = model
    self.or_filters = []
    self.filters = []
    self.order_property = None
    self.order_desc = False

  def union(self, *queries):
    """Specify the OR condition."""
    self.or_filters.append(queries)

  def filter(self, operator, prop, value):
    """Specify the filter."""
    if operator == 'IN':
      subqueries = []
      for v in value:
        q = _KeyQuery(self.model)
        q.filter('=', prop, v)
        subqueries.append(q)
      self.union(*subqueries)
    else:
      self.filters.append((operator, prop, value))

  def order(self, prop, is_desc):
    """Specify the order."""
    self.order_property, self.order_desc = prop, is_desc

  def flatten(self):
    """Flatten self into multiple queries if or_filters is not empty."""
    if not self.or_filters:
      return [self]

    for qs in self.or_filters:
      for q in qs:
        q.order(self.order_property, self.order_desc)

    queries = []
    for query in self.or_filters[0]:
      for q in query.flatten():
        queries.append(q)

    for or_queries in self.or_filters[1:]:
      new_queries = []
      for oq in or_queries:
        for fq in oq.flatten():
          for q in queries:
            new_queries.append(_combine(q, fq))
      queries = new_queries

    for q in queries:
      for (prop_op, prop, value) in self.filters:
        q.filter(prop_op, prop, value)

    return queries

  def to_datastore_query(self):
    """Return the corresponding datastore query."""
    assert not self.or_filters

    query = self.model.query()
    properties = self.model._properties  # pylint: disable=protected-access
    for (prop_op, prop, value) in self.filters:
      if prop_op == '=':
        filter_func = properties[prop].__eq__
      elif prop_op == '!=':
        filter_func = properties[prop].__ne__
      elif prop_op == '<':
        filter_func = properties[prop].__le__
      elif prop_op == '>':
        filter_func = properties[prop].__gt__
      elif prop_op == '<=':
        filter_func = properties[prop].__le__
      elif prop_op == '>=':
        filter_func = properties[prop].__ge__

      query = query.filter(filter_func(value))

    if self.order_property:
      order_property = properties[self.order_property]
      if self.order_desc:
        order_property = -order_property

      query = query.order(order_property)

    return query

  def _build_runs(self, total):
    """Construct queries and run them."""
    queries = self.flatten()

    runs = []
    # TODO(tanin): Improve the speed by detecting if we need union (or OR).
    # If we don't need union, we can set keys_only=True and projection=None in
    # order to improve speed; it's likely to be 2x faster.
    for q in queries:
      runs.append(
          _Run(
              q.to_datastore_query(),
              keys_only=False,
              projection=[self.order_property],
              limit=total))
    return runs

  def _get_total_count(self, runs, offset, limit, items, more_limit):
    """Get total count by querying more items."""
    max_total_count = offset + limit + more_limit
    current_count = len(items)

    if current_count > max_total_count:
      return max_total_count, True

    more_limit += 1
    more_runs = []
    for run in runs:
      try:
        cursor = run.result.cursor_after()
      except exceptions.BadArgumentError:
        # iterator had no results.
        cursor = None

      more_runs.append(
          _Run(
              run.query,
              start_cursor=cursor,
              keys_only=True,
              projection=None,
              limit=more_limit))

    keys = {item.key.id() for item in items}
    for run in more_runs:
      for key in run.result:
        keys.add(key)

    total_count = min(len(keys), max_total_count)
    has_more = len(keys) >= max_total_count

    return total_count, has_more

  def fetch(self, offset, limit, more_limit):
    """Construct multiple queries based on the or_filters, query them,
      combined the results, return items and total_count."""
    runs = self._build_runs(offset + limit)

    items = {}
    for run in runs:
      for item in run.result:
        if item.key.id() not in items:
          items[item.key.id()] = item

    items = sorted(
        list(items.values()),
        reverse=self.order_desc,
        key=_get_key_fn(self.order_property))

    total_count, has_more = self._get_total_count(runs, offset, limit, items,
                                                  more_limit)

    return items[offset:(offset + limit)], total_count, has_more


class Query(base.Query):
  """Query that returns items with a smart count. A smart count indicates
    a lowerbound of the total count (e.g. 500+)."""

  def __init__(self, model):
    self.model = model
    self.key_query = _KeyQuery(model)
    self.order_property = None
    self.order_desc = False

  def filter(self, field, value, operator='='):
    """Specify the filter."""
    self.key_query.filter(operator, field, value)

  def filter_in(self, field, values):
    """Specify the filter IN."""
    self.key_query.filter('IN', field, values)

  def union(self, *queries):
    """Specify the OR condition."""
    self.key_query.union(*[q.key_query for q in queries])

  def new_subquery(self):
    """Generate a new subquery with the same model."""
    return Query(self.model)

  def order(self, field, is_desc):
    """Specify the order."""
    self.order_property = field
    self.order_desc = is_desc
    self.key_query.order(field, is_desc)

  def fetch(self, offset, limit, projection, more_limit):
    """Return the items, the total count, and if there are more number of items
      than the total count."""
    assert self.order_property

    keys, total_count, has_more = self.key_query.fetch(
        limit=limit, offset=offset, more_limit=more_limit)

    if keys:
      item_query = self.key_query.model.query(
          self.key_query.model.key.IN([key.key for key in keys]))

      items = item_query.fetch(
          limit=limit,
          projection=compute_projection(projection, self.order_property))
      items = sorted(
          items, reverse=self.order_desc, key=_get_key_fn(self.order_property))
    else:
      items = []

    return items, total_count, has_more

  def fetch_page(self, page, page_size, projection, more_limit):
    """Return the items, total_pages, total_items, and has_more."""

    # Validation check to convert all negative page numbers to 1.
    if page < 1:
      page = 1

    items, total_items, has_more = self.fetch(
        offset=(page - 1) * page_size,
        limit=page_size,
        projection=projection,
        more_limit=more_limit)

    total_pages = total_items // page_size
    if (total_items % page_size) > 0:
      total_pages += 1

    return items, total_pages, total_items, has_more
