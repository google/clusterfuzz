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
"""datastore_query tests."""
# pylint: disable=protected-access
import datetime
import unittest

from google.cloud import ndb
import mock
import six

from clusterfuzz._internal.tests.test_libs import test_utils
from libs.query import datastore_query


class TestDatastoreModel(ndb.Model):
  tokens = ndb.StringProperty(repeated=True)
  boolean_value = ndb.BooleanProperty()
  datetime_value = ndb.DateTimeProperty()


def _create_data(self):
  """Create test data."""
  self.mocks = []
  for i in range(30):
    m = TestDatastoreModel()
    if (i % 2) == 0:
      m.tokens = ['a']
      m.boolean_value = True
    else:
      m.tokens = ['b']
      m.boolean_value = False
    m.datetime_value = datetime.datetime.fromtimestamp(100 - i)
    m.put()
    self.mocks.append(m)


@test_utils.with_cloud_emulators('datastore')
class KeyQueryTest(unittest.TestCase):
  """Test KeyQuery."""

  def setUp(self):
    _create_data(self)

  def test_empty(self):
    """Test when there's no record."""
    query = datastore_query._KeyQuery(TestDatastoreModel)
    query.filter('=', 'tokens', 'c')
    query.order('datetime_value', True)

    items, count, has_more = query.fetch(offset=0, limit=10, more_limit=20)
    self.assertListEqual([], items)
    self.assertEqual(0, count)
    self.assertFalse(has_more)

  def test_no_or_condition(self):
    """Test no OR condition."""
    query = datastore_query._KeyQuery(TestDatastoreModel)
    query.filter('=', 'tokens', 'a')
    query.order('datetime_value', True)

    items, count, has_more = query.fetch(offset=8, limit=2, more_limit=10)
    self.assertListEqual([self.mocks[16].key.id(), self.mocks[18].key.id()],
                         [item.key.id() for item in items])
    self.assertEqual(15, count)
    self.assertFalse(has_more)

  def test_or_condition(self):
    """Test OR conditions."""
    query = datastore_query._KeyQuery(TestDatastoreModel)
    query.filter('IN', 'tokens', ['a', 'b', 'c'])
    query.filter('IN', 'boolean_value', [True, False])
    query.order('datetime_value', True)

    queries = query.flatten()
    for q in queries:
      self.assertListEqual([], q.or_filters)
      self.assertEqual('datetime_value', q.order_property)
      self.assertTrue(q.order_desc)

    def _make(token, boolean):
      return [('=', 'tokens', token), ('=', 'boolean_value', boolean)]

    self.assertEqual(6, len(queries))
    self.assertListEqual(_make('a', True), queries[0].filters)
    self.assertListEqual(_make('b', True), queries[1].filters)
    self.assertListEqual(_make('c', True), queries[2].filters)
    self.assertListEqual(_make('a', False), queries[3].filters)
    self.assertListEqual(_make('b', False), queries[4].filters)
    self.assertListEqual(_make('c', False), queries[5].filters)

    items, count, has_more = query.fetch(offset=8, limit=2, more_limit=40)
    self.assertListEqual([self.mocks[8].key.id(), self.mocks[9].key.id()],
                         [item.key.id() for item in items])
    self.assertEqual(30, count)
    self.assertFalse(has_more)

  def test_get_more(self):
    """Test multiple OR conditions and get more items for total count."""
    query = datastore_query._KeyQuery(TestDatastoreModel)
    query.filter('IN', 'tokens', ['a', 'b'])
    query.order('datetime_value', True)

    items, count, has_more = query.fetch(offset=8, limit=2, more_limit=15)
    self.assertListEqual([self.mocks[8].key.id(), self.mocks[9].key.id()],
                         [item.key.id() for item in items])
    self.assertEqual(25, count)
    self.assertTrue(has_more)

  def test_has_more_but_not_get_more(self):
    """Test multiple OR conditions and compute total count from the current
      result."""
    query = datastore_query._KeyQuery(TestDatastoreModel)
    query.filter('IN', 'tokens', ['a', 'b'])
    query.order('datetime_value', True)

    items, count, has_more = query.fetch(offset=8, limit=2, more_limit=5)
    self.assertListEqual([self.mocks[8].key.id(), self.mocks[9].key.id()],
                         [item.key.id() for item in items])
    self.assertEqual(15, count)
    self.assertTrue(has_more)


@test_utils.with_cloud_emulators('datastore')
class QueryTest(unittest.TestCase):
  """Test Query."""

  def setUp(self):
    _create_data(self)

  def test_third_page(self):
    """Test getting the third page with more total count."""
    query = datastore_query.Query(TestDatastoreModel)
    query.filter_in('tokens', ['a', 'b'])
    query.filter('boolean_value', True)
    query.order('datetime_value', is_desc=True)

    items, total_pages, total_items, has_more = query.fetch_page(
        page=3, page_size=2, projection=['tokens'], more_limit=4)
    self.assertListEqual([self.mocks[8].key.id(), self.mocks[10].key.id()],
                         [item.key.id() for item in items])
    self.assertListEqual([['a'], ['a']], [item.tokens for item in items])
    with self.assertRaises(ndb.UnprojectedPropertyError):
      _ = [item.boolean_value for item in items]
    self.assertEqual(10, total_items)
    self.assertEqual(5, total_pages)
    self.assertTrue(has_more)

  def test_greater_or_equal(self):
    """Test that a query using an operator other than "=" works."""
    query = datastore_query.Query(TestDatastoreModel)
    query.filter(
        'datetime_value', datetime.datetime.fromtimestamp(96), operator='>=')
    query.order('datetime_value', is_desc=True)
    _, total_count, has_more = query.fetch(
        offset=0, limit=100, projection=['tokens'], more_limit=100)

    # We expect the above query to return values from 96-100.
    self.assertEqual(total_count, 5)
    self.assertFalse(has_more)

  def test_negative_page(self):
    """Test getting a negative page."""
    query = datastore_query.Query(TestDatastoreModel)
    query.filter_in('tokens', ['a', 'b'])
    query.filter('boolean_value', True)
    query.order('datetime_value', is_desc=True)

    items, total_pages, total_items, has_more = query.fetch_page(
        page=-5, page_size=2, projection=['tokens'], more_limit=4)
    self.assertListEqual([self.mocks[0].key.id(), self.mocks[2].key.id()],
                         [item.key.id() for item in items])
    self.assertListEqual([['a'], ['a']], [item.tokens for item in items])
    with self.assertRaises(ndb.UnprojectedPropertyError):
      _ = [item.boolean_value for item in items]
    self.assertEqual(6, total_items)
    self.assertEqual(3, total_pages)
    self.assertTrue(has_more)


class QueryWrapper(ndb.Query):
  """Query wrapper for easy mocking."""

  def __init__(self, wrapped, results, subqueries):  # pylint: disable=super-init-not-called
    self.wrapped = wrapped
    self.results = results
    self.subqueries = subqueries

  def filter(self, *args):
    """Wraps the result from filter()."""
    query = QueryWrapper(
        ndb.Query.filter(self.wrapped, *args), self.results, self.subqueries)
    self.subqueries.append(query)
    return query

  def order(self, *args):
    """Wraps the result from order()."""
    query = QueryWrapper(
        ndb.Query.order(self.wrapped, *args), self.results, self.subqueries)
    self.subqueries.append(query)
    return query

  def fetch(self, limit=None, **kwargs):  # pylint: disable=unused-argument
    """Wraps fetch()."""
    return self.results

  def iter(self, **kwargs):  # pylint: disable=unused-argument
    m = mock.MagicMock()
    m.__iter__.return_value = self.results
    m.cursor_after.return_value = None
    return m

  def __getattr__(self, attr):
    """Forward all other getters to the actual ndb.Query."""
    return getattr(self.wrapped, attr)


@test_utils.with_cloud_emulators('datastore')
class QueryMockTest(unittest.TestCase):
  """Test Query with mocks. This test is important because we want to make sure
    we call the underlying query correctly."""

  def setUp(self):
    original_query = TestDatastoreModel.query

    def get_query(*args, **kwargs):
      """Mock query."""
      query = original_query(*args, **kwargs)
      item = mock.MagicMock()
      item.key = ndb.Key(TestDatastoreModel, len(self.queries))
      item.datetime_value = datetime.datetime.utcnow()

      self.queries.append([query])
      return QueryWrapper(query, [item], self.queries[-1])

    self.queries = []
    patcher = mock.patch.object(TestDatastoreModel, 'query')
    mock_query = patcher.start()
    mock_query.side_effect = get_query
    self.addCleanup(patcher.stop)

  def test_third_page(self):
    """Test getting the third page with more total count."""
    query = datastore_query.Query(TestDatastoreModel)
    query.filter_in('tokens', ['a', 'b'])
    query.filter('boolean_value', True)
    query.order('datetime_value', is_desc=True)

    query.fetch_page(page=1, page_size=2, projection=['tokens'], more_limit=4)

    self.assertIsInstance(self.queries[0][-1].filters, ndb.AND)
    six.assertCountEqual(self, [
        ('tokens', '=', 'a'),
        ('boolean_value', '=', True),
    ], [f.__getnewargs__() for f in self.queries[0][-1].filters])

    self.assertIsInstance(self.queries[1][-1].filters, ndb.AND)
    six.assertCountEqual(self, [
        ('tokens', '=', 'b'),
        ('boolean_value', '=', True),
    ], [f.__getnewargs__() for f in self.queries[1][-1].filters])

    self.assertIsInstance(self.queries[2][-1].filters, ndb.OR)

    expected = []
    for item in [f.__getnewargs__() for f in self.queries[2][-1].filters]:
      expected.append((item[0], item[1], repr(item[2])))

    six.assertCountEqual(self, [
        ('__key__', '=',
         '<Key(\'TestDatastoreModel\', 0), project=test-clusterfuzz>'),
        ('__key__', '=',
         '<Key(\'TestDatastoreModel\', 1), project=test-clusterfuzz>'),
    ], expected)


class ComputeProjectionTest(unittest.TestCase):
  """Test compute_projection."""

  def test_none(self):
    """Test when projection is None."""
    self.assertIsNone(datastore_query.compute_projection(None, 'order_field'))

  def test_combine(self):
    """Test combine."""
    self.assertSetEqual(
        set(['a', 'b', 'c']),
        set(datastore_query.compute_projection(['a', 'c'], 'b')))

  def test_dedup(self):
    """Test dedup."""
    self.assertSetEqual(
        set(['a', 'b', 'c']),
        set(datastore_query.compute_projection(['a', 'b', 'c'], 'b')))
