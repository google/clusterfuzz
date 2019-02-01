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
"""Tests for ndb_patcher."""

import datetime
import unittest

from google.appengine.ext import ndb

from datastore import ndb_patcher
from system import environment
from tests.test_libs import helpers
from tests.test_libs import test_utils


class OldTestModel(ndb.Model):
  """Old version of TestModel."""
  prop_0 = ndb.StringProperty()
  prop_1 = ndb.BlobProperty()
  prop_2 = ndb.IntegerProperty()
  prop_3 = ndb.StringProperty(repeated=True)
  prop_4 = ndb.DateTimeProperty()
  old_prop = ndb.BlobProperty()

  @classmethod
  def _get_kind(cls):
    """Kind override."""
    return 'TestModel'


class TestModel(ndb.Model):
  """Test model."""
  prop_0 = ndb.StringProperty()
  prop_1 = ndb.BlobProperty()
  prop_2 = ndb.IntegerProperty()
  prop_3 = ndb.StringProperty(repeated=True)
  prop_4 = ndb.DateTimeProperty()


class TestModel2(ndb.Model):
  """Test model."""
  prop_0 = ndb.TextProperty()
  prop_1 = ndb.FloatProperty()
  prop_2 = ndb.DateProperty()
  prop_3 = ndb.TimeProperty()
  prop_4 = ndb.KeyProperty()
  prop_5 = ndb.ComputedProperty(lambda self: self.prop_1 * 10)


class TestModel3(ndb.Model):
  """Test model."""
  prop_0 = ndb.IntegerProperty()
  prop_1 = ndb.IntegerProperty()
  prop_2 = ndb.IntegerProperty()

  def _pre_put_hook(self):
    self.prop_1 = self.prop_0 + 1

  def _post_put_hook(self, _):
    self.prop_2 = self.key.id()


@unittest.skipIf(not environment.get_value('NDB_PATCHER_TESTS'),
                 'Skipping NDB patcher tests.')
@test_utils.with_cloud_emulators('datastore')
class NdbPatcherTest(unittest.TestCase):
  """Tests for ndb_patcher."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'system.environment.is_running_on_app_engine',
    ])

    self.mock.is_running_on_app_engine.return_value = False

    ndb_patcher.init()
    ndb_patcher.patch_ndb()

    self.populate_test_data()

  def tearDown(self):
    ndb_patcher.unpatch_ndb()

  def populate_test_data(self):
    """Populate test data."""
    self.model_0 = TestModel(
        id='0',
        prop_0='123',
        prop_1='\xff456',
        prop_2=111,
        prop_3=['1', '3'],
        prop_4=datetime.datetime(2018, 1, 1, 1, 0))
    self.model_1 = TestModel(
        id='1',
        prop_0='123',
        prop_1='\xff789',
        prop_2=112,
        prop_3=['2', '3'],
        prop_4=datetime.datetime(2018, 2, 1, 1, 0))
    self.model_2 = TestModel(
        id='2',
        prop_0='123',
        prop_1='\xff789',
        prop_2=110,
        prop_3=['1', '4'],
        prop_4=datetime.datetime(2018, 2, 1, 1, 0))

    self.test_entities_model = [self.model_0, self.model_1, self.model_2]
    ndb.put_multi(self.test_entities_model)

    self.model2_0 = TestModel2(
        id='0',
        prop_0='123',
        prop_1=0.5,
        prop_2=datetime.date(2018, 1, 1),
        prop_3=datetime.time(12, 0, 0),
        prop_4=ndb.Key(TestModel, '0'))

    self.test_entities_model2 = [self.model2_0]
    ndb.put_multi(self.test_entities_model2)

  def test_get_by_key(self):
    """Test get_by_key."""
    entity = ndb.Key(TestModel, '0').get()
    self.assertEqual(ndb.Key(TestModel, '0'), entity.key)
    self.assertDictEqual(self.model_0.to_dict(), entity.to_dict())
    self.assertDictEqual(entity.to_dict(), entity.key.get().to_dict())

    entity = TestModel.get_by_id('0')
    self.assertEqual(ndb.Key(TestModel, '0'), entity.key)
    self.assertDictEqual(self.model_0.to_dict(), entity.to_dict())
    self.assertDictEqual(entity.to_dict(), entity.key.get().to_dict())

    entity = ndb.Key(TestModel, 'noexist').get()
    self.assertIsNone(entity)

  def test_get_multi(self):
    """Test get_multi."""
    keys = [
        ndb.Key(TestModel, '0'),
        ndb.Key(TestModel, '0'),
        ndb.Key(TestModel, 'doesnotexist'),
        ndb.Key(TestModel2, '0'),
        ndb.Key(TestModel, '1'),
    ]
    entities = ndb.get_multi(keys)

    self.assertListEqual([
        {
            'prop_4': datetime.datetime(2018, 1, 1, 1, 0),
            'prop_0': '123',
            'prop_1': '\xff456',
            'prop_2': 111,
            'prop_3': ['1', '3']
        },
        {
            'prop_4': datetime.datetime(2018, 1, 1, 1, 0),
            'prop_0': '123',
            'prop_1': '\xff456',
            'prop_2': 111,
            'prop_3': ['1', '3']
        },
        None,
        {
            'prop_0': u'123',
            'prop_1': 0.5,
            'prop_2': datetime.date(2018, 1, 1),
            'prop_3': datetime.time(12, 0),
            'prop_4': ndb.Key(TestModel, '0'),
            'prop_5': 5.0,
        },
        {
            'prop_4': datetime.datetime(2018, 2, 1, 1, 0),
            'prop_0': '123',
            'prop_1': '\xff789',
            'prop_2': 112,
            'prop_3': ['2', '3']
        },
    ], [entity.to_dict() if entity else None for entity in entities])

  def test_iterate_query_all(self):
    """Test iterate_query (no filters)."""
    entities = list(TestModel.query())
    self.assertItemsEqual([e.to_dict() for e in self.test_entities_model],
                          [e.to_dict() for e in entities])
    self.assertItemsEqual([e.key for e in self.test_entities_model],
                          [e.key for e in entities])

  def test_iterate_query_empty(self):
    """Test iterate_query (no results)."""
    entities = list(TestModel.query().filter(TestModel.prop_2 == 999))
    self.assertItemsEqual([], entities)

  def test_iterate_query_filters_equality(self):
    """Test iterate_query (with filters)."""
    entities = list(TestModel.query(TestModel.prop_0 == '123'))
    self.assertItemsEqual([e.to_dict() for e in self.test_entities_model],
                          [e.to_dict() for e in entities])
    self.assertItemsEqual([e.key for e in self.test_entities_model],
                          [e.key for e in entities])

    entities = list(TestModel.query(TestModel.prop_2 == 111))
    self.assertItemsEqual([e.to_dict() for e in (self.model_0,)],
                          [e.to_dict() for e in entities])
    self.assertItemsEqual([e.key for e in (self.model_0,)],
                          [e.key for e in entities])

  def test_iterate_query_filters_combined(self):
    """Test iterate_query (with combined filters)."""
    entities = list(
        TestModel.query(TestModel.prop_0 == '123').filter(
            TestModel.prop_2 > 110))
    self.assertItemsEqual([e.to_dict() for e in (self.model_0, self.model_1)],
                          [e.to_dict() for e in entities])
    self.assertItemsEqual([e.key for e in (self.model_0, self.model_1)],
                          [e.key for e in entities])

  def test_iterate_query_repeated_equality(self):
    """Test iterate_query (with repeated equality filter)."""
    entities = list(TestModel.query(TestModel.prop_3 == '3'))
    self.assertItemsEqual([e.to_dict() for e in (self.model_0, self.model_1)],
                          [e.to_dict() for e in entities])
    self.assertItemsEqual([e.key for e in (self.model_0, self.model_1)],
                          [e.key for e in entities])

  def test_iterate_query_order(self):
    """Test iterate_query (with order)."""
    entities = list(TestModel.query().order(TestModel.prop_2))
    self.assertListEqual(
        [e.key for e in (self.model_2, self.model_0, self.model_1)],
        [e.key for e in entities])

  def test_iterate_query_order_descend(self):
    """Test iterate_query (with descending order)."""
    entities = list(TestModel.query().order(-TestModel.prop_2))
    self.assertListEqual(
        [e.key for e in (self.model_1, self.model_0, self.model_2)],
        [e.key for e in entities])

  def test_iterate_query_multiple_order(self):
    """Test iterate_query (with multiple orders)."""
    entities = list(TestModel.query().order(TestModel.prop_2).order(
        TestModel.prop_4))
    self.assertListEqual(
        [e.key for e in (self.model_2, self.model_0, self.model_1)],
        [e.key for e in entities])

    entities = list(TestModel.query().order(TestModel.prop_4, TestModel.prop_2))
    self.assertListEqual(
        [e.key for e in (self.model_0, self.model_2, self.model_1)],
        [e.key for e in entities])

  def test_iterate_query_projection(self):
    """Test iterate_query (with repeated projection)."""
    test_methods = [
        lambda: list(TestModel.query(projection=['prop_2'])),
        lambda: list(TestModel.query(projection=[TestModel.prop_2])),
        lambda: list(TestModel.query().iter(projection=[TestModel.prop_2])),
        # Test precedence.
        lambda: list(TestModel.query(
            projection=[TestModel.prop_0]).iter(projection=[TestModel.prop_2])),
    ]

    for test_method in test_methods:
      entities = test_method()
      self.assertListEqual(
          [e.key for e in (self.model_2, self.model_0, self.model_1)],
          [e.key for e in entities])
      self.assertListEqual(
          [e.prop_2 for e in (self.model_2, self.model_0, self.model_1)],
          [e.prop_2 for e in entities])

      for i in xrange(len(self.test_entities_model)):
        with self.assertRaises(ndb.UnprojectedPropertyError):
          _ = entities[i].prop_0

        with self.assertRaises(ndb.UnprojectedPropertyError):
          _ = entities[i].prop_1

        with self.assertRaises(ndb.UnprojectedPropertyError):
          _ = entities[i].prop_3

  def test_get_from_query(self):
    """Test get_from_query."""
    entity = TestModel.query(TestModel.prop_2 == 111).get()
    self.assertDictEqual(self.model_0.to_dict(), entity.to_dict())
    self.assertEqual(self.model_0.key, entity.key)

  def test_get_from_query_none(self):
    """Test get_from_query (no results)."""
    entity = TestModel.query(TestModel.prop_2 == 211).get()
    self.assertIsNone(entity)

  def test_put(self):
    """Test put."""
    entity = TestModel(id='new', prop_0='new', prop_1='new', prop_2=9001)
    key = entity.put()
    self.assertEqual(entity.key, key)

    get_result = ndb.Key(TestModel, 'new').get()
    self.assertDictEqual(entity.to_dict(), get_result.to_dict())

  def test_put_autogenerate_key(self):
    """Test put with autogenerated key."""
    entity = TestModel(prop_0='new', prop_1='new', prop_2=9001)
    key = entity.put()
    self.assertEqual(entity.key, key)

    get_result = key.get()
    self.assertDictEqual(entity.to_dict(), get_result.to_dict())

  def test_put_multi(self):
    """Test put_multi."""
    entity_0 = TestModel(id='new_0', prop_0='new', prop_1='new', prop_2=9001)
    entity_1 = TestModel(prop_0='new', prop_1='new', prop_2=9001)

    keys = ndb.put_multi([entity_0, entity_1])
    self.assertEqual(keys[0], entity_0.key)
    self.assertEqual(keys[1], entity_1.key)

    get_result = ndb.Key(TestModel, 'new_0').get()
    self.assertDictEqual(entity_0.to_dict(), get_result.to_dict())

    get_result = keys[1].get()
    self.assertDictEqual(entity_1.to_dict(), get_result.to_dict())

  @test_utils.slow
  def test_large_multi(self):
    """Test large multi operations."""
    # Test large puts.
    entities = [TestModel() for _ in xrange(2000)]
    keys = ndb.put_multi(entities)

    results = ndb.get_multi(keys)
    for i in xrange(2000):
      self.assertIsNotNone(results[i])

    ndb.delete_multi(keys)
    results = ndb.get_multi(keys)
    self.assertTrue(all(result is None for result in results))

  def test_delete(self):
    """Test delete."""
    ndb.Key(TestModel, '0').delete()
    get_result = ndb.Key(TestModel, '0').get()

    self.assertIsNone(get_result)

  def test_delete_multi(self):
    """Test delete_multi."""
    ndb.delete_multi([
        ndb.Key(TestModel, '0'),
        ndb.Key(TestModel, '1'),
    ])

    get_result = ndb.Key(TestModel, '0').get()
    self.assertIsNone(get_result)

    get_result = ndb.Key(TestModel, '1').get()
    self.assertIsNone(get_result)

  def test_set_unindexed_property(self):
    """Test setting unindexed properties."""
    # Unindexed properties can store > the maximum 1500 bytes.
    data = 'A' * 2000
    entity_0 = TestModel(id='new_0', prop_1=data)
    entity_0.put()

    get_result = ndb.Key(TestModel, 'new_0').get()
    self.assertEqual(data, get_result.prop_1)

  def test_distinct(self):
    """Test distinct queries."""
    results = list(TestModel.query(projection=['prop_0'], distinct=True))
    self.assertListEqual(['123'], [result.prop_0 for result in results])

  def test_limit(self):
    """Test limit queries."""
    test_methods = [
        lambda: list(TestModel.query().iter(limit=1)),
        lambda: TestModel.query().fetch(limit=1),
    ]

    for test_method in test_methods:
      results = test_method()
      self.assertEqual(1, len(results))

  def test_in(self):
    """Test IN query."""
    results = TestModel.query(TestModel.prop_2.IN([110]))
    self.assertItemsEqual([self.model_2.key],
                          [result.key for result in results])

    results = TestModel.query(TestModel.prop_2.IN([110, 111]))
    self.assertItemsEqual([self.model_0.key, self.model_2.key],
                          [result.key for result in results])

    results = TestModel.query(TestModel.prop_2.IN([110, 111, 112]))
    self.assertItemsEqual(
        [self.model_0.key, self.model_1.key, self.model_2.key],
        [result.key for result in results])

  def test_or(self):
    """Test OR query."""
    results = TestModel.query(
        ndb.OR(TestModel.prop_2 == 110, TestModel.prop_2 == 111))
    self.assertItemsEqual([self.model_0.key, self.model_2.key],
                          [result.key for result in results])

  def test_not_equal(self):
    """Test != query."""
    results = TestModel.query(TestModel.prop_2 != 110)
    self.assertItemsEqual([self.model_0.key, self.model_1.key],
                          [result.key for result in results])

  def test_complex_query(self):
    """Test a complex query."""
    results = TestModel.query(
        ndb.AND(TestModel.prop_0 == '123', TestModel.prop_2 > 110),
        ndb.OR(
            TestModel.prop_2 == 111,
            ndb.AND(TestModel.prop_2 == 112, TestModel.prop_3.IN(['2', '3']))))
    self.assertItemsEqual([self.model_0.key, self.model_1.key],
                          [result.key for result in results])

  def test_count(self):
    """Test count()."""
    self.assertEqual(3, TestModel.query().count(limit=10))
    self.assertEqual(3, TestModel.query().count())
    self.assertEqual(2, TestModel.query().count(limit=2))
    self.assertEqual(1, TestModel.query().count(limit=1))
    self.assertEqual(0, TestModel.query().count(limit=0))

  def test_put_hook(self):
    """Test put hooks."""
    entity = TestModel3(prop_0=0)
    entity.put()
    self.assertEqual(1, entity.prop_1)
    self.assertEqual(entity.key.id(), entity.prop_2)

    self.assertDictEqual({
        'prop_0': 0,
        'prop_1': 1,
        'prop_2': None,
    },
                         entity.key.get().to_dict())

    entities = [TestModel3(id=entity.key.id(), prop_0=0), TestModel3(prop_0=1)]
    ndb.put_multi(entities)
    self.assertEqual(1, entities[0].prop_1)
    self.assertEqual(entities[0].key.id(), entities[0].prop_2)
    self.assertEqual(2, entities[1].prop_1)
    self.assertEqual(entities[1].key.id(), entities[1].prop_2)

    self.assertItemsEqual([
        {
            'prop_0': 0,
            'prop_1': 1,
            'prop_2': None,
        },
        {
            'prop_0': 1,
            'prop_1': 2,
            'prop_2': None,
        },
    ], [e.to_dict() for e in TestModel3.query()])

  def test_keys_only(self):
    """Test keys only queries."""
    result = list(TestModel.query().iter(keys_only=True))
    self.assertItemsEqual([
        ndb.Key(TestModel, '0'),
        ndb.Key(TestModel, '1'),
        ndb.Key(TestModel, '2'),
    ], result)

  def test_get_with_deleted_attribute(self):
    """Test get with deleted attribute."""
    old = OldTestModel(
        id='old',
        prop_0='123',
        prop_1='\xff',
        prop_2=345,
        prop_3=['123'],
        old_prop='\x90')
    old.put()

    # App Engine magically sets non-existent properties, but the
    # gcloud.datastore implementation doesn't and we shouldn't ever use them.
    entity = ndb.Key(TestModel, 'old').get()
    expected = old.to_dict()
    del expected['old_prop']
    self.assertDictEqual(expected, entity.to_dict())

  def test_or_query_with_order(self):
    """Test unsupported OR query with order."""
    with self.assertRaises(ndb_patcher.NdbPatcherException):
      _ = list(
          TestModel.query(
              ndb.OR(TestModel.prop_2 == 112,
                     TestModel.prop_2 == 113)).order(TestModel.prop_4))
