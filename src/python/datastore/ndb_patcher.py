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
"""NDB patcher. Provides monkey patches for NDB to work
outside of App Engine through google.cloud.datastore without relying on Remote
API."""
# pylint: disable=protected-access
# pylint: disable=unidiomatic-typecheck

import collections
import datetime
import itertools
import threading

from google.api_core import exceptions
from google.api_core import retry
from google.appengine.api import datastore_errors
from google.appengine.datastore import datastore_query
from google.appengine.ext import ndb

from base import utils
from google_cloud_utils import credentials

try:
  from google.cloud import datastore
except ImportError:
  # Can't be imported on App Engine.
  pass

GET_MULTI_LIMIT = 1000
PUT_MULTI_LIMIT = 500

RETRY_DEADLINE = 90

UNSUPPORTED_PROPERTY_TYPES = [
    ndb.GeoPtProperty,
    ndb.BlobKeyProperty,
    ndb.UserProperty,
    ndb.StructuredProperty,
    ndb.LocalStructuredProperty,
    ndb.JsonProperty,
    ndb.PickleProperty,
    ndb.GenericProperty,
]

# Thead local globals.
_local = threading.local()

_patched_original = collections.defaultdict(dict)

_retry_wrap = retry.Retry(
    predicate=retry.if_exception_type((
        exceptions.Aborted,
        exceptions.DeadlineExceeded,
        exceptions.ServerError,
        exceptions.ServiceUnavailable,
    )),
    deadline=RETRY_DEADLINE)


class NdbPatcherException(Exception):
  """Base exception class."""


class _IteratorAdapter(object):
  """Iterator Adapter to turn Cloud Datastore results into ndb.Models."""

  def __init__(self,
               model_class,
               iterators,
               projection=None,
               limit=None,
               keys_only=False):
    self._model_class = model_class
    self._projection = projection
    self._limit = limit
    self._keys_only = keys_only

    if len(iterators) == 1:
      self._iterator = iterators[0]
      self._composite = False
    else:
      self._iterator = itertools.chain(*iterators)
      # Entities should not be duplicated in composite queries.
      self._seen = set()
      self._composite = True

  def __iter__(self):
    return self

  def next(self):
    """Get the next result."""
    if (self._composite and self._limit is not None and
        len(self._seen) >= self._limit):
      raise StopIteration

    entity = next(self._iterator)
    if self._composite:
      while entity.key.id_or_name in self._seen:
        entity = next(self._iterator)

      self._seen.add(entity.key.id_or_name)

    if self._keys_only:
      return _cloud_key_to_ndb_key(entity.key)

    return _cloud_entity_to_ndb_entity(
        self._model_class, entity, projection=self._projection)


class Query(object):
  """Base Query class."""

  def __init__(self, wrapped, model_class):
    self.wrapped_ndb = wrapped
    self.model_class = model_class

  def filter(self, *args):
    """Wraps the result from filter()."""
    return Query(ndb.Query.filter(self.wrapped_ndb, *args), self.model_class)

  def order(self, *args):
    """Wraps the result from order()."""
    return Query(ndb.Query.order(self.wrapped_ndb, *args), self.model_class)

  def fetch(self, limit=None, **kwargs):
    """Wraps fetch()."""
    return list(self.iter(limit=limit, **kwargs))

  def get(self):
    """Get a single result from a query."""
    # TODO(ochang): Find a way to fix this more generally.
    result_func = lambda: next(self.iter(limit=1), None)
    return _retry_wrap(result_func)()

  def iter(self, **kwargs):
    """Iterate over a query."""
    projection = None
    keys_only = False
    limit = None
    if self.default_options:
      projection = self.default_options.projection
      keys_only = self.default_options.keys_only
      limit = self.default_options.limit

    projection = _projection_to_strings(
        kwargs.get('projection', self.projection or projection))
    keys_only = kwargs.get('keys_only', keys_only)
    limit = kwargs.get('limit', limit)

    cloud_queries = _ndb_query_to_cloud_queries(
        self, projection=projection, keys_only=keys_only)
    iterators = [iter(q.fetch(limit=limit)) for q in cloud_queries]

    return _IteratorAdapter(
        self.model_class,
        iterators,
        projection=projection,
        limit=limit,
        keys_only=keys_only)

  def count(self, **kwargs):
    """Count number of elements in query."""
    kwargs['keys_only'] = True
    result = self.iter(**kwargs)
    return sum(1 for _ in result)

  def _not_implemented(self):
    raise NotImplementedError

  __iter__ = iter

  fetch_async = _not_implemented
  count_async = _not_implemented
  get_async = _not_implemented
  fetch_page = _not_implemented
  fetch_page_async = _not_implemented
  map = _not_implemented
  map_async = _not_implemented

  def __getattr__(self, attr):
    """Forward all other getters to the actual ndb.Query."""
    return getattr(self.wrapped_ndb, attr)


def _client():
  """Get the Datastore _client()."""
  if hasattr(_local, 'client'):
    return _local.client

  init()
  return _local.client


def _ndb_key_to_cloud_key(ndb_key):
  """Convert a ndb.Key to a cloud entity Key."""
  return datastore.Key(
      ndb_key.kind(), ndb_key.id(), project=utils.get_application_id())


def _cloud_key_to_ndb_key(cloud_key):
  """Convert a cloud entity key to a ndb.Key."""
  return ndb.Key(cloud_key.kind, cloud_key.id_or_name)


def _unindexed_properties(ndb_model):
  """Return list of unindexed properties for the ndb Model."""
  properties = []
  for name, prop in ndb_model._properties.iteritems():
    if not prop._indexed:
      properties.append(name)

  return properties


def _cloud_entity_to_ndb_entity(model_class, cloud_entity, projection=None):
  """Convert cloud entity to ndb.Model."""
  if cloud_entity is None:
    return None

  props = {}
  for key, value in cloud_entity.iteritems():
    ndb_property = getattr(model_class, key, None)
    if not isinstance(ndb_property, ndb.Property):
      # Deleted attribute from an old entity.
      continue

    if isinstance(ndb_property, ndb.ComputedProperty):
      continue

    if isinstance(value, (datastore.Entity, datastore.helpers.GeoPoint)):
      raise NdbPatcherException('Unsupported type for value: ' + repr(value))

    if isinstance(value, datastore.Key):
      value = _cloud_key_to_ndb_key(value)

    if type(getattr(model_class, key)) is ndb.DateProperty:
      value = value.date()

    if type(getattr(model_class, key)) is ndb.TimeProperty:
      value = value.time()

    if isinstance(value, (datetime.datetime, datetime.time)):
      # NDB datetimes are not timezone aware.
      value = value.replace(tzinfo=None)

    props[key] = value

  ndb_entity = model_class(
      id=cloud_entity.key.id_or_name, projection=projection, **props)
  return ndb_entity


def _ndb_entity_to_cloud_entity(ndb_entity):
  """Convert ndb.Model to cloud entity to prepare for put()."""
  if ndb_entity is None:
    return None

  project_id = utils.get_application_id()
  unindexed_properties = _unindexed_properties(ndb_entity.__class__)

  ndb_entity._prepare_for_put()
  ndb_entity._pre_put_hook()

  if ndb_entity.key:
    # Existing key.
    cloud_entity = datastore.Entity(
        key=_ndb_key_to_cloud_key(ndb_entity.key),
        exclude_from_indexes=unindexed_properties)
  else:
    # Auto-generate key.
    base_key = datastore.Key(ndb_entity._get_kind(), project=project_id)
    generated_key = _retry_wrap(_client().allocate_ids)(base_key, 1)[0]
    cloud_entity = datastore.Entity(
        key=generated_key, exclude_from_indexes=unindexed_properties)

    ndb_entity.key = _cloud_key_to_ndb_key(generated_key)

  for key, value in ndb_entity.to_dict().iteritems():
    ndb_property = getattr(ndb_entity.__class__, key)
    if type(ndb_property) in UNSUPPORTED_PROPERTY_TYPES:
      raise NdbPatcherException('Unsupported property type: ' +
                                ndb_property.__name__)

    if (isinstance(value, str) and type(ndb_property) is not ndb.BlobProperty):
      # All 'str' values are written as byte strings by Cloud Datastore, but ndb
      # ndb_entitys can have 'str' values for StringProperty or TextProperty, so
      # check the type of the property.
      value = unicode(value)
    elif type(value) is datetime.date:
      value = datetime.datetime.combine(value, datetime.datetime.min.time())
    elif type(value) is datetime.time:
      value = datetime.datetime.combine(datetime.date(1970, 1, 1), value)
    elif isinstance(value, ndb.Key):
      value = _ndb_key_to_cloud_key(value)

    cloud_entity[key] = value

  return cloud_entity


def _orders_from_ndb_query(query):
  """Get cloud query order from NDB query."""

  def _property_order_to_string(order):
    """Convert a PropertyOrder to a string."""
    direction = ''
    if order.direction == datastore_query.PropertyOrder.DESCENDING:
      direction = '-'

    return direction + order.prop

  if not query.orders:
    return None

  if isinstance(query.orders, datastore_query.PropertyOrder):
    return [_property_order_to_string(query.orders)]

  if isinstance(query.orders, datastore_query.CompositeOrder):
    return [_property_order_to_string(order) for order in query.orders.orders]

  raise NotImplementedError


def _projection_to_strings(projection):
  """Convert projection to strings."""

  def _property_to_string(prop):
    """Convert a single property to a string."""
    if isinstance(prop, basestring):
      return prop

    if isinstance(prop, ndb.Property):
      return prop._name

    raise NdbPatcherException('Invalid property type.')

  if not projection:
    return None

  return [_property_to_string(prop) for prop in projection]


def _ndb_filters_to_cloud_filters(cloud_query, filters):
  """Convert NDB filters to cloud filters."""
  if not filters:
    return

  if isinstance(filters, ndb.FilterNode):
    name, op, value = filters.__getnewargs__()
    cloud_query.add_filter(name, op, value)

  if isinstance(filters, ndb.AND):
    for flt in filters:
      _ndb_filters_to_cloud_filters(cloud_query, flt)

  if isinstance(filters, ndb.OR):
    raise NdbPatcherException('OR should not be in subqueries.')


def _ndb_query_to_cloud_queries(ndb_query, projection=None, keys_only=False):
  """Convert a NDB query to cloud queries."""
  if projection is None:
    projection = ()

  has_or = isinstance(ndb_query.wrapped_ndb.filters, ndb.OR)

  orders = _orders_from_ndb_query(ndb_query)
  if orders is None:
    orders = ()
  elif has_or:
    raise NdbPatcherException('Orders not supported with OR queries.')

  distinct_on = ()
  if ndb_query.is_distinct and projection:
    distinct_on = projection

  subqueries = []
  if has_or:
    for flt in ndb_query.wrapped_ndb.filters:
      subqueries.append(_client().query(
          kind=ndb_query.wrapped_ndb.kind,
          order=orders,
          projection=projection,
          distinct_on=distinct_on))

      _ndb_filters_to_cloud_filters(subqueries[-1], flt)
  else:
    subqueries.append(_client().query(
        kind=ndb_query.wrapped_ndb.kind,
        order=orders,
        projection=projection,
        distinct_on=distinct_on))

    _ndb_filters_to_cloud_filters(subqueries[-1], ndb_query.wrapped_ndb.filters)

  if keys_only:
    for subquery in subqueries:
      subquery.keys_only()

  return subqueries


def init():
  """Explicitly (re-)initialize _client(). This is useful for testing."""
  # We discard the project from the service account credentials, as it may be
  # different from the Datastore project we wish to connect to.
  creds = credentials.get_default()[0]
  _local.client = datastore.Client(
      project=utils.get_application_id(), credentials=creds)


def _gen_chunks(values, size):
  """Generate chunks of iterable."""
  for i in xrange(0, len(values), size):
    yield values[i:i + size]


def _get_multi(keys):
  """Get multiple entities."""
  cloud_keys = [_ndb_key_to_cloud_key(key) for key in keys]
  results = []

  for chunk in _gen_chunks(cloud_keys, GET_MULTI_LIMIT):
    entities = _client().get_multi(chunk)
    result_map = dict([(e.key, e) for e in entities])

    for key in chunk:
      if key in result_map:
        entity = result_map[key]
        model_class = ndb.Model._lookup_model(key.kind)
        results.append(_cloud_entity_to_ndb_entity(model_class, entity))
      else:
        results.append(None)

  return results


def _put_multi(entities):
  """Put multiple entities."""
  for chunk in _gen_chunks(entities, PUT_MULTI_LIMIT):
    _retry_wrap(_client().put_multi)(
        [_ndb_entity_to_cloud_entity(entity) for entity in chunk])

  keys = [entity.key for entity in entities]

  for entity in entities:
    entity._post_put_hook(None)

  return keys


def _delete_multi(keys):
  """Delete multiple ndb.Keys."""
  for chunk in _gen_chunks(keys, PUT_MULTI_LIMIT):
    _retry_wrap(
        _client().delete_multi)([_ndb_key_to_cloud_key(key) for key in chunk])


def _put(entity):
  """Model.put replacement."""
  _retry_wrap(_client().put)(_ndb_entity_to_cloud_entity(entity))
  key = entity.key
  entity._post_put_hook(None)
  return key


def _query(cls, *args, **kwargs):
  """Model.query replacement."""
  # Rebind ndb.Model.query to cls.
  # See https://docs.python.org/2/howto/descriptor.html for how __get__ works.
  model_query = _patched_original[ndb.Model]['query']
  model_query = model_query.__func__.__get__(cls, model_query.im_class)
  result = model_query(*args, **kwargs)
  return Query(result, cls)


def _get_by_id(cls, key_id, **_):
  """get_by_id replacement."""
  return ndb.Key(cls, key_id).get()


def _key_get(self):
  """Get an entity by key."""
  cloud_entity = _client().get(_ndb_key_to_cloud_key(self))
  if cloud_entity is None:
    return None

  model_class = ndb.Model._lookup_model(self.kind())
  return _cloud_entity_to_ndb_entity(model_class, cloud_entity)


def _key_delete(self):
  """Delete an entity by key."""
  _client().delete(_ndb_key_to_cloud_key(self))


def _transaction(callback, **kwargs):
  """ndb.transaction replacement."""

  def do_transaction():
    with _client().transaction():
      return callback()

  retries = kwargs.get('retries', 0)
  for _ in xrange(1 + retries):
    try:
      # Retry the entire transaction on any transient error.
      return _retry_wrap(do_transaction)()
    except exceptions.Conflict:
      pass

  raise datastore_errors.TransactionFailedError


def _patch(obj, attribute, replacement):
  """Patch with an replacement."""
  if attribute in _patched_original[obj]:
    raise NdbPatcherException(attribute + ' is already patched.')

  _patched_original[obj][attribute] = getattr(obj, attribute)
  setattr(obj, attribute, replacement)


def _unpatch(obj, attribute):
  """Patch with an replacement."""
  if attribute not in _patched_original[obj]:
    raise NdbPatcherException(
        'Original attribute {} not found for unpatch.'.format(attribute))

  setattr(obj, attribute, _patched_original[obj][attribute])
  del _patched_original[obj][attribute]


def patch_ndb(module=None):
  """Monkey patch NDB methods. This is used in environments outside of App
  Engine to remove the dependency on Remote API."""
  if module is None:
    module = ndb

  _patch(module, 'get_multi', _get_multi)
  _patch(module, 'delete_multi', _delete_multi)
  _patch(module, 'put_multi', _put_multi)
  _patch(module, 'transaction', _transaction)
  _patch(module.Key, 'get', _key_get)
  _patch(module.Key, 'delete', _key_delete)
  _patch(module.Model, 'put', _put)
  _patch(module.Model, 'query', classmethod(_query))
  _patch(module.Model, 'get_by_id', classmethod(_get_by_id))


def unpatch_ndb(module=None):
  """Un-apply NDB patches."""
  if module is None:
    module = ndb

  _unpatch(module, 'get_multi')
  _unpatch(module, 'delete_multi')
  _unpatch(module, 'put_multi')
  _unpatch(module, 'transaction')
  _unpatch(module.Key, 'get')
  _unpatch(module.Key, 'delete')
  _unpatch(module.Model, 'put')
  _unpatch(module.Model, 'query')
  _unpatch(module.Model, 'get_by_id')
