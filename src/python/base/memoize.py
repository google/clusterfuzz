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
"""Memoize caches the result of methods."""

import collections
import functools
import json
import threading

import six

from base import persistent_cache
from metrics import logs
from system import environment
from system.environment import appengine_noop
from system.environment import bot_noop
from system.environment import local_noop

# Thead local globals.
_local = threading.local()

_DEFAULT_REDIS_HOST = 'localhost'
_DEFAULT_REDIS_PORT = 6379


def _redis_client():
  """Get the redis client."""
  import redis

  if hasattr(_local, 'redis'):
    return _local.redis

  host = environment.get_value('REDIS_HOST', _DEFAULT_REDIS_HOST)
  port = environment.get_value('REDIS_PORT', _DEFAULT_REDIS_PORT)

  _local.redis = redis.Redis(host=host, port=port)
  return _local.redis


class FifoInMemory(object):
  """In-memory caching engine."""

  def __init__(self, capacity):
    self.capacity = capacity
    self.lock = threading.Lock()
    self._cache = None

  @property
  def cache(self):
    """Get the cache backing. None may be returned."""
    if self._cache is None:
      self._cache = collections.OrderedDict()

    return self._cache

  def put(self, key, value):
    """Put (key, value) into cache."""
    if self.cache is None:
      return

    # Lock to avoid race condition in popitem.
    self.lock.acquire()

    if len(self.cache) >= self.capacity:
      self.cache.popitem(last=False)

    self.cache[key] = value

    self.lock.release()

  def get(self, key):
    """Get the value from cache."""
    if self.cache is None:
      return None

    return self.cache.get(key)

  def get_key(self, func, args, kwargs):
    """Get a key name based on function, arguments and keyword arguments."""
    return _default_key(func, args, kwargs)


class FifoOnDisk(object):
  """On-disk caching engine."""

  def __init__(self, capacity):
    self.capacity = capacity
    self.keys = []
    self.lock = threading.Lock()

  @appengine_noop
  def put(self, key, value):
    """Put (key, value) into cache."""
    # Lock to avoid race condition in pop.
    self.lock.acquire()

    if len(self.keys) >= self.capacity:
      key_to_remove = self.keys.pop(0)
      persistent_cache.delete_value(key_to_remove)

    persistent_cache.set_value(key, value)
    self.keys.append(key)

    self.lock.release()

  @appengine_noop
  def get(self, key):
    """Get the value from cache."""
    return persistent_cache.get_value(key)

  def get_key(self, func, args, kwargs):
    """Get a key name based on function, arguments and keyword arguments."""
    return _default_key(func, args, kwargs)


class Memcache(object):
  """Memcache caching engine."""

  def __init__(self, ttl_in_seconds, key_fn=None):
    self.ttl_in_seconds = ttl_in_seconds
    self.key_fn = key_fn or _default_key

  @local_noop
  @bot_noop
  def put(self, key, value):
    """Put (key, value) into cache."""
    import redis
    try:
      _redis_client().set(
          json.dumps(key), json.dumps(value), ex=self.ttl_in_seconds)
    except redis.RedisError:
      logs.log_error('Failed to store key in cache.', key=key, value=value)

  @local_noop
  @bot_noop
  def get(self, key):
    """Get the value from cache."""
    import redis
    try:
      value_raw = _redis_client().get(json.dumps(key))
    except redis.RedisError:
      logs.log_error('Failed to retrieve key from cache.', key=key)
      return None

    if value_raw is None:
      return value_raw

    return json.loads(value_raw)

  def get_key(self, func, args, kwargs):
    return self.key_fn(func, args, kwargs)


def _default_key(func, args, kwargs):
  """Get a key name based on function, arguments and keyword arguments."""
  # Use unicode instead of str where possible. This makes it less likely to
  # have false misses.
  args = tuple(arg if not isinstance(arg, str) else str(arg) for arg in args)

  kwargs = {
      key: value if not isinstance(value, str) else str(value)
      for key, value in six.iteritems(kwargs)
  }

  return 'memoize:%s' % [func.__name__, args, sorted(kwargs.items())]


def wrap(engine):
  """Decorator for caching the result of method calls. Arguments must
    be hashable. None is not cached because we don't tell the difference
    between having None and not having a key."""

  def decorator(func):
    """Decorator function."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      """Wrapper function."""
      force_update = kwargs.pop('__memoize_force__', False)

      key = engine.get_key(func, args, kwargs)
      result = engine.get(key)

      if result is not None and not force_update:
        return result

      result = func(*args, **kwargs)
      engine.put(key, result)
      return result

    return wrapper

  return decorator
