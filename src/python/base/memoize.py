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

try:
  from google.appengine.api import memcache
except ImportError:
  # This is expected to fail on bots without appengine sdk and with local butler
  # commands.
  pass

from base import persistent_cache
from metrics import logs
from system.environment import appengine_noop
from system.environment import bot_noop


class FifoInMemory(object):
  """In-memory caching engine."""

  def __init__(self, capacity):
    self.capacity = capacity
    self.cache = collections.OrderedDict()
    self.lock = threading.Lock()

  def put(self, key, value):
    """Put (key, value) into cache."""
    # Lock to avoid race condition in popitem.
    self.lock.acquire()

    if len(self.cache) >= self.capacity:
      self.cache.popitem(last=False)

    self.cache[key] = value

    self.lock.release()

  def get(self, key):
    """Get the value from cache."""
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

  @bot_noop
  def put(self, key, value):
    """Put (key, value) into cache."""
    memcache.set(key, value, self.ttl_in_seconds)

  @bot_noop
  def get(self, key):
    """Get the value from cache."""
    return memcache.get(key)

  def get_key(self, func, args, kwargs):
    return self.key_fn(func, args, kwargs)


class MemcacheLarge(Memcache):
  """Memcache caching engine for caching large python objects. These must be
  serializable as JSON."""

  CHUNK_LEN = 90000
  MAGIC_STR = 'chunk'

  @bot_noop
  def put(self, key, value):
    logs.log('MemcacheLarge put %s.' + key)
    # Make JSON representation as compact as possible (don't use spaces).
    string_value = json.dumps(value, separators=(',', ':'))
    keys_and_values = {key: len(string_value)}
    for chunk_start in xrange(0, len(string_value), self.CHUNK_LEN):
      full_key = '%s-%s-%s' % (self.MAGIC_STR, key, chunk_start)
      keys_and_values[full_key] = string_value[chunk_start:chunk_start +
                                               self.CHUNK_LEN]

    memcache.set_multi(keys_and_values)

  @bot_noop
  def get(self, key):
    logs.log('MemcacheLarge get %s.' % key)
    value_len = memcache.get(key)
    if not value_len:
      return value_len

    value_len = int(value_len)
    keys = [
        '%s-%s-%s' % (self.MAGIC_STR, key, chunk_start)
        for chunk_start in xrange(0, value_len, self.CHUNK_LEN)
    ]

    keys_and_values = memcache.get_multi(keys).items()

    def get_chunk_start(key_and_value):
      full_key = key_and_value[0]
      key_without_chunk_start = '%s-%s-' % (self.MAGIC_STR, key)
      return int(full_key[len(key_without_chunk_start):])

    string_value = ''.join(
        value for key, value in sorted(keys_and_values, key=get_chunk_start))

    string_len = len(string_value)
    if string_len != value_len:
      logs.log_error('Unable to retrieve %s. Expected length: %s. actual: %s' %
                     (key, value_len, string_len))
      return None

    try:
      return json.loads(string_value)
    except ValueError:
      logs.log_error('Unable to retrieve ' + key)
      return None


def _default_key(func, args, kwargs):
  """Get a key name based on function, arguments and keyword arguments."""
  # Use unicode instead of str where possible. This makes it less likely to
  # have false misses.
  args = tuple(
      arg if not isinstance(arg, str) else unicode(arg) for arg in args)

  kwargs = {
      key: value if not isinstance(value, str) else unicode(value)
      for key, value in kwargs.iteritems()
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
