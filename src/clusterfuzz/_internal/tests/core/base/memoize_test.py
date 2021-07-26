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
"""memoize tests."""

import unittest

from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.base import persistent_cache
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class CacheTestClass(object):
  """Test cache class."""

  def __init__(self):
    self.called = []

  @memoize.wrap(memoize.FifoInMemory(10))
  def func(self, a, b=2):
    self.called.append((a, b))
    return a + b

  @memoize.wrap(memoize.FifoInMemory(10))
  def none(self, a):
    self.called.append(a)


CALLED = []


def gen_func():
  """Generate function with memoization."""
  del CALLED[:]

  @memoize.wrap(memoize.FifoInMemory(10))
  def func(a, b=2):
    CALLED.append((a, b))
    return a + b

  return func


class WrapTest(unittest.TestCase):
  """Test wrap() decorator on an instance method."""

  def _test_args(self, fn, called):
    """Test args."""
    self.assertEqual(fn(1), 3)
    self.assertListEqual([(1, 2)], called)

    self.assertEqual(fn(1), 3)
    self.assertListEqual([(1, 2)], called)

    self.assertEqual(fn(1, 2), 3)
    self.assertListEqual([(1, 2), (1, 2)], called)

    self.assertEqual(fn(1, 2), 3)
    self.assertListEqual([(1, 2), (1, 2)], called)

  def _test_kwargs(self, fn, called):
    """Test kwargs."""
    self.assertEqual(fn(a=1), 3)
    self.assertListEqual([(1, 2)], called)

    self.assertEqual(fn(a=1), 3)
    self.assertListEqual([(1, 2)], called)

    self.assertEqual(fn(1, b=2), 3)
    self.assertListEqual([(1, 2), (1, 2)], called)

    self.assertEqual(fn(1, b=2), 3)
    self.assertListEqual([(1, 2), (1, 2)], called)

    self.assertEqual(fn(a=1, b=2), 3)
    self.assertListEqual([(1, 2), (1, 2), (1, 2)], called)

    self.assertEqual(fn(a=1, b=2), 3)
    self.assertListEqual([(1, 2), (1, 2), (1, 2)], called)

  def test_args(self):
    """Test args."""
    obj = CacheTestClass()
    self._test_args(obj.func, obj.called)
    self._test_args(gen_func(), CALLED)

  def test_kwargs(self):
    """Test kwargs."""
    obj = CacheTestClass()
    self._test_kwargs(obj.func, obj.called)
    self._test_kwargs(gen_func(), CALLED)

  def test_force_update(self):
    """Test force update."""
    func = gen_func()
    self.assertEqual(func(1), 3)
    self.assertListEqual([(1, 2)], CALLED)

    # pylint: disable=unexpected-keyword-arg
    self.assertEqual(func(1, __memoize_force__=True), 3)
    self.assertListEqual([(1, 2), (1, 2)], CALLED)

  def test_none(self):
    """Test that none means having no key."""
    obj = CacheTestClass()

    self.assertIsNone(obj.none(a=1))
    self.assertListEqual([1], obj.called)

    self.assertIsNone(obj.none(a=1))
    self.assertIsNone(obj.none(a=1))
    self.assertIsNone(obj.none(a=1))

    # Notice that it's called multiple times; this means None is not cached.
    # This actually looks weird. But it's what we want. We might want to fix
    # it later.
    self.assertListEqual([1, 1, 1, 1], obj.called)


class FifoInMemoryTest(unittest.TestCase):
  """Test FifoInMemory."""

  def setUp(self):
    self.cache = memoize.FifoInMemory(5)

  def test_get(self):
    """Test store and get."""

    def fn():
      pass

    key = self.cache.get_key(fn, ('a', 'b'), {'c': 'd'})

    self.assertIsNone(self.cache.get(key))
    self.cache.put(key, 'b')
    self.assertEqual('b', self.cache.get(key))

  def test_hit_limit(self):
    """Test hitting the limit."""
    for i in range(6):
      self.cache.put(i, 'a')

    self.assertIsNone(self.cache.get(0))

    for i in range(1, 6):
      self.assertEqual('a', self.cache.get(i))


class FifoOnDiskTest(fake_filesystem_unittest.TestCase):
  """Test FifoOnDisk."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)
    environment.set_value('CACHE_DIR', '/tmp/test-cache')
    persistent_cache.initialize()

    self.cache = memoize.FifoOnDisk(5)

  def test_get(self):
    """Test store and get."""

    def fn():
      pass

    key = self.cache.get_key(fn, ('a', 'b'), {'c': 'd'})

    self.assertIsNone(self.cache.get(key))
    self.cache.put(key, 'b')
    self.assertEqual('b', self.cache.get(key))

  def test_hit_limit(self):
    """Test hitting the limit."""
    for i in range(6):
      self.cache.put(i, 'a')

    self.assertIsNone(self.cache.get(0))

    for i in range(1, 6):
      self.assertEqual('a', self.cache.get(i))


class _MockRedis(object):
  """Mock redis client."""

  def __init__(self):
    self._store = {}

  def get(self, key):
    """Get a value."""
    assert isinstance(key, six.string_types)
    return self._store.get(key)

  def set(self, key, value, ex=None):  # pylint: disable=unused-argument
    """Set a value."""
    assert isinstance(key, six.string_types)
    assert isinstance(value, six.string_types)
    self._store[key] = value


class MemcacheTest(unittest.TestCase):
  """Test Memcache."""

  def setUp(self):
    test_helpers.patch(self, [
        'redis.Redis',
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
    ])
    self.mock.Redis.return_value = _MockRedis()
    self.mock.is_running_on_app_engine.return_value = True

    self.cache = memoize.Memcache(100)

    def fn():
      pass

    self.key = self.cache.get_key(fn, ('a', 'b'), {'c': 'd'})
    self.value = 'b'

  def test_get(self):
    """Test store and get."""
    self.assertIsNone(self.cache.get(self.key))
    self.cache.put(self.key, self.value)
    self.assertEqual(self.value, self.cache.get(self.key))

  def test_noop(self):
    """Test noop on bot."""
    self.mock.is_running_on_app_engine.return_value = False

    self.assertIsNone(self.cache.get(self.key))
    self.cache.put(self.key, self.value)
    self.assertIsNone(self.cache.get(self.key))
