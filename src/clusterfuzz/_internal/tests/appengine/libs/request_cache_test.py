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
"""request_cache tests."""

import unittest

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from libs import request_cache


class CacheClass(object):
  """Test cache class."""

  def __init__(self):
    self.called = []

  @request_cache.wrap(3)
  def foo(self, a):
    self.called.append((a,))
    return a + 1


class CacheClass2(object):
  """Test cache class."""

  def __init__(self):
    self.called = []

  @request_cache.wrap(3)
  def foo(self, a):
    self.called.append((a,))
    return a + 2


class FakeRequest(object):
  """Fake request."""


class CacheTest(unittest.TestCase):
  """Cache tests."""

  def setUp(self):
    test_helpers.patch(self, ['libs.request_cache.get_cache_backing'])

    self.mock.get_cache_backing.return_value = FakeRequest()

  def test_basic(self):
    """Basic tests."""
    c = CacheClass()
    self.assertEqual(2, c.foo(1))
    self.assertEqual(2, c.foo(1))
    self.assertEqual(3, c.foo(2))

    self.assertListEqual([
        (1,),
        (2,),
    ], c.called)

  def test_no_request(self):
    """Test no request available."""
    self.mock.get_cache_backing.return_value = None
    c = CacheClass()
    self.assertEqual(2, c.foo(1))
    self.assertEqual(2, c.foo(1))
    self.assertEqual(3, c.foo(2))

    self.assertListEqual([
        (1,),
        (1,),
        (2,),
    ], c.called)

  def test_name_clash(self):
    """Test name clash."""
    c1 = CacheClass()
    c2 = CacheClass2()
    self.assertEqual(2, c1.foo(1))
    self.assertEqual(3, c2.foo(1))

    self.assertListEqual([
        (1,),
    ], c1.called)

    self.assertListEqual([
        (1,),
    ], c2.called)

  def test_scoped_to_request(self):
    """Test that the cache is scoped to requests."""
    c = CacheClass()
    self.assertEqual(2, c.foo(1))
    self.mock.get_cache_backing.return_value = FakeRequest()
    self.assertEqual(2, c.foo(1))

    self.assertListEqual([
        (1,),
        (1,),
    ], c.called)
