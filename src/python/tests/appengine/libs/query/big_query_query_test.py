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
"""big_query_query tests."""

import unittest

from libs.query import big_query_query


class FilterTest(unittest.TestCase):
  """Test filtering all types."""

  def test_single(self):
    """Test filtering single values."""
    q = big_query_query.Query()
    q.filter('int', 123)
    q.filter('float', 123.456)
    q.filter('bool', True)
    q.filter('string', 'test"t\nest')

    self.assertEqual(('(int = 123 AND float = 123.456 AND bool = true AND '
                      'string = "test\\"t\\nest")'), q.get_where_clause())

  def test_array(self):
    """Test filtering multiple values."""
    q = big_query_query.Query()
    q.filter_in('multi', [1, 1.2, True, False, 'test"test'])

    self.assertEqual('(multi IN (1, 1.2, true, false, "test\\"test"))',
                     q.get_where_clause())


class UnionTest(unittest.TestCase):
  """Test union."""

  def test_two_groups(self):
    """Test OR in two separate groups."""
    q = big_query_query.Query()
    q.filter('q', 'test')

    s1_1 = q.new_subquery()
    s1_1.filter('s1_1', 'test')
    s1_2 = q.new_subquery()
    s1_2.filter('s1_2', 'test')

    s2_1 = q.new_subquery()
    s2_1.filter('s2_1', 'test')
    s2_2 = q.new_subquery()
    s2_2.filter('s2_2', 'test')

    q.union(s1_1, s1_2)
    q.union(s2_1, s2_2)

    self.assertEqual(
        ('(q = "test" AND ((s1_1 = "test") OR (s1_2 = "test")) AND '
         '((s2_1 = "test") OR (s2_2 = "test")))'), q.get_where_clause())

  def test_nested_queries(self):
    """Test nested OR."""
    q = big_query_query.Query()
    q.filter('q', 'test')

    s1_1 = q.new_subquery()
    s1_1.filter('s1_1', 'test')
    s1_2 = q.new_subquery()
    s1_2.filter('s1_2', 'test')

    s2_1 = q.new_subquery()
    s2_1.filter('s2_1', 'test')
    s2_2 = q.new_subquery()
    s2_2.filter('s2_2', 'test')

    q.union(s1_1, s1_2)
    s1_2.union(s2_1, s2_2)

    self.assertEqual(('(q = "test" AND ((s1_1 = "test") OR (s1_2 = "test" AND '
                      '((s2_1 = "test") OR (s2_2 = "test")))))'),
                     q.get_where_clause())
