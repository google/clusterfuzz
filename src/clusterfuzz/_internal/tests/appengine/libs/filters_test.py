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
"""filters tests"""

import unittest

import mock

from libs import filters
from libs import helpers


class ExtractKeywordFieldTest(unittest.TestCase):
  """Test extact_keyword_field."""

  def _test(self, keyword, expected_rest, expected_value):
    rest, value = filters.extract_keyword_field(keyword, 'field')
    self.assertEqual(expected_rest, rest)
    self.assertEqual(expected_value, value)

  def test_empty(self):
    """Test empty."""
    self._test('', '', None)

  def test_no_field(self):
    """There is no keyword field."""
    self._test('key1 key2', 'key1 key2', None)

  def test_extract_field(self):
    """There is a field."""
    self._test('keyfield:value field:value key', 'keyfield:value key', 'value')
    self._test('keyfield:value field: key', 'keyfield:value key', '')
    self._test('keyfield:value field:value" key', 'keyfield:value key',
               'value"')
    self._test("keyfield:value field:'value key", 'keyfield:value key',
               "'value")

  def test_extract_field_single_quote(self):
    """There is a field with single quotes."""
    self._test("keyfield:value field:'val ue' key", 'keyfield:value key',
               'val ue')
    self._test("keyfield:value field:'' key", 'keyfield:value key', '')
    self._test("keyfield:value field:' \"a\" ' key", 'keyfield:value key',
               ' "a" ')

  def test_extract_field_double_quote(self):
    """There is a field with double quotes."""
    self._test('keyfield:value field:"val ue" key', 'keyfield:value key',
               'val ue')
    self._test('keyfield:value field:"" key', 'keyfield:value key', '')
    self._test('keyfield:value field:" \'a\' " key', 'keyfield:value key',
               " \'a\' ")


class SimpleFilterTest(unittest.TestCase):
  """Test SimpleFilter."""

  def setUp(self):
    self.query = mock.MagicMock()

  def test_empty(self):
    """Test empty value."""
    fltr = filters.SimpleFilter(
        'field', 'param', transformers=[lambda v: '1'], required=False)
    fltr.add(self.query, {'param': ''})
    self.query.filter.assert_not_called()

  def test_empty_required(self):
    """Test required value."""
    fltr = filters.SimpleFilter(
        'field', 'param', transformers=[lambda v: '1'], required=True)

    with self.assertRaises(helpers.EarlyExitException) as cm:
      fltr.add(self.query, {'param': ''})

    self.assertEqual("'param' is required.", str(cm.exception))
    self.assertEqual(400, cm.exception.status)
    self.query.filter.assert_not_called()

  def test_transform(self):
    """Test transform."""
    fltr = filters.SimpleFilter(
        'field', 'param', transformers=[lambda v: '1'], required=False)
    fltr.add(self.query, {'param': 'test'})
    self.query.filter.assert_called_once_with('field', '1')


class StringTest(unittest.TestCase):
  """Test String."""

  def setUp(self):
    self.filter = filters.String('field', 'param')
    self.query = mock.Mock()

  def test_empty(self):
    """Test empty."""
    self.filter.add(self.query, {})
    self.query.assert_not_called()

  def test_get(self):
    """Test get stripped string."""
    self.filter.add(self.query, {'param': ' aAa '})
    self.query.assert_has_calls([mock.call.filter('field', 'aAa')])


class KeywordTest(unittest.TestCase):
  """Test Keyword."""

  def setUp(self):
    fltrs = [
        filters.String('string_field', 'string_param'),
        filters.Int('int_field', 'int_param')
    ]
    self.filter = filters.Keyword(fltrs, 'field', 'param')
    self.query = mock.Mock()

  def test_get(self):
    """Test get keyword."""
    self.filter.add(self.query,
                    {'param': 'aaa bbb string_param:val int_param:234'})
    self.query.assert_has_calls([
        mock.call.filter('string_field', 'val'),
        mock.call.filter('int_field', 234),
        mock.call.filter('field', 'aaa'),
        mock.call.filter('field', 'bbb')
    ])


class NegativeBooleanTest(unittest.TestCase):
  """Test Boolean."""

  def setUp(self):
    self.filter = filters.NegativeBoolean('field', 'param')
    self.query = mock.Mock()

  def test_yes(self):
    """Test yes."""
    self.filter.add(self.query, {'param': 'yes'})
    self.query.assert_has_calls([mock.call.filter('field', False)])

  def test_no(self):
    """Test no."""
    self.filter.add(self.query, {'param': 'no'})
    self.query.assert_has_calls([mock.call.filter('field', True)])


class BooleanTest(unittest.TestCase):
  """Test Boolean."""

  def setUp(self):
    self.filter = filters.Boolean('field', 'param')
    self.query = mock.Mock()

  def test_empty(self):
    """Test empty."""
    self.filter.add(self.query, {'param': ''})
    self.query.assert_not_called()

  def test_yes(self):
    """Test yes."""
    self.filter.add(self.query, {'param': 'yes'})
    self.query.assert_has_calls([mock.call.filter('field', True)])

  def test_no(self):
    """Test no."""
    self.filter.add(self.query, {'param': 'no'})
    self.query.assert_has_calls([mock.call.filter('field', False)])

  def test_exception(self):
    """Test exception."""
    with self.assertRaises(helpers.EarlyExitException):
      self.filter.add(self.query, {'param': 'wsdljf'})
    self.query.assert_not_called()


class IntTest(unittest.TestCase):
  """Test String."""

  def setUp(self):
    self.filter = filters.Int('field', 'param')
    self.query = mock.Mock()

  def test_empty(self):
    """Test empty."""
    self.filter.add(self.query, {'param': ''})
    self.query.assert_not_called()

  def test_get(self):
    """Test get int."""
    self.filter.add(self.query, {'param': '0'})
    self.query.assert_has_calls([mock.call.filter('field', 0)])

  def test_exception(self):
    """Test exception."""
    with self.assertRaises(helpers.EarlyExitException):
      self.filter.add(self.query, {'param': 'wsdljf'})
    self.query.assert_not_called()

  def test_operator(self):
    fltr = filters.Int('field', 'param', operator='>')
    fltr.add(self.query, {'param': '0'})
    self.query.assert_has_calls([mock.call.filter('field', 0, operator='>')])


class AddTest(unittest.TestCase):
  """Test add."""

  def setUp(self):
    self.params = {}
    self.query = mock.Mock()
    self.filters = [
        filters.String('string_field', 'string_param'),
        filters.Int('int_field', 'int_param'),
        filters.Boolean('bool_field', 'bool_param'),
    ]

  def test_no_field(self):
    """Test no field."""
    filters.add(self.query, self.params, self.filters)
    self.query.filter.assert_has_calls([])

  def test_multiple_fields(self):
    """Test add multiple filters."""
    self.params['string_param'] = 'value'
    self.params['int_param'] = '123'
    self.params['bool_param'] = 'yes'

    filters.add(self.query, self.params, self.filters)

    self.query.assert_has_calls([
        mock.call.filter('string_field', 'value'),
        mock.call.filter('int_field', 123),
        mock.call.filter('bool_field', True),
    ])
