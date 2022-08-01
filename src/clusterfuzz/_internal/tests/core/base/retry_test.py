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
"""Retry tests."""
import unittest

# pylint: disable=protected-access
import mock

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.tests.test_libs import helpers


class WrapTest(unittest.TestCase):
  """Test retry decorator."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.retry.sleep',
    ])

    self.func_body = mock.MagicMock()
    monitor.metrics_store().reset_for_testing()

  @retry.wrap(retries=4, delay=10, backoff=2, function='_func')
  def _func(self, a):
    return self.func_body(a)

  @retry.wrap(retries=4, delay=10, backoff=2, function='_func')
  def _yield_func(self, a):
    for _ in range(3):
      yield self.func_body(a)

  @retry.wrap(
      retries=4, delay=10, backoff=2, function='_func', retry_on_false=True)
  def _func2(self, a):
    return self.func_body(a)

  class _FakeException(Exception):
    pass

  @retry.wrap(
      retries=4,
      delay=10,
      backoff=2,
      function='_func',
      exception_type=_FakeException)
  def _func_exception_type(self, a):
    return self.func_body(a)

  @retry.wrap(
      retries=4,
      delay=10,
      backoff=2,
      function='_func',
      exception_type=_FakeException)
  def _yield_func_exception_type(self, a):
    for _ in range(3):
      yield self.func_body(a)

  def test_retry_and_succeed(self):
    """Test when retry once and succeed for regular function.."""
    self.func_body.side_effect = [self._FakeException(), 456]

    self.assertEqual(456, self._func(123))

    self.assertEqual(2, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123), mock.call(123)])

    self.assertEqual(1, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls([mock.call(10)])

    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_and_succeed_yield(self):
    """Test when retry once and succeed for generator function.."""
    self.func_body.side_effect = [self._FakeException(), 1, 2, 3]

    results = list(self._yield_func(123))
    self.assertEqual([1, 2, 3], results)

    self.assertEqual(4, self.func_body.call_count)
    self.func_body.assert_has_calls(
        [mock.call(123),
         mock.call(123),
         mock.call(123),
         mock.call(123)])

    self.assertEqual(1, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls([mock.call(10)])

    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_and_succeed_yield_with_exceptions_in_middle(self):
    """Test when retry once and succeed for generator function with exceptions
    happening after the first element."""
    self.func_body.side_effect = [
        1, self._FakeException(), 1, 2,
        self._FakeException(), 1, 2, 3
    ]

    results = list(self._yield_func(123))
    self.assertEqual([1, 2, 3], results)

    self.assertEqual(8, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123)] * 8)

    self.assertEqual(2, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls([mock.call(10), mock.call(20)])

    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_exceed_try_limit(self):
    """Test when exceeding limit for regular function."""
    self.func_body.side_effect = self._FakeException()

    with self.assertRaises(self._FakeException):
      self._func(123)

    self.assertEqual(5, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123)] * 5)

    self.assertEqual(4, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls(
        [mock.call(10),
         mock.call(20),
         mock.call(40),
         mock.call(80)])

    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_exceed_try_limit_yield(self):
    """Test when exceeding limit for generator function."""
    self.func_body.side_effect = self._FakeException()

    with self.assertRaises(self._FakeException):
      for _ in self._yield_func(123):
        pass

    self.assertEqual(5, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123)] * 5)

    self.assertEqual(4, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls(
        [mock.call(10),
         mock.call(20),
         mock.call(40),
         mock.call(80)])

    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_exception_type_mismatch(self):
    """Test retry with exception mismatching type for regular function."""
    self.func_body.side_effect = [Exception]

    with self.assertRaises(Exception):
      self._func_exception_type(123)

    self.assertEqual(1, self.func_body.call_count)
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_exception_type_mismatch_yield(self):
    """Test retry with exception mismatching type for generator function."""
    self.func_body.side_effect = [Exception]

    with self.assertRaises(Exception):
      for _ in self._yield_func_exception_type(123):
        pass

    self.assertEqual(1, self.func_body.call_count)
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_exception_type_match(self):
    """Test retry with exception matching type for regular function."""
    self.func_body.side_effect = [self._FakeException(), 456]

    self.assertEqual(456, self._func_exception_type(123))
    self.assertEqual(2, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123), mock.call(123)])
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_exception_type_match_yield(self):
    """Test retry with exception matching type for generator function."""
    self.func_body.side_effect = [self._FakeException(), 1, 2, 3]

    results = list(self._yield_func_exception_type(123))
    self.assertEqual([1, 2, 3], results)
    self.assertEqual(4, self.func_body.call_count)
    self.func_body.assert_has_calls(
        [mock.call(123),
         mock.call(123),
         mock.call(123),
         mock.call(123)])
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_succeed_on_false(self):
    """Test retry on returning false and succeeding later."""
    self.func_body.side_effect = [False, True]
    self.assertTrue(self._func2(123))
    self.assertEqual(2, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123), mock.call(123)])
    self.assertEqual(1, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls([mock.call(10)])

    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))

  def test_retry_fail_on_false(self):
    """Test retry on returning false."""
    self.func_body.return_value = False
    self.assertFalse(self._func2(123))

    self.assertEqual(5, self.func_body.call_count)
    self.func_body.assert_has_calls([mock.call(123)] * 5)

    self.assertEqual(4, self.mock.sleep.call_count)
    self.mock.sleep.assert_has_calls(
        [mock.call(10),
         mock.call(20),
         mock.call(40),
         mock.call(80)])

    self.assertEqual(
        0,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': True,
        }))
    self.assertEqual(
        1,
        monitoring_metrics.TRY_COUNT.get({
            'function': '_func',
            'is_succeeded': False,
        }))
