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
"""helpers tests."""
# pylint: disable=protected-access

import unittest

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from libs import auth
from libs import helpers


class TestNotFoundException(Exception):
  """Serve as a testing exception."""


class IsNotEmpty(unittest.TestCase):
  """Test _is_not_empty."""

  def test_empty(self):
    """Test none."""
    self.assertFalse(helpers._is_not_empty(None))
    self.assertFalse(helpers._is_not_empty(''))
    self.assertFalse(helpers._is_not_empty(0))

  def test_not_empty(self):
    """Test not empty."""
    self.assertTrue(helpers._is_not_empty('a'))
    self.assertTrue(helpers._is_not_empty(1))
    self.assertTrue(helpers._is_not_empty(object()))

  def test_tuple_empty(self):
    """Test tuple containing only empty values."""
    self.assertFalse(helpers._is_not_empty((None, None)))
    self.assertFalse(helpers._is_not_empty((None, None, None)))
    self.assertFalse(helpers._is_not_empty(('', '')))
    self.assertFalse(helpers._is_not_empty((None, '', 0, None)))

  def test_tuple_not_empty(self):
    """Test tuples that are not considered as empty."""
    self.assertTrue(helpers._is_not_empty((None, 1)))
    self.assertTrue(helpers._is_not_empty(('a', 0)))


class GetOrExitTest(unittest.TestCase):
  """Test get_or_exit."""

  def test_should_render_json(self):
    """Ensure it determines render_json correctly."""
    self.assertTrue(
        helpers.should_render_json('adsasd;application/json;sdf', ''))
    self.assertTrue(helpers.should_render_json('', 'application/json'))
    self.assertFalse(helpers.should_render_json('text/plain;0.8', 'text/html'))

  def test_get_or_exit_valid(self):
    """Ensure it gets value."""
    fn = lambda: 'test'
    self.assertEqual(helpers.get_or_exit(fn, 'not_found', 'error'), 'test')

  def test_get_or_exit_none(self):
    """Ensure it raises 404 when the value is None."""
    fn = lambda: None
    with self.assertRaises(helpers.EarlyExitException) as catched:
      helpers.get_or_exit(fn, 'not_found', 'error')

    self.assertEqual(catched.exception.status, 404)
    self.assertEqual(str(catched.exception), 'not_found')

  def test_get_or_exit_tuple_none(self):
    """Ensure it raises 404 when the value is a tuple of None."""
    fn = lambda: (None, None)
    with self.assertRaises(helpers.EarlyExitException) as catched:
      helpers.get_or_exit(fn, 'not_found', 'error')

    self.assertEqual(catched.exception.status, 404)
    self.assertEqual(str(catched.exception), 'not_found')

  def test_get_or_exit_not_found_exception(self):
    """Ensure it raises 404 when `fn` throws a recognised exception."""

    def fn():
      raise TestNotFoundException()

    with self.assertRaises(helpers.EarlyExitException) as catched:
      helpers.get_or_exit(
          fn, 'not_found', 'error', not_found_exception=TestNotFoundException)

    self.assertEqual(catched.exception.status, 404)
    self.assertEqual(str(catched.exception), 'not_found')

  def test_get_or_exit_other_exception(self):
    """Ensure it raises 500 when `fn` throws an unknown exception."""

    def fn():
      raise Exception('message')

    with self.assertRaises(helpers.EarlyExitException) as catched:
      helpers.get_or_exit(fn, 'not_found', 'other')

    self.assertEqual(catched.exception.status, 500)

    self.assertEqual(
        str(catched.exception), "other (<class 'Exception'>: message)")


class GetUserEmailTest(unittest.TestCase):
  """Test get_user_email."""

  def setUp(self):
    test_helpers.patch(self, ['libs.auth.get_current_user'])

  def test_get_user_email_success(self):
    """Ensure it gets the email when a user is valid."""
    self.mock.get_current_user.return_value = (auth.User('TeSt@Test.com'))
    self.assertEqual(helpers.get_user_email(), 'TeSt@Test.com')

  def test_get_user_email_failure(self):
    """Ensure it gets empty string when a user is invalid."""
    self.mock.get_current_user.side_effect = Exception()
    self.assertEqual(helpers.get_user_email(), '')


class LogTest(unittest.TestCase):
  """Test log."""

  def setUp(self):
    test_helpers.patch(self, ['logging.info', 'libs.helpers.get_user_email'])
    self.mock.get_user_email.return_value = 'email'

  def test_modify(self):
    """Test log modify."""
    helpers.log('message', helpers.MODIFY_OPERATION)
    self.mock.info.assert_called_once_with('ClusterFuzz: %s (%s): %s.',
                                           helpers.MODIFY_OPERATION, 'email',
                                           'message')

  def test_view(self):
    """Test log view."""
    helpers.log('message', helpers.VIEW_OPERATION)
    self.mock.info.assert_called_once_with(
        'ClusterFuzz: %s (%s): %s.', helpers.VIEW_OPERATION, 'email', 'message')
