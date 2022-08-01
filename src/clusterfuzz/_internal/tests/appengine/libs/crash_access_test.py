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
"""Tests for the crash_access library."""
# pylint: disable=protected-access

import unittest

import mock

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from libs import crash_access
from libs import helpers
from libs.query import base


def _has_access(need_privileged_access=False):
  return not need_privileged_access


class AddScopeTest(unittest.TestCase):
  """Test add_scope."""

  def setUp(self):
    Query = base.Query  # pylint: disable=invalid-name

    test_helpers.patch(self, [
        'clusterfuzz._internal.base.external_users._allowed_entities_for_user',
        'libs.crash_access.get_permission_names',
        'libs.access.has_access',
        'libs.access.get_user_job_type',
        'libs.helpers.get_user_email',
        'libs.query.base.Query',
    ])
    self.params = {}
    self.mock.get_user_job_type.return_value = None
    self.mock.get_user_email.return_value = 'test@test.com'
    self.mock._allowed_entities_for_user.return_value = []
    self.mock.get_permission_names.return_value = []

    def create_query():
      q = mock.create_autospec(Query)
      return q

    self.mock.Query.side_effect = create_query
    self.query = base.Query()

  def test_forbidden(self):
    """Test when user is forbidden."""
    self.mock.has_access.return_value = False
    with self.assertRaises(helpers.EarlyExitException):
      crash_access.add_scope(self.query, self.params, 'security_flag',
                             'job_type', 'fuzzer_name')

  def test_default_global_privileged(self):
    """Test the default filter for globally privileged users."""
    self.mock.has_access.return_value = True
    crash_access.add_scope(self.query, self.params, 'security_flag', 'job_type',
                           'fuzzer_name')

    self.assertTrue(self.params['permissions']['everything'])
    self.assertTrue(self.params['permissions']['isPrivileged'])
    self.assertEqual([], self.params['permissions']['jobs'])
    self.assertFalse([], self.params['permissions']['fuzzers'])

    self.query.union.assert_has_calls([])
    self.query.filter.assert_has_calls([])

  def test_default_domain(self):
    """Test the default filter for domain users."""
    self.mock.has_access.side_effect = _has_access
    crash_access.add_scope(self.query, self.params, 'security_flag', 'job_type',
                           'fuzzer_name')

    self.assertTrue(self.params['permissions']['everything'])
    self.assertFalse(self.params['permissions']['isPrivileged'])
    self.assertEqual([], self.params['permissions']['jobs'])
    self.assertFalse([], self.params['permissions']['fuzzers'])

    self.query.filter.assert_has_calls([])
    self.query.union.assert_called_once_with(mock.ANY)

    q = self.query.union.call_args[0][0]
    q.union.assert_has_calls([])
    q.filter.assert_has_calls([mock.call('security_flag', False)])

  def test_domain_with_job_and_fuzzer(self):
    """Test domain user with job and fuzzer."""
    self.mock.has_access.side_effect = _has_access
    self.mock.get_user_job_type.return_value = 'job'
    self.mock._allowed_entities_for_user.side_effect = [['job2'], ['fuzzer']]
    self.mock.get_permission_names.side_effect = [['perm'], ['perm1']]

    crash_access.add_scope(self.query, self.params, 'security_flag', 'job_type',
                           'fuzzer_name')

    self.assertTrue(self.params['permissions']['everything'])
    self.assertFalse(self.params['permissions']['isPrivileged'])
    self.assertListEqual(['perm', 'job'], self.params['permissions']['jobs'])
    self.assertListEqual(['perm1'], self.params['permissions']['fuzzers'])

    self.query.union.assert_has_calls([])
    self.query.union.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)

    everything_query = self.query.union.call_args[0][0]
    job_query = self.query.union.call_args[0][1]
    fuzzer_query = self.query.union.call_args[0][2]

    everything_query.union.assert_has_calls([])
    job_query.union.assert_has_calls([])
    fuzzer_query.union.assert_has_calls([])

    everything_query.filter.assert_has_calls(
        [mock.call('security_flag', False)])
    job_query.filter_in.assert_has_calls([
        mock.call('job_type', ['job2', 'job']),
    ])
    fuzzer_query.filter_in.assert_has_calls([
        mock.call('fuzzer_name', ['fuzzer']),
    ])
