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
"""testcase_list tests."""
import datetime
import unittest

import flask
import mock
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import testcase_list
from libs import helpers
from libs.query import datastore_query


def _has_access(need_privileged_access=False):
  return not need_privileged_access


def _make_permissions(is_prefix, name):
  perm = data_types.ExternalUserPermission()
  perm.entity_name = name
  perm.is_prefix = is_prefix
  return perm


class AddFiltersTest(unittest.TestCase):
  """Test add_filters(..)."""

  def setUp(self):
    self.params = {}

    self.query = mock.Mock()

  def test_no_field(self):
    """Test no field."""
    testcase_list.add_filters(self.query, self.params)
    self.query.order.assert_called_once_with('timestamp', is_desc=True)
    self.query.filter.assert_has_calls([
        mock.call('status', 'Processed'),
        mock.call('is_a_duplicate_flag', False),
        mock.call('open', True),
        mock.call('is_leader', True)
    ])

  def test_both_fields(self):
    """Test filter field and keyword field."""
    self.params['q'] = ('hello group:456 issue:123 platform:windows stable:s.1'
                        ' beta:b.2 extended_stable:es.1 fuzzer:2 job:3')
    self.params['fuzzer'] = 'fuzz'
    self.params['issue'] = 'yes'
    self.params['job'] = 'somejob'
    self.params['open'] = 'yes'
    self.params['project'] = 'project'
    self.params['reproducible'] = 'yes'
    self.params['security'] = 'yes'
    self.params['impact'] = 'stable'
    testcase_list.add_filters(self.query, self.params)
    self.query.order.assert_called_once_with('timestamp', is_desc=True)
    self.query.filter.assert_has_calls([
        mock.call('status', 'Processed'),
        mock.call('is_a_duplicate_flag', False),
        mock.call('impact_version_indices', 'stable'),
        mock.call('has_bug_flag', True),
        mock.call('open', True),
        mock.call('security_flag', True),
        mock.call('group_id', 456),
        mock.call('bug_indices', '123'),
        mock.call('platform', 'windows'),
        mock.call('impact_extended_stable_version_indices', 'es.1'),
        mock.call('impact_stable_version_indices', 's.1'),
        mock.call('impact_beta_version_indices', 'b.2'),
        mock.call('fuzzer_name_indices', '2'),
        mock.call('job_type', '3'),
        mock.call('keywords', 'hello'),
        mock.call('one_time_crasher_flag', False),
        mock.call('job_type', 'somejob'),
        mock.call('fuzzer_name_indices', 'fuzz'),
        mock.call('project_name', 'project'),
    ])

  def test_revision_greater_than(self):
    """Ensure that we change ordering when using revision_greater_than."""
    self.params['revision_greater_than'] = '123456'
    testcase_list.add_filters(self.query, self.params)
    self.query.order.assert_called_once_with('crash_revision', is_desc=True)
    self.query.filter.assert_has_calls([
        mock.call('status', 'Processed'),
        mock.call('is_a_duplicate_flag', False),
        mock.call('is_leader', True),
        mock.call('crash_revision', 123456, operator='>'),
    ])


class GroupFilterTest(unittest.TestCase):
  """Test GroupFilter."""

  def setUp(self):
    self.filter = testcase_list.GroupFilter()
    self.query = mock.create_autospec(datastore_query.Query)

  def test_has_group(self):
    """Test having group."""
    self.filter.add(self.query, {'group': '1234'})
    self.query.filter.assert_has_calls([mock.call('group_id', 1234)])

  def test_no_group(self):
    """Test no group."""
    self.filter.add(self.query, {'group': ''})
    self.query.filter.assert_has_calls([mock.call('is_leader', True)])

  def test_raise_exception(self):
    """Test raising exceptions."""
    with self.assertRaises(helpers.EarlyExitException) as cm:
      self.filter.add(self.query, {'group': '123x4'})

    self.query.filter.assert_has_calls([])
    self.assertEqual("'group' must be int.", str(cm.exception))


@test_utils.with_cloud_emulators('datastore')
class JsonHandlerTest(unittest.TestCase):
  """Test Handler."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.external_users._allowed_entities_for_user',
        'clusterfuzz._internal.base.external_users._get_permissions_query_for_user',
        'libs.access.get_user_job_type',
        'libs.access.has_access',
        'libs.helpers.get_user_email',
    ])
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=testcase_list.JsonHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

    self.testcases = []
    for i in range(10):
      t = data_types.Testcase()
      t.crash_type = ''
      t.crash_state = ''
      t.status = 'Processed'
      t.security_flag = True
      t.is_a_duplicate_flag = False
      t.one_time_crasher_flag = False
      t.open = True
      t.is_leader = True
      t.timestamp = datetime.datetime.fromtimestamp(100 - i)
      t.put()
      self.testcases.append(t)

  def test_domain_with_job_and_fuzzer(self):
    """Test domain user with permitted jobis and permitted fuzzer."""

    self.mock.get_user_job_type.return_value = 'job2'
    self.mock.get_user_email.return_value = 'test@test.com'
    self.mock.has_access.side_effect = _has_access
    self.mock._allowed_entities_for_user.side_effect = [['job'], ['fuzzer']]  # pylint: disable=protected-access
    self.mock._get_permissions_query_for_user.side_effect = [  # pylint: disable=protected-access
        [_make_permissions(True, 'job_')],
        [_make_permissions(False, 'fuzzer')],
    ]

    self.testcases[5].job_type = 'job'
    self.testcases[5].security_flag = True
    self.testcases[5].one_time_crasher_flag = False
    self.testcases[5].put()
    self.testcases[6].fuzzer_name = 'fuzzer'
    self.testcases[6].security_flag = True
    self.testcases[6].one_time_crasher_flag = False
    self.testcases[6].put()
    self.testcases[7].job_type = 'job2'
    self.testcases[7].security_flag = False
    self.testcases[7].one_time_crasher_flag = False
    self.testcases[7].put()
    self.testcases[8].security_flag = False
    self.testcases[8].one_time_crasher_flag = False
    self.testcases[8].put()

    resp = self.app.post_json('/', {'reproducible': 'yes'})

    self.assertEqual(200, resp.status_int)
    self.assertListEqual([
        self.testcases[5].key.id(), self.testcases[6].key.id(),
        self.testcases[7].key.id(), self.testcases[8].key.id()
    ], [item['id'] for item in resp.json['items']])
