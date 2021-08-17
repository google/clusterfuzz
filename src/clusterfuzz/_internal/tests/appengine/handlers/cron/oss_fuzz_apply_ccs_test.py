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
"""oss_fuzz_apply_ccs tests."""
import datetime
import unittest

import flask
import six
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import oss_fuzz_apply_ccs
from libs.issue_management import issue_tracker_policy
from libs.issue_management import monorail
from libs.issue_management.monorail.issue import Issue

OSS_FUZZ_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'deadline_policy_message':
        'This bug is subject to a 90 day disclosure deadline. '
        'If 90 days elapse\n'
        'without an upstream patch, then the bug report will automatically\n'
        'become visible to the public.',
    'labels': {
        'reported': 'Reported-%YYYY-MM-DD%',
        'restrict_view': 'Restrict-View-Commit',
    },
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'fixed': 'Fixed',
        'new': 'New',
        'verified': 'Verified',
        'wontfix': 'WontFix'
    }
})

DEADLINE_NOTE = (
    'This bug is subject to a 90 day disclosure deadline. If 90 days elapse\n'
    'without an upstream patch, then the bug report will automatically\n'
    'become visible to the public.')


class IssueTrackerManager(object):
  """Mock issue tracker manager."""

  def __init__(self, project_name):
    self.project_name = project_name
    self.last_issue = None
    self.modified_issues = {}

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
    """Save a issue."""
    self.modified_issues[issue.id] = issue


def get_original_issue(self, issue_id):
  """Get original issue."""
  issue_id = int(issue_id)

  issue = Issue()
  issue.open = True
  issue.itm = self._itm  # pylint: disable=protected-access
  issue.id = issue_id

  if issue_id == 1337:
    issue.add_cc('user@example.com')
    issue.add_label('Restrict-View-Commit')
  elif issue_id == 1338:
    issue.add_cc('user@example.com')
    issue.add_cc('user2@example.com')
  elif issue_id == 1340:
    issue.add_label('reported-2015-01-01')

  return monorail.Issue(issue)


@test_utils.with_cloud_emulators('datastore')
class OssFuzzApplyCcsTest(unittest.TestCase):
  """Test OssFuzzApplyCcs."""

  def setUp(self):
    test_helpers.patch_environ(self)
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/apply-ccs',
        view_func=oss_fuzz_apply_ccs.Handler.as_view('/apply-ccs'))
    self.app = webtest.TestApp(flaskapp)

    data_types.ExternalUserPermission(
        email='user@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user2@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
        'handlers.base_handler.Handler.is_cron',
        'libs.issue_management.issue_tracker.IssueTracker.get_original_issue',
        'libs.issue_management.issue_tracker_policy.get',
        'libs.issue_management.issue_tracker_utils.'
        'get_issue_tracker_for_testcase',
    ])

    self.itm = IssueTrackerManager('oss-fuzz')
    self.mock.get_issue_tracker_for_testcase.return_value = (
        monorail.IssueTracker(self.itm))
    self.mock.utcnow.return_value = datetime.datetime(2016, 1, 1)
    self.mock.get.return_value = OSS_FUZZ_POLICY
    self.mock.get_original_issue.side_effect = get_original_issue

    data_types.Testcase(
        open=True, status='Processed', bug_information='1337',
        job_type='job').put()

    data_types.Testcase(
        open=True, status='Processed', bug_information='1338',
        job_type='job').put()

    data_types.Testcase(
        open=True, status='Processed', bug_information='1339',
        job_type='job').put()

    data_types.Testcase(
        open=True, status='Processed', bug_information='1340',
        job_type='job').put()

  def test_execute(self):
    """Tests executing of cron job."""
    self.app.get('/apply-ccs')
    self.assertEqual(len(self.itm.modified_issues), 3)

    issue_1337 = self.itm.modified_issues[1337]
    six.assertCountEqual(self, issue_1337.cc, [
        'user@example.com',
        'user2@example.com',
    ])

    self.assertTrue(issue_1337.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1337.comment, DEADLINE_NOTE)

    self.assertNotIn(1338, self.itm.modified_issues)

    issue_1339 = self.itm.modified_issues[1339]
    six.assertCountEqual(self, issue_1339.cc, [
        'user@example.com',
        'user2@example.com',
    ])

    self.assertTrue(issue_1339.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1339.comment, '')

    issue_1340 = self.itm.modified_issues[1340]
    six.assertCountEqual(self, issue_1340.cc, [
        'user@example.com',
        'user2@example.com',
    ])
    self.assertTrue(issue_1340.has_label_matching('reported-2015-01-01'))
    self.assertFalse(issue_1340.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1340.comment, '')
