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

import webapp2
import webtest

from datastore import data_types
from handlers.cron import oss_fuzz_apply_ccs
from issue_management import issue_filer
from issue_management.issue import Issue
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class IssueTrackerManager(object):
  """Mock issue tracker manager."""

  def __init__(self, project_name):
    self.project_name = project_name
    self.last_issue = None
    self.modified_issues = {}

  def get_original_issue(self, issue_id):
    """Get original issue."""
    issue = Issue()
    issue.open = True
    issue.itm = self
    issue.id = issue_id

    if issue_id == 1337:
      issue.add_cc('user@example.com')
      issue.add_label('Restrict-View-Commit')
    elif issue_id == 1338:
      issue.add_cc('user@example.com')
      issue.add_cc('user2@example.com')
    elif issue_id == 1340:
      issue.add_label('reported-2015-01-01')

    return issue

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
    """Save a issue."""
    self.modified_issues[issue.id] = issue


@test_utils.with_cloud_emulators('datastore')
class OssFuzzApplyCcsTest(unittest.TestCase):
  """Test OssFuzzApplyCcs."""

  def setUp(self):
    test_helpers.patch_environ(self)
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/apply-ccs', oss_fuzz_apply_ccs.Handler)]))

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
        'base.utils.utcnow',
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'handlers.base_handler.Handler.is_cron',
    ])

    self.itm = IssueTrackerManager('oss-fuzz')
    self.mock.get_issue_tracker_manager.return_value = self.itm
    self.mock.utcnow.return_value = datetime.datetime(2016, 1, 1)

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
    self.assertItemsEqual(issue_1337.cc, [
        'user@example.com',
        'user2@example.com',
    ])

    self.assertTrue(issue_1337.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1337.comment, issue_filer.DEADLINE_NOTE)

    self.assertNotIn(1338, self.itm.modified_issues)

    issue_1339 = self.itm.modified_issues[1339]
    self.assertItemsEqual(issue_1339.cc, [
        'user@example.com',
        'user2@example.com',
    ])

    self.assertTrue(issue_1339.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1339.comment, '')

    issue_1340 = self.itm.modified_issues[1340]
    self.assertItemsEqual(issue_1340.cc, [
        'user@example.com',
        'user2@example.com',
    ])
    self.assertTrue(issue_1340.has_label_matching('reported-2015-01-01'))
    self.assertFalse(issue_1340.has_label_matching('reported-2016-01-01'))
    self.assertEqual(issue_1340.comment, '')
