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
"""issue_filer tests."""

import datetime
import parameterized
import unittest

from datastore import data_types
from issue_management import issue_filer
from issue_management import label_utils

from tests.test_libs import helpers
from tests.test_libs import test_utils


class IssueTrackerManager(object):
  """Mock issue tracker manager."""

  def __init__(self, project_name):
    self.project_name = project_name
    self.last_issue = None

  def save(self, issue, *args, **kwargs):  # pylint: disable=unused-argument
    self.last_issue = issue


@test_utils.with_cloud_emulators('datastore')
class IssueFilerTests(unittest.TestCase):
  """Tests for the issue filer."""

  def setUp(self):
    data_types.Job(
        name='job1',
        environment_string='ISSUE_VIEW_RESTRICTIONS = all',
        platform='linux').put()

    data_types.Job(
        name='job2',
        environment_string='ISSUE_VIEW_RESTRICTIONS = security',
        platform='linux').put()

    data_types.Job(
        name='job3',
        environment_string='ISSUE_VIEW_RESTRICTIONS = none',
        platform='linux').put()

    data_types.Job(
        name='chromeos_job4', environment_string='', platform='linux').put()

    testcase_args = {
        'crash_type': 'Heap-use-after-free',
        'crash_address': '0x1337',
        'crash_state': '1\n2\n3\n',
        'crash_stacktrace': 'stack\n',
        'fuzzer_name': 'fuzzer',
    }

    self.testcase1 = data_types.Testcase(job_type='job1', **testcase_args)
    self.testcase1.put()

    self.testcase1_security = data_types.Testcase(
        security_flag=True, job_type='job1', **testcase_args)
    self.testcase1_security.put()

    self.testcase2 = data_types.Testcase(job_type='job2', **testcase_args)
    self.testcase2.put()

    self.testcase2_security = data_types.Testcase(
        security_flag=True, job_type='job2', **testcase_args)
    self.testcase2_security.put()

    self.testcase3 = data_types.Testcase(job_type='job3', **testcase_args)
    self.testcase3.put()

    self.testcase3_security = data_types.Testcase(
        job_type='job3', security_flag=True, **testcase_args)
    self.testcase3_security.put()

    self.testcase4 = data_types.Testcase(
        job_type='chromeos_job4', **testcase_args)
    self.testcase4.put()

    self.testcase5 = data_types.Testcase(
        job_type='job',
        additional_metadata='{"issue_labels": "label1 , label2,,"}',
        **testcase_args)
    self.testcase5.put()

    self.testcase6 = data_types.Testcase(
        job_type='job', additional_metadata='invalid', **testcase_args)
    self.testcase5.put()

    data_types.ExternalUserPermission(
        email='user@example.com',
        entity_name='job2',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user2@example.com',
        entity_name='job3',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.SECURITY).put()

    helpers.patch(self, [
        'base.utils.utcnow',
        'datastore.data_handler.get_issue_description',
    ])

    self.mock.get_issue_description.return_value = 'Issue'
    self.mock.utcnow.return_value = datetime.datetime(2016, 1, 1)

  def test_filed_issues_chromium(self):
    """Tests issue filing for chromium."""
    itm = IssueTrackerManager('chromium')
    issue_filer.file_issue(self.testcase4, itm)
    self.assertIn('OS-Chrome', itm.last_issue.labels)

  def test_filed_issues_oss_fuzz(self):
    """Tests issue filing for oss-fuzz."""
    itm = IssueTrackerManager('oss-fuzz')
    issue_filer.file_issue(self.testcase1, itm)
    self.assertTrue(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertFalse(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

    issue_filer.file_issue(self.testcase1_security, itm)
    self.assertTrue(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertFalse(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

    issue_filer.file_issue(self.testcase2, itm)
    self.assertFalse(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertTrue(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

    issue_filer.file_issue(self.testcase2_security, itm)
    self.assertTrue(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertTrue(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

    issue_filer.file_issue(self.testcase3, itm)
    self.assertFalse(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertFalse(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

    issue_filer.file_issue(self.testcase3_security, itm)
    self.assertFalse(itm.last_issue.has_label_matching('restrict-view-commit'))
    self.assertTrue(itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(issue_filer.DEADLINE_NOTE, itm.last_issue.body)

  def test_testcase_metadata_labels(self):
    """Tests issue filing with additional labels."""
    itm = IssueTrackerManager('chromium')
    issue_filer.file_issue(self.testcase5, itm)
    self.assertListEqual([
        'ClusterFuzz',
        'Reproducible',
        'Pri-1',
        'Stability-Crash',
        'Type-Bug',
        'label1',
        'label2',
    ], itm.last_issue.labels)

  def test_testcase_metadata_invalid(self):
    """Tests issue filing with invalid metadata."""
    itm = IssueTrackerManager('chromium')
    issue_filer.file_issue(self.testcase6, itm)
    self.assertListEqual(
        ['ClusterFuzz', 'Reproducible', 'Pri-1', 'Stability-Crash', 'Type-Bug'],
        itm.last_issue.labels)

  @parameterized.parameterized.expand(['chromium', 'oss-fuzz', 'any_project'])
  def test_security_severity_functional_bug(self, project_name):
    """Test security severity label is not set for a functional bug."""
    itm = IssueTrackerManager(project_name)

    self.testcase1.security_flag = False
    self.testcase1.security_severity = None
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, itm)
    self.assertFalse(itm.last_issue.has_label_by_prefix('Security_Severity-'))

  @parameterized.parameterized.expand(['chromium', 'oss-fuzz', 'any_project'])
  def test_security_severity_security_bug_default_severity(self, project_name):
    """Test security severity label is set when testcase is a security bug and
    no severity can be determined."""
    itm = IssueTrackerManager(project_name)

    self.testcase1.security_flag = True
    self.testcase1.security_severity = None
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, itm)
    self.assertIn('Security_Severity-High', itm.last_issue.labels)
    self.assertEqual(
        1, len(itm.last_issue.get_labels_by_prefix('Security_Severity-')))

  @parameterized.parameterized.expand(['chromium', 'oss-fuzz', 'any_project'])
  def test_security_severity_security_bug_severity_override(self, project_name):
    """Test security severity label is set correct when testcase has its own
    severity but there is an override provided."""
    itm = IssueTrackerManager(project_name)

    self.testcase1.security_flag = True
    self.testcase1.security_severity = data_types.SecuritySeverity.HIGH
    self.testcase1.put()
    issue_filer.file_issue(
        self.testcase1,
        itm,
        security_severity=data_types.SecuritySeverity.MEDIUM)
    self.assertNotIn('Security_Severity-High', itm.last_issue.labels)
    self.assertIn('Security_Severity-Medium', itm.last_issue.labels)
    self.assertEqual(
        1, len(itm.last_issue.get_labels_by_prefix('Security_Severity-')))

  @parameterized.parameterized.expand(['chromium', 'oss-fuzz', 'any_project'])
  def test_security_severity_security_bug_with_severity_set(self, project_name):
    """Test security severity label is set when testcase is a security bug and
    has a security severity."""
    security_severity_string_map = {
        data_types.SecuritySeverity.HIGH: 'Security_Severity-High',
        data_types.SecuritySeverity.MEDIUM: 'Security_Severity-Medium',
        data_types.SecuritySeverity.LOW: 'Security_Severity-Low',
    }

    for security_severity in security_severity_string_map:
      itm = IssueTrackerManager(project_name)

      self.testcase1.security_flag = True
      self.testcase1.security_severity = security_severity
      self.testcase1.put()

      issue_filer.file_issue(self.testcase1, itm)
      self.assertIn(security_severity_string_map[security_severity],
                    itm.last_issue.labels)
      self.assertEqual(
          1, len(itm.last_issue.get_labels_by_prefix('Security_Severity-')))

  @parameterized.parameterized.expand(['chromium', 'oss-fuzz', 'any_project'])
  def test_memory_tool_used(self, project_name):
    """Test memory tool label is correctly set."""
    for entry in label_utils.MEMORY_TOOLS_LABELS:
      itm = IssueTrackerManager(project_name)

      self.testcase1.crash_stacktrace = '\n\n%s\n' % entry['token']
      self.testcase1.put()
      issue_filer.file_issue(self.testcase1, itm)
      self.assertIn(entry['label'], itm.last_issue.labels)
