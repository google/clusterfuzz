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

# pylint: disable=protected-access

from builtins import object
import datetime
import parameterized
import unittest

from datastore import data_types
from issue_management import issue_tracker_policy
from issue_management import label_utils
from issue_management import monorail
from libs import issue_filer

from tests.test_libs import helpers
from tests.test_libs import test_utils

CHROMIUM_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'all': {
        'labels': ['ClusterFuzz', 'OS-%PLATFORM%', 'Stability-%SANITIZER%'],
        'status': 'new'
    },
    'existing': {
        'labels': ['Stability-%SANITIZER%']
    },
    'labels': {
        'fuzz_blocker': 'Fuzz-Blocker',
        'ignore': 'ClusterFuzz-Ignore',
        'invalid_fuzzer': 'ClusterFuzz-Invalid-Fuzzer',
        'needs_feedback': 'Needs-Feedback',
        'reported_prefix': 'Reported-',
        'reproducible': 'Reproducible',
        'restrict_view': 'Restrict-View-SecurityTeam',
        'security_severity_prefix': 'Security_Severity-',
        'unreproducible': 'Unreproducible',
        'verified': 'ClusterFuzz-Verified'
    },
    'non_security': {
        'crash_labels': ['Stability-Crash', 'Pri-1'],
        'labels': ['Type-Bug'],
        'non_crash_labels': ['Pri-2']
    },
    'security': {
        'labels': ['Type-Bug-Security', 'Security_Severity-%SEVERITY%']
    },
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'fixed': 'Fixed',
        'new': 'Untriaged',
        'verified': 'Verified',
        'wontfix': 'WontFix'
    }
})

OSS_FUZZ_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'all': {
        'issue_body_footer':
            'When you fix this bug, please\n'
            '  * mention the fix revision(s).\n'
            '  * state whether the bug was a short-lived regression or an '
            'old bug in any stable releases.\n'
            '  * add any other useful information.\n'
            'This information can help downstream consumers.\n\n'
            'If you need to contact the OSS-Fuzz team with a question, '
            'concern, or any other feedback, please file an issue at '
            'https://github.com/google/oss-fuzz/issues.',
        'labels': [
            'ClusterFuzz', 'OS-%PLATFORM%', 'Reported-%YYYY-MM-DD%',
            'Stability-%SANITIZER%'
        ],
        'status':
            'new'
    },
    'deadline_policy_message':
        'This bug is subject to a 90 day disclosure deadline. If 90 days '
        'elapse\n'
        'without an upstream patch, then the bug report will automatically\n'
        'become visible to the public.',
    'existing': {
        'labels': ['Stability-%SANITIZER%']
    },
    'labels': {
        'fuzz_blocker': 'Fuzz-Blocker',
        'ignore': 'ClusterFuzz-Ignore',
        'invalid_fuzzer': 'ClusterFuzz-Invalid-Fuzzer',
        'needs_feedback': 'Needs-Feedback',
        'reported_prefix': 'Reported-',
        'reproducible': 'Reproducible',
        'restrict_view': 'Restrict-View-Commit',
        'security_severity_prefix': 'Security_Severity-',
        'unreproducible': 'Unreproducible',
        'verified': 'ClusterFuzz-Verified'
    },
    'non_security': {
        'labels': ['Type-Bug']
    },
    'security': {
        'labels': ['Type-Bug-Security', 'Security_Severity-%SEVERITY%']
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

FIX_NOTE = (
    'When you fix this bug, please\n'
    '  * mention the fix revision(s).\n'
    '  * state whether the bug was a short-lived regression or an old bug'
    ' in any stable releases.\n'
    '  * add any other useful information.\n'
    'This information can help downstream consumers.')

QUESTIONS_NOTE = (
    'If you need to contact the OSS-Fuzz team with a question, concern, or any '
    'other feedback, please file an issue at '
    'https://github.com/google/oss-fuzz/issues.')


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
    self.testcase6.put()

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
        'issue_management.issue_tracker_policy.get',
    ])

    self.mock.get_issue_description.return_value = 'Issue'
    self.mock.utcnow.return_value = datetime.datetime(2016, 1, 1)

  def test_filed_issues_chromium(self):
    """Tests issue filing for chromium."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase4, issue_tracker)
    self.assertIn('OS-Chrome', issue_tracker._itm.last_issue.labels)
    self.assertEqual('Untriaged', issue_tracker._itm.last_issue.status)
    self.assertNotIn('Restrict-View-SecurityTeam',
                     issue_tracker._itm.last_issue.labels)

  def test_filed_issues_chromium_security(self):
    """Tests issue filing for chromium."""
    self.testcase4.security_flag = True
    self.testcase4.put()
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase4, issue_tracker)
    self.assertIn('OS-Chrome', issue_tracker._itm.last_issue.labels)
    self.assertEqual('Untriaged', issue_tracker._itm.last_issue.status)
    self.assertIn('Restrict-View-SecurityTeam',
                  issue_tracker._itm.last_issue.labels)

  def test_filed_issues_oss_fuzz(self):
    """Tests issue filing for oss-fuzz."""
    self.mock.get.return_value = OSS_FUZZ_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('oss-fuzz'))
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertEqual('New', issue_tracker._itm.last_issue.status)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase1_security, issue_tracker)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase2, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase2_security, issue_tracker)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase3, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase3_security, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)

  def test_testcase_metadata_labels(self):
    """Tests issue filing with additional labels."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase5, issue_tracker)
    self.assertItemsEqual([
        'ClusterFuzz',
        'Reproducible',
        'Pri-1',
        'Stability-Crash',
        'Type-Bug',
        'label1',
        'label2',
    ], issue_tracker._itm.last_issue.labels)

  def test_testcase_metadata_invalid(self):
    """Tests issue filing with invalid metadata."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase6, issue_tracker)
    self.assertItemsEqual(
        ['ClusterFuzz', 'Reproducible', 'Pri-1', 'Stability-Crash', 'Type-Bug'],
        issue_tracker._itm.last_issue.labels)

  @parameterized.parameterized.expand([
      ('chromium', CHROMIUM_POLICY),
      ('oss-fuzz', OSS_FUZZ_POLICY),
  ])
  def test_security_severity_functional_bug(self, project_name, policy):
    """Test security severity label is not set for a functional bug."""
    self.mock.get.return_value = policy
    issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

    self.testcase1.security_flag = False
    self.testcase1.security_severity = None
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_by_prefix('Security_Severity-'))

  @parameterized.parameterized.expand([
      ('chromium', CHROMIUM_POLICY),
      ('oss-fuzz', OSS_FUZZ_POLICY),
  ])
  def test_security_severity_security_bug_default_severity(
      self, project_name, policy):
    """Test security severity label is set when testcase is a security bug and
    no severity can be determined."""
    self.mock.get.return_value = policy
    issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

    self.testcase1.security_flag = True
    self.testcase1.security_severity = None
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Security_Severity-High',
                  issue_tracker._itm.last_issue.labels)
    self.assertEqual(
        1,
        len(
            issue_tracker._itm.last_issue.get_labels_by_prefix(
                'Security_Severity-')))

  @parameterized.parameterized.expand([
      ('chromium', CHROMIUM_POLICY),
      ('oss-fuzz', OSS_FUZZ_POLICY),
  ])
  def test_security_severity_security_bug_severity_override(
      self, project_name, policy):
    """Test security severity label is set correct when testcase has its own
    severity but there is an override provided."""
    self.mock.get.return_value = policy
    issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

    self.testcase1.security_flag = True
    self.testcase1.security_severity = data_types.SecuritySeverity.HIGH
    self.testcase1.put()
    issue_filer.file_issue(
        self.testcase1,
        issue_tracker,
        security_severity=data_types.SecuritySeverity.MEDIUM)
    self.assertNotIn('Security_Severity-High',
                     issue_tracker._itm.last_issue.labels)
    self.assertIn('Security_Severity-Medium',
                  issue_tracker._itm.last_issue.labels)
    self.assertEqual(
        1,
        len(
            issue_tracker._itm.last_issue.get_labels_by_prefix(
                'Security_Severity-')))

  @parameterized.parameterized.expand([
      ('chromium', CHROMIUM_POLICY),
      ('oss-fuzz', OSS_FUZZ_POLICY),
  ])
  def test_security_severity_security_bug_with_severity_set(
      self, project_name, policy):
    """Test security severity label is set when testcase is a security bug and
    has a security severity."""
    self.mock.get.return_value = policy
    security_severity_string_map = {
        data_types.SecuritySeverity.HIGH: 'Security_Severity-High',
        data_types.SecuritySeverity.MEDIUM: 'Security_Severity-Medium',
        data_types.SecuritySeverity.LOW: 'Security_Severity-Low',
    }

    for security_severity in security_severity_string_map:
      issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

      self.testcase1.security_flag = True
      self.testcase1.security_severity = security_severity
      self.testcase1.put()

      issue_filer.file_issue(self.testcase1, issue_tracker)
      self.assertIn(security_severity_string_map[security_severity],
                    issue_tracker._itm.last_issue.labels)
      self.assertEqual(
          1,
          len(
              issue_tracker._itm.last_issue.get_labels_by_prefix(
                  'Security_Severity-')))

  @parameterized.parameterized.expand([
      ('chromium', CHROMIUM_POLICY),
      ('oss-fuzz', OSS_FUZZ_POLICY),
  ])
  def test_memory_tool_used(self, project_name, policy):
    """Test memory tool label is correctly set."""
    self.mock.get.return_value = policy
    for entry in label_utils.MEMORY_TOOLS_LABELS:
      issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

      self.testcase1.crash_stacktrace = '\n\n%s\n' % entry['token']
      self.testcase1.put()
      issue_filer.file_issue(self.testcase1, issue_tracker)
      self.assertIn('Stability-' + entry['label'],
                    issue_tracker._itm.last_issue.labels)

  def test_reproducible_flag(self):
    """Test (un)reproducible flag is correctly set."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))

    self.testcase1.one_time_crasher_flag = True
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Unreproducible', issue_tracker._itm.last_issue.labels)

    self.testcase1.one_time_crasher_flag = False
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Reproducible', issue_tracker._itm.last_issue.labels)

  def test_crash_labels(self):
    """Test crash label setting."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))

    self.testcase1.crash_type = 'UNKNOWN'
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Pri-1', issue_tracker._itm.last_issue.labels)
    self.assertIn('Stability-Crash', issue_tracker._itm.last_issue.labels)

    self.testcase1.crash_type = 'Undefined-shift'
    self.testcase1.put()
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Pri-2', issue_tracker._itm.last_issue.labels)
    self.assertNotIn('Stability-Crash', issue_tracker._itm.last_issue.labels)
