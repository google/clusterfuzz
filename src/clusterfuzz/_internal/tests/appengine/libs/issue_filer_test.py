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

import datetime
import os
import unittest
from unittest import mock

import parameterized

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.issue_management import google_issue_tracker
from clusterfuzz._internal.issue_management import issue_filer
from clusterfuzz._internal.issue_management import issue_tracker_policy
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.issue_management import monorail
from clusterfuzz._internal.issue_management.google_issue_tracker.issue_tracker import \
    IssueAccessLevel
from clusterfuzz._internal.issue_management.issue_tracker import LabelStore
from clusterfuzz._internal.issue_management.monorail.issue import \
    Issue as MonorailIssue
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import mock_config
from clusterfuzz._internal.tests.test_libs import test_utils

CHROMIUM_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'verified': 'Verified',
        'new': 'Untriaged',
        'wontfix': 'WontFix',
        'fixed': 'Fixed'
    },
    'all': {
        'status': 'new',
        'labels': ['ClusterFuzz', 'Stability-%SANITIZER%']
    },
    'non_security': {
        'labels': ['Type-Bug'],
        'crash_labels': ['Stability-Crash', 'Pri-1'],
        'non_crash_labels': ['Pri-2']
    },
    'labels': {
        'ignore': 'ClusterFuzz-Ignore',
        'verified': 'ClusterFuzz-Verified',
        'security_severity': 'Security_Severity-%SEVERITY%',
        'needs_feedback': 'Needs-Feedback',
        'invalid_fuzzer': 'ClusterFuzz-Invalid-Fuzzer',
        'reported': None,
        'wrong': 'ClusterFuzz-Wrong',
        'fuzz_blocker': 'Fuzz-Blocker',
        'reproducible': 'Reproducible',
        'auto_cc_from_owners': 'ClusterFuzz-Auto-CC',
        'os': 'OS-%PLATFORM%',
        'unreproducible': 'Unreproducible',
        'restrict_view': 'Restrict-View-SecurityTeam'
    },
    'security': {
        'labels': ['Type-Bug-Security'],
        '_ext_collaborators': ['superman@krypton.com', 'batman@gotham.com'],
        '_ext_issue_access_limit': {
            'access_limit': IssueAccessLevel.LIMIT_VIEW
        }
    },
    'existing': {
        'labels': ['Stability-%SANITIZER%']
    },
    'unreproducible_component': 'Unreproducible>Component'
})

CHROMIUM_POLICY_FALLBACK = issue_tracker_policy.IssueTrackerPolicy({
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'verified': 'Verified',
        'new': 'Untriaged',
        'wontfix': 'WontFix',
        'fixed': 'Fixed'
    },
    'all': {
        'status': 'new',
        'labels': ['ClusterFuzz', 'Stability-%SANITIZER%']
    },
    'non_security': {
        'labels': ['Type-Bug'],
        'crash_labels': ['Stability-Crash', 'Pri-1'],
        'non_crash_labels': ['Pri-2']
    },
    'labels': {
        'ignore': 'ClusterFuzz-Ignore',
        'verified': 'ClusterFuzz-Verified',
        'security_severity': 'Security_Severity-%SEVERITY%',
        'needs_feedback': 'Needs-Feedback',
        'invalid_fuzzer': 'ClusterFuzz-Invalid-Fuzzer',
        'reported': None,
        'wrong': 'ClusterFuzz-Wrong',
        'fuzz_blocker': 'Fuzz-Blocker',
        'reproducible': 'Reproducible',
        'auto_cc_from_owners': 'ClusterFuzz-Auto-CC',
        'os': 'OS-%PLATFORM%',
        'unreproducible': 'Unreproducible',
        'restrict_view': 'Restrict-View-SecurityTeam'
    },
    'security': {
        'labels': ['Type-Bug-Security'],
        '_ext_collaborators': ['superman@krypton.com', 'batman@gotham.com'],
        '_ext_issue_access_limit': {
            'access_limit': IssueAccessLevel.LIMIT_VIEW
        }
    },
    'existing': {
        'labels': ['Stability-%SANITIZER%']
    },
    'fallback_component': 'fallback>component',
    'fallback_policy_message':
        '**NOTE**: This bug was filed into this component due to permission '
        'or configuration issues with the specified component(s) %COMPONENTS%'
})

CHROMIUM_GIT_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'type': 'google_issue_tracker',
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'verified': 'Verified',
        'new': 'Untriaged',
        'wontfix': 'WontFix',
        'fixed': 'Fixed'
    },
    'all': {
        'status': 'new',
        'labels': ['1679217', 'Stability-%SANITIZER%']
    },
    'non_security': {
        'labels': ['Type-Bug'],
        'crash_labels': ['Stability-Crash', 'Pri-1'],
        'non_crash_labels': ['Pri-2']
    },
    'labels': {
        'ignore': '1',
        'verified': '2',
        'security_severity': '3',
        'needs_feedback': '4',
        'invalid_fuzzer': '5',
        'reported': '9999999',
        'wrong': '6',
        'fuzz_blocker': '7',
        'reproducible': '8',
        'auto_cc_from_owners': '9',
        'os': '10',
        'unreproducible': '11',
        'restrict_view': '12'
    },
    'security': {
        'labels': ['Type-Bug-Security'],
        '_ext_collaborators': ['superman@krypton.com', 'batman@gotham.com'],
        '_ext_issue_access_limit': {
            'access_limit': IssueAccessLevel.LIMIT_VIEW
        }
    },
    'existing': {
        'labels': ['Stability-%SANITIZER%'],
        'ext_collaborators': ['user1@google.com']
    },
    'component_id': '123',
    'fallback_component': '1234567890',
    'fallback_policy_message':
        '**NOTE**: This bug was filed into this component due to permission '
        'or configuration issues with the specified component(s) %COMPONENTS%',
    'default_component_id': '123',
})

CHROMIUM_MIRACLEPTR_STACKTRACE_PROTECTED = (
    """SUMMARY: AddressSanitizer: heap-use-after-free swap.h:36:9

Shadow bytes around the buggy address:

  0x0c1680046160: fa fa f7 fa fd fd fd fd fd fd fd fd fd fd fd fd

  0x0c1680046170: fd fa fa fa fa fa fa fa f7 fa fd fd fd fd fd fd

=>0x0c1680046180: fd fd fd fd fd[fd]fd fa fa fa fa fa fa fa f7 fa

  0x0c1680046190: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa

  0x0c16800461a0: fa fa fa fa f7 fa fd fd fd fd fd fd fd fd fd fd

Shadow byte legend (one shadow byte represents 8 application bytes):

  Addressable:           00

  Partially addressable: 01 02 03 04 05 06 07

  ...

  Right alloca redzone:    cb


MiraclePtr Status: PROTECTED

The crash occurred while a raw_ptr<T> object containing a dangling pointer was being dereferenced.

MiraclePtr should make this crash non-exploitable in regular builds.

Refer to https://chromium.googlesource.com/chromium/src/+/main/base/memory/raw_ptr.md for details.

==3196407==ABORTING""")

CHROMIUM_MIRACLEPTR_STACKTRACE_NOT_PROTECTED = (
    """SUMMARY: AddressSanitizer: heap-use-after-free swap.h:36:9

Shadow bytes around the buggy address:

  0x0c1680046160: fa fa f7 fa fd fd fd fd fd fd fd fd fd fd fd fd

  0x0c1680046170: fd fa fa fa fa fa fa fa f7 fa fd fd fd fd fd fd

=>0x0c1680046180: fd fd fd fd fd[fd]fd fa fa fa fa fa fa fa f7 fa

  0x0c1680046190: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa

  0x0c16800461a0: fa fa fa fa f7 fa fd fd fd fd fd fd fd fd fd fd

Shadow byte legend (one shadow byte represents 8 application bytes):

  Addressable:           00

  Partially addressable: 01 02 03 04 05 06 07

  ...

  Right alloca redzone:    cb


MiraclePtr Status: NOT PROTECTED

The crash occurred while a raw_ptr<T> object containing a dangling pointer was being dereferenced.

MiraclePtr should make this crash non-exploitable in regular builds.

Refer to https://chromium.googlesource.com/chromium/src/+/main/base/memory/raw_ptr.md for details.

==3196407==ABORTING""")

CHROMIUM_MIRACLEPTR_STACKTRACE_MANUAL = (
    """SUMMARY: AddressSanitizer: heap-use-after-free swap.h:36:9

Shadow bytes around the buggy address:

  0x0c1680046160: fa fa f7 fa fd fd fd fd fd fd fd fd fd fd fd fd

  0x0c1680046170: fd fa fa fa fa fa fa fa f7 fa fd fd fd fd fd fd

=>0x0c1680046180: fd fd fd fd fd[fd]fd fa fa fa fa fa fa fa f7 fa

  0x0c1680046190: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa

  0x0c16800461a0: fa fa fa fa f7 fa fd fd fd fd fd fd fd fd fd fd

Shadow byte legend (one shadow byte represents 8 application bytes):

  Addressable:           00

  Partially addressable: 01 02 03 04 05 06 07

  ...

  Right alloca redzone:    cb


MiraclePtr Status: MANUAL ANALYSIS REQUIRED

The crash occurred while a raw_ptr<T> object containing a dangling pointer was being dereferenced.

MiraclePtr should make this crash non-exploitable in regular builds.

Refer to https://chromium.googlesource.com/chromium/src/+/main/base/memory/raw_ptr.md for details.

==3196407==ABORTING""")

OSS_FUZZ_POLICY = issue_tracker_policy.IssueTrackerPolicy({
    'status': {
        'assigned': 'Assigned',
        'duplicate': 'Duplicate',
        'verified': 'Verified',
        'new': 'New',
        'wontfix': 'WontFix',
        'fixed': 'Fixed'
    },
    'all': {
        'status': 'new',
        'labels': ['ClusterFuzz', 'Stability-%SANITIZER%'],
        'issue_body_footer':
            'When you fix this bug, please\n'
            '  * mention the fix revision(s).\n'
            '  * state whether the bug was a short-lived regression or an old '
            'bug in any stable releases.\n'
            '  * add any other useful information.\n'
            'This information can help downstream consumers.\n\n'
            'If you need to contact the OSS-Fuzz team with a question, '
            'concern, or any other feedback, please file an issue at '
            'https://github.com/google/oss-fuzz/issues.'
    },
    'non_security': {
        'labels': ['Type-Bug']
    },
    'labels': {
        'ignore': 'ClusterFuzz-Ignore',
        'verified': 'ClusterFuzz-Verified',
        'security_severity': 'Security_Severity-%SEVERITY%',
        'needs_feedback': 'Needs-Feedback',
        'invalid_fuzzer': 'ClusterFuzz-Invalid-Fuzzer',
        'reported': 'Reported-%YYYY-MM-DD%',
        'wrong': 'ClusterFuzz-Wrong',
        'fuzz_blocker': 'Fuzz-Blocker',
        'reproducible': 'Reproducible',
        'auto_cc_from_owners': 'ClusterFuzz-Auto-CC',
        'os': 'OS-%PLATFORM%',
        'unreproducible': 'Unreproducible',
        'restrict_view': 'Restrict-View-Commit'
    },
    'security': {
        'labels': ['Type-Bug-Security']
    },
    'deadline_policy_message':
        'This bug is subject to a 90 day disclosure deadline. If 90 days '
        'elapse\n'
        'without an upstream patch, then the bug report will automatically\n'
        'become visible to the public.',
    'existing': {
        'labels': ['Stability-%SANITIZER%']
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


class IssueTrackerManager:
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
    self.job1 = data_types.Job(
        name='job1',
        environment_string=('ISSUE_VIEW_RESTRICTIONS = all\n'
                            'PROJECT_NAME = proj\n'),
        platform='linux')
    self.job1.put()

    self.job2 = data_types.Job(
        name='job2',
        environment_string='ISSUE_VIEW_RESTRICTIONS = security\n',
        platform='linux')
    self.job2.put()

    self.job3 = data_types.Job(
        name='job3',
        environment_string='ISSUE_VIEW_RESTRICTIONS = none\n',
        platform='linux')
    self.job3.put()

    data_types.Job(
        name='chromeos_job4', environment_string='', platform='linux').put()

    data_types.Job(name='ios_job', environment_string='', platform='mac').put()

    testcase_args = {
        'crash_type': 'Heap-use-after-free',
        'crash_address': '0x1337',
        'crash_state': '1\n2\n3\n',
        'crash_stacktrace': 'stack\n',
        'fuzzer_name': 'fuzzer',
    }

    testcase_args_2 = testcase_args.copy()

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
        additional_metadata=('{"issue_labels": "label1 , label2,,", '
                             '"issue_components": "component1,component2"}'),
        **testcase_args)
    self.testcase5.put()

    self.testcase6 = data_types.Testcase(
        job_type='job', additional_metadata='invalid', **testcase_args)
    self.testcase6.put()

    self.testcase7 = data_types.Testcase(job_type='ios_job4', **testcase_args)
    self.testcase7.put()

    self.testcase8 = data_types.Testcase(job_type='job1', **testcase_args_2)
    self.testcase8.set_metadata('crash_categories', ['Fuzzer-exit'])
    self.testcase8.put()

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
        'clusterfuzz._internal.base.utils.utcnow',
        'clusterfuzz._internal.datastore.data_handler.get_issue_description',
        'clusterfuzz._internal.issue_management.issue_tracker_policy.get',
    ])

    self.mock.get_issue_description.return_value = 'Issue'
    self.mock.utcnow.return_value = datetime.datetime(2016, 1, 1)

  def test_filed_issue_google_issue_tracker(self):
    """Tests issue filing flow for chromium with google_issue_tracker."""

    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.IssueTrackerConfig.get',
        'clusterfuzz._internal.issue_management.google_issue_tracker.IssueTracker._execute',
        'clusterfuzz._internal.issue_management.google_issue_tracker.client.build',
        'clusterfuzz._internal.issue_management.google_issue_tracker.issue_tracker.Issue.labels'
    ])
    # This mock is for the issue_tracker_utils.get_issue_tracker call.
    self.mock.get.return_value = CHROMIUM_GIT_POLICY
    # This mock is for the IssueTrackerConfig.get call.
    self.mock.get.return_value = {
        'type': 'google_issue_tracker',
        'default_component_id': '1234567890',
        'component_id': '123',
        'url': 'https://issues.chromium.org/issues',
    }
    exp_issue_id = 68828938
    self.mock._execute.return_value = {
        'issueId': exp_issue_id,
        'issueState': {
            'componentId': '29002',
            'type': 'BUG',
        },
    }
    issue_tracker_utils._ISSUE_TRACKER_CONSTRUCTORS = {
        'google_issue_tracker': google_issue_tracker.get_issue_tracker
    }

    issue_tracker = issue_tracker_utils.get_issue_tracker()
    actual_issue_id, exception = issue_filer.file_issue(self.testcase1,
                                                        issue_tracker)
    self.assertIsNone(exception)
    self.assertEqual(exp_issue_id, actual_issue_id)

  def test_filed_issues_chromium(self):
    """Tests issue filing for chromium."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    _, exception = issue_filer.file_issue(self.testcase4, issue_tracker)
    self.assertIsNone(exception)
    self.assertIn('OS-Chrome', issue_tracker._itm.last_issue.labels)
    self.assertEqual('Untriaged', issue_tracker._itm.last_issue.status)
    self.assertNotIn('Restrict-View-SecurityTeam',
                     issue_tracker._itm.last_issue.labels)

  def test_filed_issues_chromium_ios(self):
    """Tests issue filing for chromium iOS."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase7, issue_tracker)
    self.assertIn('OS-iOS', issue_tracker._itm.last_issue.labels)

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

  def test_filed_issues_chromium_miracleptr(self):
    """Tests MiraclePtr Status label for chromium."""
    self.mock.get.return_value = CHROMIUM_POLICY
    helpers.patch(
        self, ['clusterfuzz._internal.datastore.data_handler.get_stacktrace'])
    self.mock.get_stacktrace.return_value = CHROMIUM_MIRACLEPTR_STACKTRACE_PROTECTED
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('MiraclePtr-Protected', issue_tracker._itm.last_issue.labels)

    self.mock.get_stacktrace.return_value = CHROMIUM_MIRACLEPTR_STACKTRACE_NOT_PROTECTED
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('MiraclePtr-NotProtected',
                  issue_tracker._itm.last_issue.labels)

    self.mock.get_stacktrace.return_value = CHROMIUM_MIRACLEPTR_STACKTRACE_MANUAL
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('MiraclePtr-ManualAnalysisRequired',
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
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase1_security, issue_tracker)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase2, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase2_security, issue_tracker)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase3, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

    issue_filer.file_issue(self.testcase3_security, issue_tracker)
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

  def test_filed_issues_oss_fuzz_disable_disclose(self):
    """Test filing oss-fuzz issues with disclosure disabled."""
    self.job2.environment_string += 'DISABLE_DISCLOSURE = True\n'
    self.job2.put()

    self.mock.get.return_value = OSS_FUZZ_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('oss-fuzz'))

    issue_filer.file_issue(self.testcase2_security, issue_tracker)
    self.assertTrue(
        issue_tracker._itm.last_issue.has_label_matching(
            'restrict-view-commit'))
    self.assertFalse(
        issue_tracker._itm.last_issue.has_label_matching('reported-2016-01-01'))
    self.assertNotIn(DEADLINE_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(FIX_NOTE, issue_tracker._itm.last_issue.body)
    self.assertIn(QUESTIONS_NOTE, issue_tracker._itm.last_issue.body)

  def test_testcase_metadata_labels_and_components(self):
    """Tests issue filing with additional labels and components."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase5, issue_tracker)
    self.assertCountEqual([
        'ClusterFuzz',
        'Reproducible',
        'Pri-1',
        'Stability-Crash',
        'Type-Bug',
        'label1',
        'label2',
    ], issue_tracker._itm.last_issue.labels)
    self.assertCountEqual([
        'component1',
        'component2',
    ], issue_tracker._itm.last_issue.components)

  def test_testcase_metadata_invalid(self):
    """Tests issue filing with invalid metadata."""
    self.mock.get.return_value = CHROMIUM_POLICY
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase6, issue_tracker)
    self.assertCountEqual(
        ['ClusterFuzz', 'Reproducible', 'Pri-1', 'Stability-Crash', 'Type-Bug'],
        issue_tracker._itm.last_issue.labels)

  def test_testcase_save_exception(self):
    """Tests issue filing when issue.save exception"""
    self.mock.get.return_value = CHROMIUM_POLICY_FALLBACK
    original_save = monorail.issue.Issue.save
    helpers.patch(
        self,
        ['clusterfuzz._internal.issue_management.monorail.issue.Issue.save'])

    def my_save(*args, **kwargs):
      if getattr(my_save, 'raise_exception', True):
        setattr(my_save, 'raise_exception', False)
        raise RuntimeError('Boom!')
      return original_save(*args, **kwargs)

    self.mock.save.side_effect = my_save

    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    _, exception = issue_filer.file_issue(self.testcase5, issue_tracker)
    self.assertIsInstance(exception, RuntimeError)

    self.assertCountEqual(['fallback>component', '-component1', '-component2'],
                          issue_tracker._itm.last_issue.components)
    self.assertIn(
        '**NOTE**: This bug was filed into this component due to permission or '
        'configuration issues with the specified component(s) component1 component2',
        issue_tracker._itm.last_issue.body)

    # call without fallback_component in policy
    # Expected result: no issue is added to itm
    setattr(my_save, 'raise_exception', True)
    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    self.mock.get.return_value = CHROMIUM_POLICY
    with self.assertRaises(Exception):
      issue_filer.file_issue(self.testcase1, issue_tracker)

    self.assertIsNone(issue_tracker._itm.last_issue)

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

    for security_severity, value in security_severity_string_map.items():
      issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

      self.testcase1.security_flag = True
      self.testcase1.security_severity = security_severity
      self.testcase1.put()

      issue_filer.file_issue(self.testcase1, issue_tracker)
      self.assertIn(value, issue_tracker._itm.last_issue.labels)
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
    for entry in issue_filer.MEMORY_TOOLS_LABELS:
      issue_tracker = monorail.IssueTracker(IssueTrackerManager(project_name))

      self.testcase1.crash_stacktrace = f'\n\n{entry["token"]}\n'
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
    self.assertCountEqual(['Unreproducible>Component'],
                          issue_tracker._itm.last_issue.components)

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

  def test_footer_formatting(self):
    """Test footer message with formatting."""
    policy = issue_tracker_policy.IssueTrackerPolicy({
        'status': {
            'assigned': 'Assigned',
            'duplicate': 'Duplicate',
            'verified': 'Verified',
            'new': 'Untriaged',
            'wontfix': 'WontFix',
            'fixed': 'Fixed'
        },
        'all': {
            'status': 'new',
            'issue_body_footer': 'Target: %FUZZ_TARGET%, Project: %PROJECT%'
        },
        'non_security': {},
        'labels': {},
        'security': {},
        'existing': {},
    })
    self.mock.get.return_value = policy

    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    self.testcase1.project_name = 'proj'
    self.testcase1.fuzzer_name = 'libFuzzer'
    self.testcase1.overridden_fuzzer_name = 'libFuzzer_proj_target'

    data_types.FuzzTarget(
        id='libFuzzer_proj_target',
        project='proj',
        engine='libFuzzer',
        binary='target').put()

    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Target: target, Project: proj',
                  issue_tracker._itm.last_issue.body)

  def test_crash_type_labels(self):
    """Test crash type labels."""
    policy = issue_tracker_policy.IssueTrackerPolicy({
        'status': {
            'assigned': 'Assigned',
            'duplicate': 'Duplicate',
            'verified': 'Verified',
            'new': 'Untriaged',
            'wontfix': 'WontFix',
            'fixed': 'Fixed'
        },
        'all': {
            'status': 'new',
        },
        'non_security': {},
        'labels': {
            'crash_types': {
                'heap-use-after-free': 'Memory corruption',
                'stack-overflow': 'Resource Exhaustion',
            }
        },
        'security': {},
        'existing': {},
    })
    self.mock.get.return_value = policy

    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase1, issue_tracker)
    self.assertIn('Memory corruption', issue_tracker._itm.last_issue.labels)
    self.assertNotIn('Resource Exhaustion',
                     issue_tracker._itm.last_issue.labels)

  def test_additional_crash_categories(self):
    """Test filing of crash_categories."""
    policy = issue_tracker_policy.IssueTrackerPolicy({
        'status': {
            'assigned': 'Assigned',
            'duplicate': 'Duplicate',
            'verified': 'Verified',
            'new': 'Untriaged',
            'wontfix': 'WontFix',
            'fixed': 'Fixed'
        },
        'all': {
            'status': 'new',
        },
        'non_security': {},
        'labels': {
            'crash_categories': {
                'fuzzer-exit': 'Fuzzer-exit',
            }
        },
        'security': {},
        'existing': {},
    })
    self.mock.get.return_value = policy

    issue_tracker = monorail.IssueTracker(IssueTrackerManager('chromium'))
    issue_filer.file_issue(self.testcase8, issue_tracker)
    self.assertIn('Fuzzer-exit', issue_tracker._itm.last_issue.labels)
    self.assertNotIn('Resource Exhaustion',
                     issue_tracker._itm.last_issue.labels)


class MemoryToolLabelsTest(unittest.TestCase):
  """Memory tool labels tests."""
  DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'issue_filer_data')

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(
        os.path.join(self.DATA_DIRECTORY, name), encoding='utf-8') as handle:
      return handle.read()

  def test_memory_tools_labels_asan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-AddressSanitizer']
    data = self._read_test_data('memory_tools_asan.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_afl(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-AddressSanitizer', 'AFL']
    data = self._read_test_data('memory_tools_asan_afl.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_libfuzzer(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-AddressSanitizer', 'LibFuzzer']
    data = self._read_test_data('memory_tools_asan_libfuzzer.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_asan_lsan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-AddressSanitizer', 'Memory-LeakSanitizer']
    data = self._read_test_data('memory_tools_asan_lsan.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_msan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-MemorySanitizer']
    data = self._read_test_data('memory_tools_msan.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_msan_libfuzzer(self):
    """Run memory tools detection with test data."""
    expected_labels = ['Memory-MemorySanitizer', 'LibFuzzer']
    data = self._read_test_data('memory_tools_msan_libfuzzer.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_labels_tsan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['ThreadSanitizer']
    data = self._read_test_data('memory_tools_tsan.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)

  def test_memory_tools_ubsan(self):
    """Run memory tools detection with test data."""
    expected_labels = ['UndefinedBehaviorSanitizer']
    data = self._read_test_data('memory_tools_ubsan.txt')
    actual_labels = issue_filer.get_memory_tool_labels(data)

    self.assertEqual(actual_labels, expected_labels)


@test_utils.with_cloud_emulators('datastore')
class UpdateImpactTest(unittest.TestCase):
  """Update impact tests."""

  def _make_mock_issue(self):
    mock_issue = mock.Mock(autospec=MonorailIssue)
    mock_issue.labels = LabelStore()

    return mock_issue

  def setUp(self):
    helpers.patch_environ(self)
    self.testcase = data_types.Testcase()
    self.testcase.one_time_crasher_flag = False
    self.testcase.crash_state = 'fake_crash'

  def test_update_impact_stable_from_regression(self):
    """Tests updating impact to Stable from the regression range."""
    self.testcase.regression = '0:1000'
    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Extended'], mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_update_impact_extended_stable(self):
    """Tests updating impact to Extended Stable."""
    self.testcase.is_impact_set_flag = True
    self.testcase.impact_extended_stable_version = '99.1024.11.42'

    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Extended', 'FoundIn-99'],
                          mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_update_impact_stable(self):
    """Tests updating impact to Stable."""
    self.testcase.is_impact_set_flag = True
    self.testcase.impact_stable_version = '99.1024.11.42'

    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Stable', 'FoundIn-99'],
                          mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_update_impact_beta(self):
    """Tests updating impact to Beta."""
    self.testcase.is_impact_set_flag = True
    self.testcase.impact_beta_version = '100.1044.44.44'

    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Beta', 'FoundIn-100'],
                          mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_update_impact_head(self):
    """Tests updating impact to Head."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Head'], mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_no_impact_for_unreproducible_testcase(self):
    """Tests no impact for unreproducible testcase on trunk and which also
    does not crash on stable and beta."""
    self.testcase.is_impact_set_flag = True
    self.testcase.crash_state = ''

    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual([], mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_no_impact_if_not_set(self):
    """Tests no impact if the impact flag is not set."""
    mock_issue = self._make_mock_issue()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual([], mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_replace_impact(self):
    """Tests replacing impact."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()
    mock_issue.labels.add('Security_Impact-Beta')
    mock_issue.labels.reset_tracking()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(['Security_Impact-Head'], mock_issue.labels.added)
    self.assertCountEqual(['Security_Impact-Beta'], mock_issue.labels.removed)

  def test_replace_same_impact(self):
    """Tests replacing same impact."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()
    mock_issue.labels.add('Security_Impact-Head')
    mock_issue.labels.reset_tracking()

    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual([], mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)

  def test_component_add_label(self):
    """Test that we set labels for component builds."""
    self.testcase.job_type = 'job'
    self.testcase.impact_extended_stable_version = '1.2.3.4'
    self.testcase.impact_stable_version = '2.3.4.5'
    self.testcase.impact_beta_version = '3.4.5.6'
    self.testcase.put()

    data_types.Job(
        name='job',
        environment_string=(
            'RELEASE_BUILD_BUCKET_PATH = '
            'https://example.com/blah-v8-component-([0-9]+).zip\n')).put()

    self.testcase.is_impact_set_flag = True
    mock_issue = self._make_mock_issue()
    issue_filer.update_issue_impact_labels(self.testcase, mock_issue,
                                           CHROMIUM_POLICY)
    self.assertCountEqual(
        ['Security_Impact-Extended', 'FoundIn-1', 'FoundIn-2', 'FoundIn-3'],
        mock_issue.labels.added)
    self.assertCountEqual([], mock_issue.labels.removed)


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class NotifyIssueUpdateTests(unittest.TestCase):
  """notify_issue_update tests."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
    ])

    self.topic = 'projects/project/topics/issue-updates'
    self.subscription = 'projects/project/subscriptions/issue-updates'

    self.mock.ProjectConfig.return_value = mock_config.MockConfig({
        'issue_updates': {
            'pubsub_topic': self.topic,
        },
    })

    self.pubsub_client = pubsub.PubSubClient()
    self.pubsub_client.create_topic(self.topic)
    self.pubsub_client.create_subscription(self.subscription, self.topic)

    self.testcase = data_types.Testcase(
        crash_address='0xffff',
        security_flag=True,
        crash_type='CRASH TYPE',
        crash_state='CRASH STATE',
        bug_information='123')
    self.testcase.put()

  def test_basic(self):
    """Basic test."""
    issue_filer.notify_issue_update(self.testcase, 'new')
    messages = self.pubsub_client.pull_from_subscription(
        self.subscription, max_messages=16)
    self.assertEqual(1, len(messages))
    self.assertDictEqual({
        'crash_address': '0xffff',
        'crash_state': 'CRASH STATE',
        'crash_type': 'CRASH TYPE',
        'issue_id': '123',
        'security': 'true',
        'status': 'new',
        'testcase_id': '1'
    }, messages[0].attributes)

  def test_no_topic(self):
    """Test when no topic is specified."""
    self.mock.ProjectConfig.return_value = mock_config.MockConfig({})
    issue_filer.notify_issue_update(self.testcase, 'new')
    messages = self.pubsub_client.pull_from_subscription(
        self.subscription, max_messages=16)
    self.assertEqual(0, len(messages))

  def test_no_issue(self):
    """Test no issue id."""
    self.testcase.bug_information = None
    issue_filer.notify_issue_update(self.testcase, 'new')
    messages = self.pubsub_client.pull_from_subscription(
        self.subscription, max_messages=16)
    self.assertEqual(1, len(messages))
    self.assertDictEqual({
        'crash_address': '0xffff',
        'crash_state': 'CRASH STATE',
        'crash_type': 'CRASH TYPE',
        'issue_id': '',
        'security': 'true',
        'status': 'new',
        'testcase_id': '1'
    }, messages[0].attributes)
