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
"""Tests for cleanup task."""
# pylint: disable=protected-access

import datetime
import unittest

import six

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import appengine_test_utils
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import cleanup
from libs.issue_management import issue_tracker_policy

ISSUE_IGNORE_LABEL = 'ClusterFuzz-Ignore'
ISSUE_INVALID_FUZZER_LABEL = 'ClusterFuzz-Invalid-Fuzzer'
ISSUE_MISTRIAGED_LABEL = 'ClusterFuzz-Wrong'
ISSUE_NEEDS_FEEDBACK_LABEL = 'Needs-Feedback'
ISSUE_VERIFIED_LABEL = 'ClusterFuzz-Verified'
ISSUE_FUZZ_BLOCKER_LABEL = 'Fuzz-Blocker'


@test_utils.with_cloud_emulators('datastore')
class GetPredatorResultItemTest(unittest.TestCase):
  """Tests for the get_predator_result_item helper function."""

  def test_with_components(self):
    """Ensure that we return the components for test cases which have them."""
    result_with_component = {'result': {'suspected_components': ['A', 'B>C']}}

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('predator_result', result_with_component)

    actual = cleanup._get_predator_result_item(testcase, 'suspected_components')
    self.assertListEqual(actual, ['A', 'B>C'])

  def test_no_components(self):
    """Ensure that we handle cases with a result, but no components field."""
    result_no_component = {'result': {}}

    testcase = test_utils.create_generic_testcase()
    testcase.set_metadata('predator_result', result_no_component)

    actual = cleanup._get_predator_result_item(testcase, 'suspected_components')
    self.assertIsNone(actual)

  def test_no_result(self):
    """Ensure that we handle cases without a predator result."""
    testcase = test_utils.create_generic_testcase()
    testcase.delete_metadata('predator_result')

    actual = cleanup._get_predator_result_item(
        testcase, 'suspected_components', default=[])
    self.assertListEqual(actual, [])


@test_utils.with_cloud_emulators('datastore')
class CleanupTest(unittest.TestCase):
  """Tests for various cleanup functions."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
        'handlers.cron.cleanup.get_crash_occurrence_platforms',
    ])
    self.mock.utcnow.return_value = test_utils.CURRENT_TIME
    self.issue = appengine_test_utils.create_generic_issue()
    self.policy = issue_tracker_policy.get('test-project')

  def test_mark_duplicate_testcase_as_closed_with_no_issue_1(self):
    """Ensure that a regular bug older than 7 days does not get closed."""
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.DUPLICATE_TESTCASE_NO_BUG_DEADLINE + 1)
    testcase.status = 'Processed'
    testcase.put()
    cleanup.mark_duplicate_testcase_as_closed_with_no_issue(testcase=testcase)
    self.assertTrue(testcase.open)

  def test_mark_duplicate_testcase_as_closed_with_no_issue_2(self):
    """Ensure that a duplicate bug older than 7 days, with an associated
    issue does not get closed."""
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.DUPLICATE_TESTCASE_NO_BUG_DEADLINE + 1)
    testcase.bug_information = str(self.issue.id)
    testcase.status = 'Duplicate'
    testcase.put()
    cleanup.mark_duplicate_testcase_as_closed_with_no_issue(testcase=testcase)
    self.assertTrue(testcase.open)

  def test_mark_duplicate_testcase_as_closed_with_no_issue_3(self):
    """Ensure that a duplicate bug older than 7 days, with no associated
    issue does get closed."""
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.DUPLICATE_TESTCASE_NO_BUG_DEADLINE + 1)
    testcase.bug_information = ''
    testcase.status = 'Duplicate'
    testcase.put()
    cleanup.mark_duplicate_testcase_as_closed_with_no_issue(testcase=testcase)
    self.assertFalse(testcase.open)

  def test_mark_duplicate_testcase_as_closed_with_no_issue_4(self):
    """Ensure that a duplicate bug 7 days old does not get closed."""
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.DUPLICATE_TESTCASE_NO_BUG_DEADLINE)
    testcase.bug_information = ''
    testcase.status = 'Duplicate'
    testcase.put()
    cleanup.mark_duplicate_testcase_as_closed_with_no_issue(testcase=testcase)
    self.assertTrue(testcase.open)

  def test_delete_unreproducible_testcase_with_no_issue_1(self):
    """Ensure that a reproducible bug with no crash in last 7 days, and with an
    associated issue does not get deleted."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.delete_unreproducible_testcase_with_no_issue(testcase=testcase)
    self.assertTrue(test_utils.entity_exists(testcase))

  def test_delete_unreproducible_testcase_with_no_issue_2(self):
    """Ensure that an unreproducible bug with no crash in last 7 days, with an
    associated issue does not get deleted."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.delete_unreproducible_testcase_with_no_issue(testcase=testcase)
    self.assertTrue(test_utils.entity_exists(testcase))

  def test_delete_unreproducible_testcase_with_no_issue_3(self):
    """Ensure that an unreproducible bug with no crash in last 7 days, and with
    no associated issue does get deleted."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = ''
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.delete_unreproducible_testcase_with_no_issue(testcase=testcase)
    self.assertFalse(test_utils.entity_exists(testcase))

  def test_delete_unreproducible_testcase_with_no_issue_4(self):
    """Ensure that an unreproducible bug with crash in last 7 days does not get
    deleted."""
    self.mock.get_crash_occurrence_platforms.return_value = ['Linux']
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.bug_information = ''
    testcase.put()
    cleanup.delete_unreproducible_testcase_with_no_issue(testcase=testcase)
    self.assertTrue(test_utils.entity_exists(testcase))

  def test_delete_unreproducible_testcase_with_no_issue_5(self):
    """Ensure that an unreproducible bug created in last 7 days and with crash
    seen in last 7 days does not get deleted."""
    self.mock.get_crash_occurrence_platforms.return_value = ['Linux']
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE - 1)
    testcase.one_time_crasher_flag = True
    testcase.bug_information = ''
    testcase.put()
    cleanup.delete_unreproducible_testcase_with_no_issue(testcase=testcase)
    self.assertTrue(test_utils.entity_exists(testcase))

  def test_mark_issue_as_closed_if_testcase_is_fixed_1(self):
    """Ensure that we don't close issue if associated testcase is open and
    reproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.open = True
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_2(self):
    """Ensure that we don't close issue if associated testcase is open and
    unreproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.open = True
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_3(self):
    """Ensure that we close issue if associated testcase is unreproducible, but
    is explicitly marked as closed."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.open = False
    testcase.fixed = 'Yes'
    testcase.put()
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual(self.issue.status, 'Verified')
    self.assertIn('ClusterFuzz testcase 1 is verified as fixed.',
                  self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_4(self):
    """Ensure that we close issue if associated testcase is closed and
    reproducible, and the similar open testcase is unreproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.one_time_crasher_flag = True
    similar_testcase.put()

    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual(self.issue.status, 'Verified')
    self.assertIn(
        'ClusterFuzz testcase 1 is verified as fixed in '
        'https://test-clusterfuzz.appspot.com/revisions'
        '?job=test_content_shell_drt&range=1:2',
        self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_5(self):
    """Ensure that we don't close issue if associated testcase is closed and
    reproducible, but there is a similar testcase is opened."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.put()

    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_6(self):
    """Ensure that we close issue if all associated testcases are closed and
    reproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.open = False
    similar_testcase.put()

    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual(self.issue.status, 'Verified')
    self.assertIn(
        'ClusterFuzz testcase 1 is verified as fixed in '
        'https://test-clusterfuzz.appspot.com/revisions'
        '?job=test_content_shell_drt&range=1:2',
        self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_7(self):
    """Ensure that we close issue if issue is marked fixed and all associated
    testcases are closed and reproducible."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.open = False
    similar_testcase.put()

    self.issue._monorail_issue.open = False
    self.issue.status = 'Fixed'

    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual(self.issue.status, 'Verified')
    self.assertIn(
        'ClusterFuzz testcase 1 is verified as fixed in '
        'https://test-clusterfuzz.appspot.com/revisions'
        '?job=test_content_shell_drt&range=1:2',
        self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_8(self):
    """Ensure that we don't close issue when we already did the issue
    verification once."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    self.issue.status = 'Assigned'
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_VERIFIED_LABEL])
    ]
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_9(self):
    """Ensure that we don't close issue if a developer has labeled the last
    verification as incorrect."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    self.issue.status = 'Assigned'
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_MISTRIAGED_LABEL])
    ]
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_10(self):
    """Ensure that we don't close issue when this is unreproducible upload."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.status = 'Unreproducible (trunk)'
    testcase.fixed = ''
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotEqual(self.issue.status, 'Verified')
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_mark_issue_as_closed_if_testcase_is_fixed_11(self):
    """Ensure that we mark issue as verified, but don't close it if job
    definition specifies to skip it."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.fixed = '1:2'
    testcase.open = False
    testcase.one_time_crasher_flag = False
    testcase.put()

    data_types.Job(
        name=testcase.job_type,
        platform='LINUX',
        environment_string=('SKIP_AUTO_CLOSE_ISSUE = True\n')).put()

    cleanup.mark_issue_as_closed_if_testcase_is_fixed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertIn(
        'ClusterFuzz testcase 1 is verified as fixed in '
        'https://test-clusterfuzz.appspot.com/revisions'
        '?job=test_content_shell_drt&range=1:2',
        self.issue._monorail_issue.comment)
    self.assertEqual(self.issue.status, 'Assigned')

  def test_mark_testcase_as_closed_if_issue_is_closed_1(self):
    """Test that we don't do anything if testcase is already closed."""
    testcase = test_utils.create_generic_testcase()
    testcase.open = False
    testcase.put()
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertFalse(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_2(self):
    """Test that we don't do anything if we are unable to get issue object from
    issue tracker."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=None)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_3(self):
    """Test that we don't do anything if there is no associated issue i.e.
    bug_information is not set."""
    testcase = test_utils.create_generic_testcase()
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_4(self):
    """Test that we don't do anything if issue is still open."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = True
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_5(self):
    """Test that we don't do anything if there is a ignore label on issue."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE + 1))
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_IGNORE_LABEL])
    ]
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_6(self):
    """Test that we don't close testcase if issue is closed <= 2 weeks and
    does not have ignore label."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE))
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_issue_is_closed_7(self):
    """Test that we close testcase if issue is closed longer than 2 weeks and
    does not have ignore label."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.CLOSE_TESTCASE_WITH_CLOSED_BUG_DEADLINE + 1))
    cleanup.mark_testcase_as_closed_if_issue_is_closed(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertFalse(testcase.open)

  def test_mark_testcase_as_closed_if_job_is_invalid_1(self):
    """Test that we don't close testcase if we have a valid job type."""
    testcase = test_utils.create_generic_testcase()

    jobs = [testcase.job_type]
    cleanup.mark_testcase_as_closed_if_job_is_invalid(
        testcase=testcase, jobs=jobs)
    self.assertTrue(testcase.open)

  def test_mark_testcase_as_closed_if_job_is_invalid_2(self):
    """Test that we close testcase if we don't have a job type."""
    testcase = test_utils.create_generic_testcase()

    jobs = []
    cleanup.mark_testcase_as_closed_if_job_is_invalid(
        testcase=testcase, jobs=jobs)
    self.assertFalse(testcase.open)

  def test_mark_unreproducible_testcase_as_fixed_if_issue_is_closed_1(self):
    """Ensure that a reproducible testcase with no associated issue is not
    marked as Fixed."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = ''
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_unreproducible_testcase_as_fixed_if_issue_is_closed(
        testcase=testcase, issue=None)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_as_fixed_if_issue_is_closed_2(self):
    """Ensure that a reproducible testcase with associated issue in open state
    is not marked as Fixed."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_unreproducible_testcase_as_fixed_if_issue_is_closed(
        testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_as_fixed_if_issue_is_closed_3(self):
    """Ensure that a reproducible testcase with associated issue in closed state
    is not marked as Fixed."""
    self.issue._monorail_issue.open = False
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_unreproducible_testcase_as_fixed_if_issue_is_closed(
        testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_as_fixed_if_issue_is_closed_4(self):
    """Ensure that an unreproducible testcase with associated issue in open
    state is marked as Fixed."""
    self.issue._monorail_issue.open = True
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_as_fixed_if_issue_is_closed(
        testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_as_fixed_if_issue_is_closed_5(self):
    """Ensure that an unreproducible testcase with associated issue in closed
    state is marked as Fixed."""
    self.issue._monorail_issue.open = False
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_as_fixed_if_issue_is_closed(
        testcase=testcase, issue=self.issue)
    self.assertFalse(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_1(
      self):
    """Ensure that a reproducible testcase with no associated issue is not
    closed."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = ''
    testcase.one_time_crasher_flag = False
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=None)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_2(
      self):
    """Ensure that an unreproducible testcase with no associated issue is not
    closed."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = ''
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=None)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_3(
      self):
    """Ensure that an unreproducible testcase with a closed issue is not
    closed."""
    self.issue._monorail_issue.open = False
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_4(
      self):
    """Ensure that an unreproducible testcase with an open issue and with crash
    still seen in crash stats is not closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = ['Linux']
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_5(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, but with other open reproducible testcase is not
    closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_6(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, but with mistriaged issue label is not closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_MISTRIAGED_LABEL])
    ]
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_7(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, and status as Unreproducible does not lead to closing
    of issue."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.status = 'Unreproducible'
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_8(
      self):
    """Ensure that an unreproducible testcase with an open issue, created within
    the deadline and crash seen in crash stats is not not closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = ['Linux']
    testcase = test_utils.create_generic_testcase(
        created_days_ago=data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE -
        1)
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_9(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, is closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertFalse(testcase.open)
    self.assertEqual('WontFix', self.issue.status)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_10(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, but with an uploader email is not closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.uploader_email = 'abc@example.com'
    testcase.put()
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_11(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats, but reproduced yesterday as as part of progression task
    is not closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    testcase.set_metadata('last_tested_crash_time', test_utils.CURRENT_TIME)
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertTrue(testcase.open)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_unreproducible_testcase_and_issue_as_closed_after_deadline_12(
      self):
    """Ensure that an unreproducible testcase with an open issue, with crash not
    seen in crash stats and progression task is closed."""
    self.issue = appengine_test_utils.create_generic_issue()
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.one_time_crasher_flag = True
    testcase.put()
    testcase.set_metadata(
        'last_tested_crash_time',
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE + 1))
    cleanup.mark_unreproducible_testcase_and_issue_as_closed_after_deadline(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertFalse(testcase.open)
    self.assertEqual('WontFix', self.issue.status)

  def test_notify_closed_issue_if_testcase_is_open_1(self):
    """Test that we don't do anything if testcase is already closed."""
    testcase = test_utils.create_generic_testcase()
    testcase.open = False
    testcase.put()
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_2(self):
    """Test that we don't do anything if testcase has status unreproducible
    (upload didn't reproduce)."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.status = 'Unreproducible'
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE + 1))
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_3(self):
    """Test that we don't do anything if we are unable to get issue object from
    issue tracker."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=None)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_4(self):
    """Test that we don't do anything if there is no associated issue i.e.
    bug_information is not set."""
    testcase = test_utils.create_generic_testcase()
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_5(self):
    """Test that we don't do anything if issue is still open."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = True
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_6(self):
    """Test that we don't do anything if we have not exceeded the notification
    deadline."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE))
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_7(self):
    """Test that we don't do anything if there is an ignore label already on
    the issue."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE + 1))
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_IGNORE_LABEL])
    ]
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_8(self):
    """Test that we don't do anything if there is an needs feedback label
    already on the issue."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE + 1))
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_NEEDS_FEEDBACK_LABEL])
    ]
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertNotIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_notify_closed_issue_if_testcase_is_open_9(self):
    """Test that we add notification if we are past the notification deadline
    and we have not added a needs feedback already."""
    testcase = test_utils.create_generic_testcase()
    testcase.bug_information = str(self.issue.id)
    testcase.put()
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME - datetime.timedelta(
            days=data_types.NOTIFY_CLOSED_BUG_WITH_OPEN_TESTCASE_DEADLINE + 1))
    cleanup.notify_closed_issue_if_testcase_is_open(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertIn(ISSUE_NEEDS_FEEDBACK_LABEL, self.issue.labels)

  def test_mark_na_testcase_issues_as_wontfix(self):
    """Test that issue for fixed == 'NA' testcases are closed."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.status = 'Processed'
    testcase.open = False
    testcase.fixed = 'NA'
    testcase.bug_information = str(self.issue.id)
    testcase.put()

    cleanup.mark_na_testcase_issues_as_wontfix(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertIn(
        'ClusterFuzz testcase 1 is closed as invalid, so closing issue.',
        self.issue._monorail_issue.comment)
    self.assertEqual('WontFix', self.issue.status)

  def test_mark_na_testcase_issues_as_wontfix_testcase_open(self):
    """Test that valid open testcases don't get their issues closed."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.status = 'Processed'
    testcase.bug_information = str(self.issue.id)
    testcase.put()

    cleanup.mark_na_testcase_issues_as_wontfix(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_na_testcase_issues_as_wontfix_still_occurring(self):
    """Test that issue for fixed == 'NA' testcases are not closed if the crash
    is still occurring."""
    self.mock.get_crash_occurrence_platforms.return_value = ['Linux']
    testcase = test_utils.create_generic_testcase()
    testcase.status = 'Processed'
    testcase.open = False
    testcase.fixed = 'NA'
    testcase.bug_information = str(self.issue.id)
    testcase.put()

    cleanup.mark_na_testcase_issues_as_wontfix(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_na_testcase_issues_as_wontfix_similar_testcase(self):
    """Test that issue for fixed == 'NA' testcases are not closed if there is a
    similar testcase attached to the same issue."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    testcase = test_utils.create_generic_testcase()
    testcase.status = 'Processed'
    testcase.open = False
    testcase.fixed = 'NA'
    testcase.bug_information = str(self.issue.id)
    testcase.put()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.put()

    cleanup.mark_na_testcase_issues_as_wontfix(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual('Assigned', self.issue.status)

  def test_mark_na_testcase_issues_as_wontfix_mistriaged(self):
    """Test that issue for fixed == 'NA' testcases are not closed if the issue
    was marked as being mistriaged."""
    self.mock.get_crash_occurrence_platforms.return_value = []
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_MISTRIAGED_LABEL])
    ]
    testcase = test_utils.create_generic_testcase()
    testcase.status = 'Processed'
    testcase.open = False
    testcase.fixed = 'NA'
    testcase.bug_information = str(self.issue.id)
    testcase.put()

    cleanup.mark_na_testcase_issues_as_wontfix(
        policy=self.policy, testcase=testcase, issue=self.issue)
    self.assertEqual('Assigned', self.issue.status)


@test_utils.with_cloud_emulators('datastore')
class UpdateOsLabelsTest(unittest.TestCase):
  """Test updateOsLabels."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.crash_stats.get',
    ])
    self.policy = issue_tracker_policy.get('test-project')

  def test_no_issue(self):
    """Test no issue."""
    testcase = data_types.Testcase(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        project_name='project')
    testcase.put()
    cleanup.update_os_labels(self.policy, testcase, None)

  def test_labels_added(self):
    """Test os label added from crash stats."""
    testcase = data_types.Testcase(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        project_name='project')
    testcase.put()

    testcase_variant = data_types.TestcaseVariant(
        testcase_id=testcase.key.id(),
        job_type='mac_job',
        is_similar=True,
        platform='mac')
    testcase_variant.put()

    history = data_types.BuildCrashStatsJobHistory(end_time_in_hours=10000)
    history.put()

    rows = [{
        'groups': [{
            'name': 'windows'
        }, {
            'name': 'linux'
        }, {
            'name': 'android:test'
        }, {
            'name': 'android:test2'
        }]
    }]
    self.mock.get.return_value = (1, rows)

    issue = appengine_test_utils.create_generic_issue()
    issue._monorail_issue.labels = []
    cleanup.update_os_labels(self.policy, testcase, issue)
    self.assertEqual({'OS-Windows', 'OS-Linux', 'OS-Mac', 'OS-Android'},
                     set(issue.labels))
    self.mock.get.assert_called_once_with(
        end=10000,
        block='day',
        days=1,
        group_by='platform',
        where_clause=('crash_type = "type" AND crash_state = "state" AND '
                      'security_flag = true AND project = "project"'),
        group_having_clause='',
        sort_by='total_count',
        offset=0,
        limit=1)

  def test_labels_not_added(self):
    """Test os labels not added from crash stats."""
    testcase = data_types.Testcase(
        crash_type='type',
        crash_state='state',
        security_flag=True,
        project_name='project')
    testcase.put()

    history = data_types.BuildCrashStatsJobHistory(end_time_in_hours=10000)
    history.put()

    rows = [{
        'groups': [{
            'name': 'windows'
        }, {
            'name': 'linux'
        }, {
            'name': 'mac'
        }, {
            'name': 'android:test'
        }, {
            'name': 'android:test2'
        }]
    }]
    self.mock.get.return_value = (1, rows)

    issue = appengine_test_utils.create_generic_issue()
    issue._monorail_issue.labels = []
    comment = appengine_test_utils.create_generic_issue_comment(
        labels=['OS-Mac', 'OS-Android'])
    issue._monorail_issue.comments.append(comment)
    issue.labels.add('OS-Windows')

    cleanup.update_os_labels(self.policy, testcase, issue)
    self.assertEqual({'OS-Windows', 'OS-Linux'}, set(issue.labels))


@test_utils.with_cloud_emulators('datastore')
class GetJobsAndPlatformsForProjectTest(unittest.TestCase):
  """Test get_jobs_and_platforms_for_project."""

  def setUp(self):
    data_types.Job(
        name='job1',
        platform='LINUX',
        environment_string=('EXPERIMENTAL = True\nPROJECT_NAME=project1'),
    ).put()
    data_types.Job(
        name='job2',
        platform='MAC',
        environment_string=('CUSTOM_BINARY = True\nPROJECT_NAME=project2'),
    ).put()
    data_types.Job(
        name='job3',
        platform='WINDOWS',
        environment_string=(
            'SYSTEM_BINARY_DIR = C:\\Program Files\\Internet Explorer\\\n'
            'PROJECT_NAME=project3'),
    ).put()
    data_types.Job(
        name='job4',
        platform='ANDROID',
        environment_string=(
            'EXCLUDE_FROM_TOP_CRASHES = True\nPROJECT_NAME=project4'),
    ).put()
    data_types.Job(
        name='job5',
        platform='LINUX',
        environment_string=('PROJECT_NAME=project5')).put()
    data_types.Job(
        name='job6',
        platform='MAC',
        environment_string=('PROJECT_NAME=project6')).put()

  def test(self):
    actual_projects_map = cleanup.get_jobs_and_platforms_for_project()
    expected_projects_map = {
        'project5': cleanup.ProjectMap(set(['job5']), set(['LINUX'])),
        'project6': cleanup.ProjectMap(set(['job6']), set(['MAC']))
    }
    self.assertEqual(actual_projects_map, expected_projects_map)


@test_utils.with_cloud_emulators('datastore')
class GetTopCrashesForAllProjectsAndPlatforms(unittest.TestCase):
  """Test get_top_crashes_for_all_projects_and_platforms."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.crash_stats.get',
        'clusterfuzz._internal.metrics.crash_stats.get_last_successful_hour',
    ])

    self.top_crashes_rows = [
        {
            'crashState': 'state1',
            'crashType': 'type1',
            'isSecurity': True,
            'totalCount': 350
        },
        {
            'crashState': 'state2',
            'crashType': 'type2',
            'isSecurity': False,
            'totalCount': 450
        },
        {
            'crashState': 'state3',
            'crashType': 'type3',
            'isSecurity': False,
            'totalCount': 250
        },
    ]
    self.mock.get.return_value = (1, self.top_crashes_rows)
    self.mock.get_last_successful_hour.return_value = 10000
    data_types.Job(
        name='job',
        platform='LINUX',
        environment_string=('PROJECT_NAME = project')).put()

  def test(self):
    """Test."""
    expected_top_crashes_map = {
        u'project': {
            'LINUX': [{
                'crashState': 'state1',
                'crashType': 'type1',
                'isSecurity': True,
                'totalCount': 350
            }, {
                'crashState': 'state2',
                'crashType': 'type2',
                'isSecurity': False,
                'totalCount': 450
            }]
        }
    }
    actual_top_crashes_map = (
        cleanup.get_top_crashes_for_all_projects_and_platforms())
    self.assertEqual(expected_top_crashes_map, actual_top_crashes_map)
    self.mock.get.assert_called_once_with(
        end=10000,
        block='day',
        days=7,
        group_by='platform',
        where_clause=('crash_type NOT IN UNNEST('
                      '["Out-of-memory", "Stack-overflow", "Timeout"]) AND '
                      'crash_state NOT IN UNNEST(["NULL"]) AND '
                      'job_type IN UNNEST(["job"]) AND '
                      'platform LIKE "linux%" AND '
                      'project = "project"'),
        group_having_clause='',
        sort_by='total_count',
        offset=0,
        limit=5)


@test_utils.with_cloud_emulators('datastore')
class UpdateTopCrashLabelsTest(unittest.TestCase):
  """Test update_fuzz_blocker_label."""

  def setUp(self):
    helpers.patch_environ(self)

    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'clusterfuzz._internal.base.utils.is_chromium',
        'clusterfuzz._internal.chrome.build_info.get_release_milestone',
    ])
    self.mock.get_release_milestone.return_value = 63

    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()
    self.mock.is_chromium.return_value = True
    self.mock.is_oss_fuzz.return_value = False
    self.policy = issue_tracker_policy.get('test-project')

  def test_no_top_crashes(self):
    """Test no label is added if there are no top crashes."""
    top_crashes_by_project_and_platform_map = {u'project': {'LINUX': []}}

    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertNotIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertNotIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                     self.issue.labels)
    self.assertNotIn('M-63', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_top_crashes_no_match(self):
    """Test no label is added if there are no matching top crashes."""
    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': 'state1',
                'crashType': 'type1',
                'isSecurity': True,
                'totalCount': 500
            }]
        }
    }
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertNotIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertNotIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                     self.issue.labels)
    self.assertNotIn('M-63', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_top_crashes_with_testcase_closed(self):
    """Test label is not added if testcase is closed."""
    self.testcase.open = False
    self.testcase.put()

    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 350
            }]
        }
    }
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertNotIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertNotIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                     self.issue.labels)
    self.assertNotIn('M-63', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_top_crashes_match_single_platform(self):
    """Test label is added if there is a matching top crash."""
    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 350
            }]
        }
    }
    self.issue.labels.add('M-62')
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                  self.issue.labels)
    self.assertIn('M-63', self.issue.labels)
    self.assertNotIn('M-62', self.issue.labels)
    self.assertEqual(
        'This crash occurs very frequently on linux platform and is likely '
        'preventing the fuzzer fuzzer1 from making much progress. '
        'Fixing this will allow more bugs to be found.'
        '\n\nMarking this bug as a blocker for next Beta release.'
        '\n\nIf this is incorrect, please add the ClusterFuzz-Wrong label and '
        'remove the ReleaseBlock-Beta label.',
        self.issue._monorail_issue.comment)

  def test_top_crashes_match_single_platform_oss_fuzz(self):
    """Test label is added if there is a matching top crash for external
    project."""
    self.mock.is_oss_fuzz.return_value = True
    self.testcase.set_metadata('fuzzer_binary_name', 'fuzz_target1')
    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 350
            }]
        }
    }
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertNotIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                     self.issue.labels)
    self.assertNotIn('M-63', self.issue.labels)
    self.assertEqual(
        'This crash occurs very frequently on linux platform and is likely '
        'preventing the fuzzer fuzz_target1 from making much progress. '
        'Fixing this will allow more bugs to be found.'
        '\n\nIf this is incorrect, please file a bug on '
        'https://github.com/google/oss-fuzz/issues/new',
        self.issue._monorail_issue.comment)

  def test_top_crashes_match_multiple_platforms(self):
    """Test label is added if there is a matching top crash."""
    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 500
            }],
            'MAC': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 600
            }],
            'WINDOWS': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 700
            }]
        }
    }
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                  self.issue.labels)
    self.assertIn('M-63', self.issue.labels)
    self.assertEqual(
        'This crash occurs very frequently on linux, mac and windows platforms '
        'and is likely preventing the fuzzer fuzzer1 from making much '
        'progress. Fixing this will allow more bugs to be found.'
        '\n\nMarking this bug as a blocker for next Beta release.'
        '\n\nIf this is incorrect, please add the ClusterFuzz-Wrong label and '
        'remove the ReleaseBlock-Beta label.',
        self.issue._monorail_issue.comment)

  def test_top_crashes_match_and_label_removed(self):
    """Test label is not added if it was added before and removed."""
    top_crashes_by_project_and_platform_map = {
        u'project': {
            'LINUX': [{
                'crashState': self.testcase.crash_state,
                'crashType': self.testcase.crash_type,
                'isSecurity': self.testcase.security_flag,
                'totalCount': 500
            }]
        }
    }

    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_FUZZ_BLOCKER_LABEL])
    ]
    cleanup.update_fuzz_blocker_label(self.policy, self.testcase, self.issue,
                                      top_crashes_by_project_and_platform_map)
    self.assertNotIn(ISSUE_FUZZ_BLOCKER_LABEL, self.issue.labels)
    self.assertNotIn(data_types.CHROMIUM_ISSUE_RELEASEBLOCK_BETA_LABEL,
                     self.issue.labels)
    self.assertNotIn('M-63', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)


@test_utils.with_cloud_emulators('datastore')
class UpdateComponentsTest(unittest.TestCase):
  """Tests for update_component_labels."""

  def setUp(self):
    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()

  def test_components_added(self):
    """Ensure that we add components when applicable."""
    self.testcase.set_metadata(
        'predator_result', {'result': {
            'suspected_components': ['A', 'B>C']
        }})

    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertIn('A', self.issue.components)
    self.assertIn('B>C', self.issue.components)
    self.assertIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_components_not_reapplied(self):
    """Ensure that we don't re-add components once applied."""
    self.testcase.set_metadata(
        'predator_result', {'result': {
            'suspected_components': ['A', 'B>C']
        }})

    comment = appengine_test_utils.create_generic_issue_comment(
        labels=['Test-Predator-Auto-Components'])
    self.issue._monorail_issue.comments.append(comment)

    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertNotIn('A', self.issue.components)
    self.assertNotIn('B>C', self.issue.components)
    self.assertNotIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_no_label_added_for_no_components(self):
    """Ensure that we don't add label when there is no component in result."""
    self.testcase.set_metadata('predator_result', {})
    self.issue.components.add('A')
    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertIn('A', self.issue.components)
    self.assertNotIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_no_label_added_for_same_components(self):
    """Ensure that we don't add label when there is no component in result."""
    self.testcase.set_metadata(
        'predator_result', {'result': {
            'suspected_components': ['A', 'B>C']
        }})
    self.issue.components.add('A')
    self.issue.components.add('B>C')
    self.issue.components.add('D')
    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertIn('A', self.issue.components)
    self.assertIn('B>C', self.issue.components)
    self.assertIn('D', self.issue.components)
    self.assertNotIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_no_label_added_for_more_specific_component(self):
    """Ensure that we don't add label when there is a more specific component
    already."""
    self.testcase.set_metadata('predator_result',
                               {'result': {
                                   'suspected_components': ['A']
                               }})
    self.issue.components.add('A>B')
    self.issue.components.add('D')
    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertNotIn('A', self.issue.components)
    self.assertIn('A>B', self.issue.components)
    self.assertIn('D', self.issue.components)
    self.assertNotIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_label_added_for_more_specific_component_and_new_component(self):
    """Ensure that we add label when there is a more specific component
    already, but also a new components."""
    self.testcase.set_metadata('predator_result',
                               {'result': {
                                   'suspected_components': ['A', 'E']
                               }})
    self.issue.components.add('A>B')
    self.issue.components.add('D')
    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertNotIn('A', self.issue.components)
    self.assertIn('A>B', self.issue.components)
    self.assertIn('D', self.issue.components)
    self.assertIn('E', self.issue.components)
    self.assertIn('Test-Predator-Auto-Components', self.issue.labels)

  def test_label_added_for_unrelated_component(self):
    """Ensure that we add label when there is a unrelated component with same
    prefix."""
    self.testcase.set_metadata('predator_result',
                               {'result': {
                                   'suspected_components': ['A']
                               }})
    self.issue.components.add('AA>B')
    self.issue.components.add('D')
    cleanup.update_component_labels(self.testcase, self.issue)
    self.assertIn('A', self.issue.components)
    self.assertIn('AA>B', self.issue.components)
    self.assertIn('D', self.issue.components)
    self.assertIn('Test-Predator-Auto-Components', self.issue.labels)


@test_utils.with_cloud_emulators('datastore')
class UpdateIssueCCsFromOwnersFileTest(unittest.TestCase):
  """Tests for update_issue_ccs_from_owners_file."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
    ])
    helpers.patch_environ(self)

    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()

    # We'll generally want to assume we have an unassigned issue.
    self.issue.assignee = ''
    self.issue._monorail_issue.cc = []
    self.issue.status = 'Untriaged'

    self.testcase.set_metadata('issue_owners',
                               'dev1@example1.com,dev2@example2.com')
    self.mock.is_oss_fuzz.return_value = False
    self.policy = issue_tracker_policy.get('test-project')

  def test_skipped_issue_closed(self):
    """Test that we don't add ccs to closed issues."""
    self.issue.status = 'Fixed'
    self.issue._monorail_issue.open = False
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual('', self.issue._monorail_issue.comment)
    six.assertCountEqual(self, [], self.issue.ccs)
    self.assertNotIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_skipped_issue_updated_once(self):
    """Test that we don't add ccs if we added ccs once already."""
    comment = appengine_test_utils.create_generic_issue_comment(
        labels=['ClusterFuzz-Auto-CC'])
    self.assertEqual('', self.issue._monorail_issue.comment)
    self.issue._monorail_issue.comments.append(comment)
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    six.assertCountEqual(self, [], self.issue.ccs)

  def test_skipped_no_testcase_metadata(self):
    """Test that we don't add ccs if there are no issue_owners key in testcase
    metadata."""
    self.testcase.delete_metadata('issue_owners')
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual('', self.issue._monorail_issue.comment)
    six.assertCountEqual(self, [], self.issue.ccs)
    self.assertNotIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_skipped_empty_testcase_metadata(self):
    """Test that we don't add ccs if owners list is empty in testcase
    metadata."""
    self.testcase.set_metadata('issue_owners', '')
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual('', self.issue._monorail_issue.comment)
    six.assertCountEqual(self, [], self.issue.ccs)
    self.assertNotIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_skipped_ccs_already_added_and_metadata_set(self):
    """Test that we don't add ccs if ccs are added already and metadata has
    has_issue_ccs_from_owners_file attribute."""
    self.testcase.set_metadata('has_issue_ccs_from_owners_file', True)
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual('', self.issue._monorail_issue.comment)
    six.assertCountEqual(self, [], self.issue.ccs)
    self.assertNotIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_skipped_ccs_alread_added_and_metadata_set(self):
    """Test that we don't add ccs if ccs are added already."""
    self.issue.ccs.add('dev1@example1.com')
    self.issue.ccs.add('dev2@example2.com')
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual(
        True, self.testcase.get_metadata('has_issue_ccs_from_owners_file'))
    self.assertEqual('', self.issue._monorail_issue.comment)
    six.assertCountEqual(self, ['dev1@example1.com', 'dev2@example2.com'],
                         sorted(self.issue.ccs))
    self.assertNotIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_add_ccs_with_some_initial_ones(self):
    """Test that we only add new ccs if some are added already."""
    self.issue._monorail_issue.cc = ['dev1@example1.com']
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual(
        'Automatically adding ccs based on OWNERS file / target commit history.'
        '\n\nIf this is incorrect, please add the ClusterFuzz-Wrong label.',
        self.issue._monorail_issue.comment)
    six.assertCountEqual(self, ['dev1@example1.com', 'dev2@example2.com'],
                         sorted(self.issue.ccs))
    self.assertIn('ClusterFuzz-Auto-CC', self.issue.labels)

  def test_add_ccs_without_any_initial_ones(self):
    """Test adding of ccs with none already existing on the issue."""
    self.mock.is_oss_fuzz.return_value = True
    cleanup.update_issue_ccs_from_owners_file(self.policy, self.testcase,
                                              self.issue)
    self.assertEqual(
        'Automatically adding ccs based on OWNERS file / target commit history.'
        '\n\nIf this is incorrect, '
        'please file a bug on https://github.com/google/oss-fuzz/issues/new.',
        self.issue._monorail_issue.comment)
    six.assertCountEqual(self, ['dev1@example1.com', 'dev2@example2.com'],
                         sorted(self.issue.ccs))
    self.assertIn('ClusterFuzz-Auto-CC', self.issue.labels)


@test_utils.with_cloud_emulators('datastore')
class UpdateIssueLabelsForFlakyTestcaseTest(unittest.TestCase):
  """Tests for update_issue_labels_for_flaky_testcase."""

  def setUp(self):
    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()
    self.policy = issue_tracker_policy.get('test-project')

  def test_mark_unreproducible_if_reproducible_change(self):
    """Test that we change label on issue if the testcase is now flaky."""
    self.issue.labels.add('Reproducible')
    self.testcase.one_time_crasher_flag = True
    self.testcase.put()
    cleanup.update_issue_labels_for_flaky_testcase(self.policy, self.testcase,
                                                   self.issue)

    self.assertNotIn('Reproducible', self.issue.labels)
    self.assertIn('Unreproducible', self.issue.labels)
    self.assertEqual(
        'ClusterFuzz testcase 1 appears to be flaky, '
        'updating reproducibility label.', self.issue._monorail_issue.comment)

  def test_skip_if_unreproducible(self):
    """Test that we don't change labels if the testcase is unreproducible and
    issue is already marked unreproducible."""
    self.issue.labels.add('Unreproducible')
    self.testcase.one_time_crasher_flag = True
    self.testcase.put()
    cleanup.update_issue_labels_for_flaky_testcase(self.policy, self.testcase,
                                                   self.issue)

    self.assertNotIn('Reproducible', self.issue.labels)
    self.assertIn('Unreproducible', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_skip_if_reproducible(self):
    """Test that we don't change labels if the testcase is reproducible."""
    self.issue.labels.add('Reproducible')
    self.testcase.one_time_crasher_flag = False
    self.testcase.put()
    cleanup.update_issue_labels_for_flaky_testcase(self.policy, self.testcase,
                                                   self.issue)

    self.assertIn('Reproducible', self.issue.labels)
    self.assertNotIn('Unreproducible', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_skip_if_another_reproducible_testcase(self):
    """Test that we don't change label on issue if another reproducible
    testcase exists."""
    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.open = True
    similar_testcase.put()

    self.issue.labels.add('Reproducible')
    self.testcase.one_time_crasher_flag = True
    cleanup.update_issue_labels_for_flaky_testcase(self.policy, self.testcase,
                                                   self.issue)

    self.assertIn('Reproducible', self.issue.labels)
    self.assertNotIn('Unreproducible', self.issue.labels)
    self.assertEqual('', self.issue._monorail_issue.comment)


@test_utils.with_cloud_emulators('datastore')
class UpdateIssueOwnerAndCCsFromPredatorResultsTest(unittest.TestCase):
  """Tests for update_issue_owner_and_ccs_from_predator_results."""

  def setUp(self):
    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()

    # We'll generally want to assume we have an unassigned issue.
    self.issue.assignee = ''
    self.issue.status = 'Untriaged'
    self.policy = issue_tracker_policy.get('test-project')

    # Set the metadata to a generic result that would lead to an update,
    # assuming no other conditions are violated.
    self.testcase.set_metadata(
        'predator_result', {
            'result': {
                'suspected_cls': [{
                    'author': 'a@example.com',
                    'description': 'blah',
                    'url': 'url'
                },]
            }
        })

  def test_owner_assigned(self):
    """Ensure that we set the owner when appropriate."""
    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, 'a@example.com')
    self.assertEqual(self.issue.status, 'Assigned')
    self.assertIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_single_owner_cced_if_specified(self):
    """Ensure that we cc single authors if assignment is disabled."""
    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue, only_allow_ccs=True)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertIn('a@example.com', self.issue.ccs)
    self.assertIn('Test-Predator-Auto-CC', self.issue.labels)

  def test_closed_not_updated(self):
    """Ensure that we don't set owners for closed issues."""
    self.issue.status = 'Fixed'
    self.issue._monorail_issue.open = False

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Fixed')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_owner_not_reassigned(self):
    """Ensure that we don't overwrite already assigned owners."""
    self.issue.status = 'Assigned'
    self.issue.assignee = 'b@example.com'

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, 'b@example.com')
    self.assertEqual(self.issue.status, 'Assigned')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_skipped_if_already_updated(self):
    """Ensure that we don't try to update the same issue twice."""
    comment = appengine_test_utils.create_generic_issue_comment(
        labels=['Test-Predator-Auto-Owner'])
    self.issue._monorail_issue.comments.append(comment)

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_skipped_if_previously_assigned(self):
    """Ensure that we don't assign to someone who was already the owner."""
    comment = appengine_test_utils.create_generic_issue_comment()
    comment.owner = 'a@example.com'
    self.issue._monorail_issue.comments.append(comment)

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_skipped_if_no_cls(self):
    """Ensure that we do nothing if we have no suspected CLs."""
    self.testcase.set_metadata('predator_result',
                               {'result': {
                                   'suspected_cls': []
                               }})

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)

  def test_add_ccs_if_multiple_cls(self):
    """Ensure that we only cc when we have multiple suspected CLs."""
    self.testcase.set_metadata(
        'predator_result', {
            'result': {
                'suspected_cls': [
                    {
                        'author': 'a@example.com',
                        'description': 'blah',
                        'url': 'url'
                    },
                    {
                        'author': 'b@example.com',
                        'description': 'halb',
                        'url': 'lru'
                    },
                ]
            }
        })

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)
    self.assertIn('Test-Predator-Auto-CC', self.issue.labels)
    self.assertIn('a@example.com', self.issue.ccs)
    self.assertIn('b@example.com', self.issue.ccs)

  def test_skipped_if_previously_cced_and_metadata_set(self):
    """Ensure that we don't re-cc authors who were cced in the past and have
    has_issue_ccs_from_predator_results set in metadata."""
    self.testcase.set_metadata('has_issue_ccs_from_predator_results', True)
    self.testcase.set_metadata(
        'predator_result', {
            'result': {
                'suspected_cls': [
                    {
                        'author': 'a@example.com',
                        'description': 'blah',
                        'url': 'url'
                    },
                    {
                        'author': 'b@example.com',
                        'description': 'halb',
                        'url': 'lru'
                    },
                ]
            }
        })

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue, only_allow_ccs=True)
    self.assertNotIn('a@example.com', self.issue.ccs)
    self.assertNotIn('b@example.com', self.issue.ccs)
    self.assertNotIn('Test-Predator-Auto-CC', self.issue.labels)

  def test_skipped_if_previously_cced_and_metadata_not_set(self):
    """Ensure that we don't re-cc authors who were cced in the past."""
    comment = appengine_test_utils.create_generic_issue_comment()
    comment.cc = ['-a@example.com']
    self.issue._monorail_issue.comments.append(comment)

    self.testcase.set_metadata(
        'predator_result', {
            'result': {
                'suspected_cls': [
                    {
                        'author': 'a@example.com',
                        'description': 'blah',
                        'url': 'url'
                    },
                    {
                        'author': 'b@example.com',
                        'description': 'halb',
                        'url': 'lru'
                    },
                ]
            }
        })

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertNotIn('a@example.com', self.issue.ccs)
    self.assertIn('b@example.com', self.issue.ccs)
    self.assertIn('Test-Predator-Auto-CC', self.issue.labels)

  def test_skipped_if_malformed_cl(self):
    """Ensure that we do nothing if the suspected CL is malformed."""
    self.testcase.set_metadata('predator_result',
                               {'result': {
                                   'suspected_cls': [{
                                       'url': 'url'
                                   },]
                               }})

    cleanup.update_issue_owner_and_ccs_from_predator_results(
        self.policy, self.testcase, self.issue)
    self.assertEqual(self.issue.assignee, '')
    self.assertEqual(self.issue.status, 'Untriaged')
    self.assertNotIn('Test-Predator-Auto-Owner', self.issue.labels)


@test_utils.with_cloud_emulators('datastore')
class NotifyIssueIfTestcaseIsInvalidTest(unittest.TestCase):
  """Tests for notify_issue_if_testcase_is_invalid."""

  def setUp(self):
    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()

    # Assume a test case associated with an assigned issue.
    self.issue.status = 'Assigned'
    self.testcase.bug_information = '123456'
    self.policy = issue_tracker_policy.get('test-project')

  def test_skipped_if_no_issue(self):
    """Ensure that we handle the case where there is no issue."""
    self.testcase.bug_information = None

    # Simply ensure that we don't throw an exception in this case.
    cleanup.notify_issue_if_testcase_is_invalid(self.policy, self.testcase,
                                                None)

  def test_skipped_if_closed_issue(self):
    """Ensure that we ignore issues that are already closed."""
    self.issue.status = 'Fixed'
    self.issue._monorail_issue.open = False
    cleanup.notify_issue_if_testcase_is_invalid(self.policy, self.testcase,
                                                self.issue)
    self.assertEqual(self.issue._monorail_issue.comment, '')

  def test_skipped_if_unmarked_issue(self):
    """Ensure that we ignore issues that have valid fuzzers."""
    cleanup.notify_issue_if_testcase_is_invalid(self.policy, self.testcase,
                                                self.issue)
    self.assertEqual(self.issue._monorail_issue.comment, '')

  def test_notified_if_fuzzer_was_deleted(self):
    """Ensure that we comment on issues that have invalid fuzzers."""
    self.testcase.set_metadata('fuzzer_was_deleted', True)
    cleanup.notify_issue_if_testcase_is_invalid(self.policy, self.testcase,
                                                self.issue)
    self.assertIn('is associated with an obsolete fuzzer',
                  self.issue._monorail_issue.comment)
    self.assertIn(ISSUE_INVALID_FUZZER_LABEL, self.issue.labels)

  def test_not_notified_if_fuzzer_was_deleted_and_notified(self):
    """Ensure that we don't comment again on issues that have invalid fuzzers
    and we have commented once."""
    self.testcase.set_metadata('fuzzer_was_deleted', True)
    self.issue._monorail_issue.comments += [
        appengine_test_utils.create_generic_issue_comment(
            labels=[ISSUE_INVALID_FUZZER_LABEL])
    ]
    cleanup.notify_issue_if_testcase_is_invalid(self.policy, self.testcase,
                                                self.issue)
    self.assertNotIn('is associated with an obsolete fuzzer',
                     self.issue._monorail_issue.comment)


@test_utils.with_cloud_emulators('datastore')
class NotifyUploaderIfTestcaseIsProcessed(unittest.TestCase):
  """Tests for notify_uploader_when_testcase_is_processed."""

  def setUp(self):
    helpers.patch(self, [
        'handlers.cron.cleanup._update_issue_security_severity_and_get_comment',
        'libs.issue_management.issue_filer.update_issue_impact_labels',
        'libs.mail.send',
    ])

    self.issue = appengine_test_utils.create_generic_issue()
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_id = self.testcase.key.id()
    self.uploader_email = 'uploader@email.com'
    self.policy = issue_tracker_policy.get('test-project')

    data_types.Config(url='url', reproduction_help_url='repro_help_url').put()

  def _get_notification(self):
    """Return notification entity for our testcase."""
    return data_types.Notification.query(
        data_types.Notification.testcase_id == self.testcase_id).get()

  def test_no_upload_metadata(self):
    """Ensure that we don't send notification if there is no upload metadata."""
    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.assertEqual(0, self.mock.send.call_count)
    self.assertIsNone(self._get_notification())

  def test_upload_metadata_with_no_uploader_email(self):
    """Ensure that we don't send notification if there is no uploader email."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id, uploader_email=None, bundled=False).put()
    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.assertEqual(0, self.mock.send.call_count)
    self.assertIsNone(self._get_notification())

  def test_upload_metadata_with_multiple_testcases(self):
    """Ensure that we don't send notification if this a bundled metadata archive
    (with multiple testcases)."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False).put()
    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.assertEqual(0, self.mock.send.call_count)
    self.assertIsNone(self._get_notification())

  def test_critical_tasks_not_completed(self):
    """Ensure that we don't send notification if critical tasks not complete."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False).put()
    self.testcase.minimized_keys = None
    self.testcase.regression = None
    self.testcase.put()
    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.assertEqual(0, self.mock.send.call_count)

  def test_pending_testcase(self):
    """Ensure that notification is not sent with a pending testcase."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False).put()
    self.testcase.status = 'Pending'
    self.testcase.one_time_crasher_flag = False
    self.testcase.put()

    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.assertEqual(0, self.mock.send.call_count)

  def test_notification_sent_with_regular_testcase(self):
    """Ensure that notification is sent with a regular testcase."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False).put()
    self.testcase.status = 'Processed'
    self.testcase.minimized_keys = 'some-key'
    self.testcase.regression = '1:2'
    self.testcase.is_impact_set_flag = True
    self.testcase.put()

    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.mock.send.assert_called_once_with(
        'uploader@email.com', 'Your testcase upload 1 analysis is complete.',
        'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1<br><br>'
        'Fuzzer: fuzzer1<br>'
        'Job Type: test_content_shell_drt<br>'
        'Crash Type: fake type<br>'
        'Crash Address: 0xdeadbeef<br>'
        'Crash State:<br>'
        '  ...see report...<br>'
        'Sanitizer: address (ASAN)<br><br>'
        'Regressed: https://test-clusterfuzz.appspot.com/revisions?'
        'job=test_content_shell_drt&range=1:2<br><br>'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1<br><br>'
        'See repro_help_url for instructions to reproduce this bug locally.'
        '<br><br>'
        'If you suspect that the result above is incorrect, '
        'try re-doing that job on the testcase report page.')
    self.assertIsNotNone(self._get_notification())

  def test_notification_sent_with_unreproducible_testcase(self):
    """Ensure that notification is sent with an unreproducible testcase."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False).put()
    self.testcase.status = 'Unreproducible'
    self.testcase.one_time_crasher_flag = False
    self.testcase.put()

    cleanup.notify_uploader_when_testcase_is_processed(
        self.policy, self.testcase, self.issue)

    self.mock.send.assert_called_once_with(
        'uploader@email.com', 'Your testcase upload 1 analysis is complete.',
        'Testcase 1 failed to reproduce the crash. '
        'Please inspect the program output at '
        'https://test-clusterfuzz.appspot.com/testcase?key=1.<br><br>'
        'If you suspect that the result above is incorrect, '
        'try re-doing that job on the testcase report page.')
    self.assertIsNotNone(self._get_notification())

  def test_notification_sent_with_one_issue_update_when_quiet_flag_set(self):
    """Ensure that notification is sent and issue is updated only once when
    quiet flag is set."""
    data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase_id,
        uploader_email=self.uploader_email,
        bundled=False,
        bug_information=str(self.issue.id),
        quiet_flag=True).put()
    self.testcase.status = 'Processed'
    self.testcase.minimized_keys = 'some-key'
    self.testcase.regression = '1:2'
    self.testcase.is_impact_set_flag = True
    self.testcase.put()

    for _ in range(3):
      cleanup.notify_uploader_when_testcase_is_processed(
          self.policy, self.testcase, self.issue)

    self.assertEqual(
        1, self.mock._update_issue_security_severity_and_get_comment.call_count)
    self.assertIsNotNone(self._get_notification())


@test_utils.with_cloud_emulators('datastore')
class CleanupUnusedFuzzTargetsTest(unittest.TestCase):
  """Tests for cleanup_unused_fuzz_targets_and_jobs."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = datetime.datetime(2018, 1, 31)

  def test_cleanup_unused_fuzz_targets_and_jobs(self):
    """Test cleaning up fuzz targets."""
    # FuzzTarget should be removed. All FuzzTargetJobs are older than the
    # threshold.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='binary1', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_binary1',
        job='job1',
        last_run=datetime.datetime(2018, 1, 15)).put()

    # FuzzTarget should be removed. No FuzzTargetJobs.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='binary2', project='test-project').put()

    # FuzzTarget should not be removed. Has 1 FuzzTargetJob left after removing
    # old ones.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='binary3', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_binary3',
        job='job1',
        last_run=datetime.datetime(2018, 1, 20)).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_binary3',
        job='job2',
        last_run=datetime.datetime(2018, 1, 15)).put()

    # FuzzTarget should not be removed. All FuzzTargetJob valid.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='binary4', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_binary4',
        job='job1',
        last_run=datetime.datetime(2018, 1, 20)).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_binary4',
        job='job2',
        last_run=datetime.datetime(2018, 1, 20)).put()

    cleanup.cleanup_unused_fuzz_targets_and_jobs()

    six.assertCountEqual(
        self, ['libFuzzer_binary3', 'libFuzzer_binary4'],
        list([t.key.id() for t in data_types.FuzzTarget.query()]))
    six.assertCountEqual(
        self, [
            'libFuzzer_binary3/job1', 'libFuzzer_binary4/job1',
            'libFuzzer_binary4/job2'
        ], list([t.key.id() for t in data_types.FuzzTargetJob.query()]))


@test_utils.with_cloud_emulators('datastore')
class CleanupUnusedHeartbeatsTest(unittest.TestCase):
  """Tests for cleaning up heartbeat entities."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
    ])

    self.mock.utcnow.return_value = datetime.datetime(2018, 1, 31)

  def test_cleanup(self):
    """Test cleanup_unused_heartbeats."""
    data_types.Heartbeat(last_beat_time=datetime.datetime(2018, 1, 14)).put()
    data_types.Heartbeat(last_beat_time=datetime.datetime(2018, 1, 15)).put()
    data_types.Heartbeat(last_beat_time=datetime.datetime(2018, 1, 16)).put()
    data_types.Heartbeat(last_beat_time=datetime.datetime(2018, 1, 17)).put()
    data_types.Heartbeat(last_beat_time=datetime.datetime(2018, 2, 1)).put()
    cleanup.cleanup_unused_heartbeats()

    six.assertCountEqual(self, [
        {
            'task_payload': None,
            'source_version': None,
            'task_end_time': None,
            'last_beat_time': datetime.datetime(2018, 1, 16, 0, 0),
            'bot_name': None,
            'platform_id': None,
            'keywords': [],
        },
        {
            'task_payload': None,
            'source_version': None,
            'task_end_time': None,
            'last_beat_time': datetime.datetime(2018, 1, 17, 0, 0),
            'bot_name': None,
            'platform_id': None,
            'keywords': [],
        },
        {
            'task_payload': None,
            'source_version': None,
            'task_end_time': None,
            'last_beat_time': datetime.datetime(2018, 2, 1, 0, 0),
            'bot_name': None,
            'platform_id': None,
            'keywords': [],
        },
    ], [e.to_dict() for e in data_types.Heartbeat.query()])


class UpdateSeverityLabelsTest(unittest.TestCase):
  """Tests for updating severity labels."""

  def setUp(self):
    self.testcase = data_types.Testcase()
    self.issue = appengine_test_utils.create_generic_issue()
    self.policy = issue_tracker_policy.get('test-project')

  def test_add_missing_severity(self):
    """Test updating missing severity."""
    self.testcase.security_severity = data_types.SecuritySeverity.HIGH
    result = cleanup._update_issue_security_severity_and_get_comment(
        self.policy, self.testcase, self.issue)
    self.assertIn('Security_Severity-High', self.issue.labels)
    self.assertIn('A recommended severity was added to this bug.', result)

  def test_add_same_severity(self):
    """Test correct severity already set."""
    self.testcase.security_severity = data_types.SecuritySeverity.HIGH
    self.issue.labels.add('Security_severity-High')
    result = cleanup._update_issue_security_severity_and_get_comment(
        self.policy, self.testcase, self.issue)
    self.assertIn('Security_Severity-High', self.issue.labels)
    self.assertEqual('', result)

  def test_add_different_severity(self):
    """Test incorrect severity set."""
    self.testcase.security_severity = data_types.SecuritySeverity.HIGH
    self.issue.labels.add('Security_Severity-Medium')
    result = cleanup._update_issue_security_severity_and_get_comment(
        self.policy, self.testcase, self.issue)
    self.assertNotIn('Security_Severity-High', self.issue.labels)
    self.assertIn('Security_Severity-Medium', self.issue.labels)
    self.assertIn('different from what was assigned', result)
