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
# pylint: disable=protected-access
"""Tests for triage task."""

import datetime
import unittest

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import appengine_test_utils
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import triage


@test_utils.with_cloud_emulators('datastore')
class CrashImportantTest(unittest.TestCase):
  """Tests for _is_crash_important."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.crash_stats.get_last_successful_hour',
        'clusterfuzz._internal.metrics.crash_stats.get',
        'clusterfuzz._internal.base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = test_utils.CURRENT_TIME

  def test_is_crash_important_1(self):
    """Ensure that a reproducible testcase is important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = False
    testcase.put()

    self.assertTrue(triage._is_crash_important(testcase))

  def test_is_crash_important_2(self):
    """Ensure that an unreproducible testcase with status Unreproducible is
    not important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.status = 'Unreproducible'
    testcase.put()

    self.assertFalse(triage._is_crash_important(testcase))

  def test_is_crash_important_3(self):
    """Ensure that an unreproducible testcase with status Duplicate is
    not important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.status = 'Duplicate'
    testcase.put()

    self.assertFalse(triage._is_crash_important(testcase))

  def test_is_crash_important_4(self):
    """If the unreproducible testcase has another reproducible testcase in
    group, then crash is not important."""
    testcase_1 = test_utils.create_generic_testcase()
    testcase_1.one_time_crasher_flag = True
    testcase_1.group_id = 1
    testcase_1.put()

    testcase_2 = test_utils.create_generic_testcase()
    testcase_2.one_time_crasher_flag = False
    testcase_2.group_id = 1
    testcase_2.put()

    self.assertFalse(triage._is_crash_important(testcase_1))

  def test_is_crash_important_5(self):
    """If we don't have any crash stats data for this unreproducible testcase,
    then we can't make judgement on crash importance, so we return result as
    False."""
    self.mock.get_last_successful_hour.return_value = None
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage._is_crash_important(testcase))

  def test_is_crash_important_6(self):
    """If this unreproducible testcase is less than the total crash threshold,
    then it is not important."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 1,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 14,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage._is_crash_important(testcase))

  def test_is_crash_important_7(self):
    """If this unreproducible testcase spiked only for a certain interval, then
    it is not important."""
    self.mock.get_last_successful_hour.return_value = 417325
    self.mock.get.return_value = (1, [{
        'totalCount':
            125,
        'groups': [{
            'indices': [{
                'count': 125,
                'hour': 417301,
            }],
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage._is_crash_important(testcase))

  def test_is_crash_important_8(self):
    """If this unreproducible testcase is crashing frequently, then it is an
    important crash."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 10,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 140,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertTrue(triage._is_crash_important(testcase))

  def test_is_crash_important_9(self):
    """If this unreproducible testcase is crashing frequently, but its crash
    type is one of crash type ignores, then it is not an important crash."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 10,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 140,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    for crash_type in ['Out-of-memory', 'Stack-overflow', 'Timeout']:
      testcase.crash_type = crash_type
      self.assertFalse(triage._is_crash_important(testcase))


@test_utils.with_cloud_emulators('datastore')
class CheckAndUpdateSimilarBug(unittest.TestCase):
  """Tests for _check_and_update_similar_bug."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = test_utils.CURRENT_TIME

    self.testcase = test_utils.create_generic_testcase()
    self.issue = appengine_test_utils.create_generic_issue()
    self.issue_tracker = self.issue.issue_tracker

  def test_no_other_testcase(self):
    """Tests result is false when there is no other similar testcase."""
    self.assertEqual(
        False,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_without_bug_information(self):
    """Tests result is false when there is a similar testcase but without an
    associated bug."""
    similar_testcase = test_utils.create_generic_testcase()  # pylint: disable=unused-variable

    self.assertEqual(
        False,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_get_issue_failed(self):
    """Tests result is false when there is a similar testcase with an associated
    bug but we are unable to fetch it via get_issue."""
    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.bug_information = '2'  # Non-existent.
    similar_testcase.put()

    self.assertEqual(
        False,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_is_reproducible_and_open(self):
    """Tests result is true when there is a similar testcase which is
    reproducible, open and has an accessible associated bug."""
    self.issue.save()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.open = True
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_reproducible_and_closed_but_issue_open_1(self):
    """Tests result is true when there is a similar testcase which is
    reproducible and fixed due to flakiness but issue is kept open. Only update
    testcase bug mapping if similar testcase is fixed longer than the grace
    period."""
    self.issue.save()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.open = False
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))
    testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(None, testcase.bug_information)
    self.assertEqual('', self.issue._monorail_issue.comment)

    similar_testcase.set_metadata(
        'closed_time',
        test_utils.CURRENT_TIME -
        datetime.timedelta(hours=data_types.MIN_ELAPSED_TIME_SINCE_FIXED + 1))
    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_reproducible_and_closed_but_issue_open_2(self):
    """Tests result is true when there is a similar testcase which is
    reproducible and fixed due to flakiness but issue is kept open. Don't update
    testcase bug mapping if another reproducible testcase is open and attached
    to this bug."""
    self.issue.save()

    similar_testcase_1 = test_utils.create_generic_testcase()
    similar_testcase_1.one_time_crasher_flag = False
    similar_testcase_1.open = False
    similar_testcase_1.bug_information = str(self.issue.id)
    similar_testcase_1.put()

    similar_testcase_2 = test_utils.create_generic_testcase()
    similar_testcase_2.one_time_crasher_flag = False
    similar_testcase_2.open = True
    similar_testcase_2.bug_information = str(self.issue.id)
    similar_testcase_2.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))
    testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(None, testcase.bug_information)
    self.assertEqual('', self.issue._monorail_issue.comment)

  def test_similar_testcase_unreproducible_but_issue_open(self):
    """Tests result is true when there is a similar testcase which is
    unreproducible but issue is kept open. Update testcase bug mapping always
    since this testcase is reproducible."""
    self.issue.save()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = True
    similar_testcase.open = False
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

  def test_similar_testcase_with_issue_closed_with_ignore_label(self):
    """Tests result is true when there is a similar testcase with closed issue
    blacklisted with ignore label."""
    self.issue.status = 'WontFix'
    self.issue._monorail_issue.open = False
    self.issue.labels.add('ClusterFuzz-Ignore')
    self.issue.save()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.open = False
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

    testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(
        'Skipping filing a bug since similar testcase (2) in issue (1) '
        'is blacklisted with ClusterFuzz-Ignore label.',
        testcase.get_metadata(triage.TRIAGE_MESSAGE_KEY))

  def test_similar_testcase_with_issue_recently_closed(self):
    """Tests result is true when there is a similar testcase with issue closed
    recently."""
    self.issue.status = 'Fixed'
    self.issue._monorail_issue.open = False
    self.issue._monorail_issue.closed = (
        test_utils.CURRENT_TIME -
        datetime.timedelta(hours=data_types.MIN_ELAPSED_TIME_SINCE_FIXED - 1))
    self.issue.save()

    similar_testcase = test_utils.create_generic_testcase()
    similar_testcase.one_time_crasher_flag = False
    similar_testcase.open = False
    similar_testcase.bug_information = str(self.issue.id)
    similar_testcase.put()

    self.assertEqual(
        True,
        triage._check_and_update_similar_bug(self.testcase, self.issue_tracker))

    testcase = data_handler.get_testcase_by_id(self.testcase.key.id())
    self.assertEqual(
        'Delaying filing a bug since similar testcase (2) in issue (1) '
        'was just fixed.', testcase.get_metadata(triage.TRIAGE_MESSAGE_KEY))
