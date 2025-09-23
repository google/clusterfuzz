# Copyright 2025 Google LLC
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
"""Testcase status information retrieval tests."""
# pylint: disable=protected-access

import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import testcase_status_events


class EventsInfoBasicTest(unittest.TestCase):
  """Helper class with basic setup for tests involving retrieving events."""

  def setUp(self):
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_id = self.testcase.key.id()
    self.status_info_instance = testcase_status_events.TestcaseStatusInfo(
        self.testcase_id)
    test_helpers.patch(
        self, ['clusterfuzz._internal.config.local_config.ProjectConfig'])
    self.mock.ProjectConfig.return_value = {'events.storage': 'datastore'}


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseStatusMachineInfoNoEventsTest(EventsInfoBasicTest):
  """Test retrieving testcase status machine information with no events."""

  def test_get_testcase_status_info_no_events(self):
    """Verify that no information besides 'task_name' and 'event_type' are returned."""
    result = self.status_info_instance.get_info()

    expected_task_events = [
        {
            'task_name': 'Analyze'
        },
        {
            'task_name': 'Minimize'
        },
        {
            'task_name': 'Impact'
        },
        {
            'task_name': 'Regression'
        },
        {
            'task_name': 'Progression'
        },
        {
            'task_name': 'Blame'
        },
        {
            'task_name': 'Variant'
        },
    ]

    expected_lifecycle_events = [
        {
            'event_type': 'Testcase Rejection'
        },
        {
            'event_type': 'Testcase Creation'
        },
        {
            'event_type': 'Testcase Fixed'
        },
        {
            'event_type': 'Issue Closing'
        },
        {
            'event_type': 'Issue Filing'
        },
        {
            'event_type': 'Testcase Grouping'
        },
    ]

    self.assertCountEqual(result.keys(),
                          ['task_events_info', 'lifecycle_events_info'])
    self.assertCountEqual(result['task_events_info'], expected_task_events)
    self.assertCountEqual(result['lifecycle_events_info'],
                          expected_lifecycle_events)


class EventsInfoTest(EventsInfoBasicTest):
  """Helper class for tests involving retrieving events information."""

  def setUp(self):
    super().setUp()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='analyze',
        task_stage='stage1',
        task_status='status1',
        task_outcome='outcome1',
        timestamp=datetime.datetime(2023, 1, 1, 10, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='analyze',
        task_stage='stage2',
        task_status='status2',
        task_outcome='outcome2',
        timestamp=datetime.datetime(2023, 1, 1, 11, 3, 11)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='minimize',
        task_stage='stage3',
        task_status='status3',
        task_outcome=None,
        timestamp=datetime.datetime(2023, 1, 1, 11, 4, 9)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_CREATION,
        creation_origin=events.TestcaseOrigin.MANUAL_UPLOAD,
        uploader='@gmail.com',
        timestamp=datetime.datetime(2023, 1, 1, 9, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_FIXED,
        fixed_revision='123:456',
        timestamp=datetime.datetime(2023, 1, 2, 0, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.ISSUE_FILING,
        issue_created=True,
        issue_id='123456',
        issue_reporter='@gmail.com',
        timestamp=datetime.datetime(2023, 1, 3, 0, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.ISSUE_CLOSING,
        closing_reason=events.ClosingReason.TESTCASE_FIXED,
        timestamp=datetime.datetime(2023, 1, 4, 0, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='blame',
        task_stage='stage4',
        task_status='status4',
        task_outcome='outcome5',
        timestamp=datetime.datetime(2023, 1, 1, 13, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='variant',
        task_stage='stage2',
        task_status='status3',
        task_outcome='outcome2',
        timestamp=datetime.datetime(2023, 1, 1, 14, 0, 0)).put()


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseStatusMachineInfoTest(EventsInfoTest):
  """Test testcase status machine information retrieval."""

  def test_get_testcase_status_info(self):
    """Verify that testcase information is retrieved correctly from events."""
    result = self.status_info_instance.get_info()

    expected_task_events = [{
        'task_name': 'Impact'
    }, {
        'task_name': 'Regression'
    }, {
        'task_name': 'Progression'
    }, {
        'task_name': 'Analyze',
        'task_stage': 'stage2',
        'task_status': 'status2',
        'task_outcome': 'outcome2',
        'timestamp': '2023-01-01 11:03:11.000000 UTC'
    }, {
        'task_name': 'Minimize',
        'task_stage': 'stage3',
        'task_status': 'status3',
        'task_outcome': None,
        'timestamp': '2023-01-01 11:04:09.000000 UTC'
    }, {
        'task_name': 'Blame',
        'task_stage': 'stage4',
        'task_status': 'status4',
        'task_outcome': 'outcome5',
        'timestamp': '2023-01-01 13:00:00.000000 UTC'
    }, {
        'task_name': 'Variant',
        'task_stage': 'stage2',
        'task_status': 'status3',
        'task_outcome': 'outcome2',
        'timestamp': '2023-01-01 14:00:00.000000 UTC'
    }]

    expected_lifecycle_events = [{
        'event_type': 'Testcase Rejection'
    }, {
        'event_type': 'Testcase Grouping'
    }, {
        'event_type': 'Testcase Creation',
        'timestamp': '2023-01-01 09:00:00.000000 UTC',
        'event_info': 'Creation origin: manual_upload\nUploaded by @gmail.com'
    }, {
        'event_type': 'Testcase Fixed',
        'timestamp': '2023-01-02 00:00:00.000000 UTC',
        'event_info': 'Fixed revision: 123:456',
    }, {
        'event_type': 'Issue Filing',
        'timestamp': '2023-01-03 00:00:00.000000 UTC',
        'event_info': 'Issue created (123456)\nManually created by @gmail.com',
    }, {
        'event_type': 'Issue Closing',
        'timestamp': '2023-01-04 00:00:00.000000 UTC',
        'event_info': 'Closing reason: testcase_fixed',
    }]

    self.assertCountEqual(result.keys(),
                          ['task_events_info', 'lifecycle_events_info'])
    self.assertEqual(result['task_events_info'], expected_task_events)
    self.assertEqual(result['lifecycle_events_info'], expected_lifecycle_events)


@test_utils.with_cloud_emulators('datastore')
class GetLastEventInfoTest(EventsInfoTest):
  """Test retrieving information from the last event based on filters."""

  def test_format_task_execution_event(self):
    """Verify the retrieval of a task execution event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TASK_EXECUTION, task_name='minimize')

    expected = {
        'task_name': 'Minimize',
        'task_stage': 'stage3',
        'task_status': 'status3',
        'task_outcome': None,
        'timestamp': '2023-01-01 11:04:09.000000 UTC'
    }
    self.assertEqual(result, expected)

  def test_format_blame_task_execution_event(self):
    """Verify the retrieval of a blame event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TASK_EXECUTION, task_name='blame')

    expected = {
        'task_name': 'Blame',
        'task_stage': 'stage4',
        'task_status': 'status4',
        'task_outcome': 'outcome5',
        'timestamp': '2023-01-01 13:00:00.000000 UTC'
    }
    self.assertEqual(result, expected)

  def test_format_variant_task_execution_event(self):
    """Verify the retrieval of a variant event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TASK_EXECUTION, task_name='variant')

    expected = {
        'task_name': 'Variant',
        'task_stage': 'stage2',
        'task_status': 'status3',
        'task_outcome': 'outcome2',
        'timestamp': '2023-01-01 14:00:00.000000 UTC'
    }
    self.assertEqual(result, expected)

  def test_format_testcase_creation_event(self):
    """Verify the retrieval of a testcase creation event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_CREATION)

    expected = {
        'event_type': 'Testcase Creation',
        'timestamp': '2023-01-01 09:00:00.000000 UTC',
        'event_info': 'Creation origin: manual_upload\nUploaded by @gmail.com'
    }
    self.assertEqual(result, expected)

  def test_format_testcase_rejection_event(self):
    """Verify the retrieval of a testcase rejection event information."""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_REJECTION,
        rejection_reason=events.RejectionReason.ANALYZE_NO_REPRO,
        timestamp=datetime.datetime(2023, 1, 5, 0, 0, 0)).put()

    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_REJECTION)

    expected = {
        'event_type': 'Testcase Rejection',
        'timestamp': '2023-01-05 00:00:00.000000 UTC',
        'event_info': 'Rejection reason: analyze_no_repro'
    }
    self.assertEqual(result, expected)

  def test_format_testcase_fixed_event(self):
    """Verify the retrieval of a testcase fixed event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_FIXED)

    expected = {
        'event_type': 'Testcase Fixed',
        'timestamp': '2023-01-02 00:00:00.000000 UTC',
        'event_info': 'Fixed revision: 123:456'
    }
    self.assertEqual(result, expected)

  def test_format_issue_closing_event(self):
    """Verify the retrieval of an issue closing event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.ISSUE_CLOSING)

    expected = {
        'event_type': 'Issue Closing',
        'timestamp': '2023-01-04 00:00:00.000000 UTC',
        'event_info': 'Closing reason: testcase_fixed'
    }
    self.assertEqual(result, expected)

  def test_format_issue_filing_event_success(self):
    """Verify the retrieval of a successful issue filing event information."""
    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.ISSUE_FILING)

    expected = {
        'event_type': 'Issue Filing',
        'timestamp': '2023-01-03 00:00:00.000000 UTC',
        'event_info': 'Issue created (123456)\nManually created by @gmail.com'
    }
    self.assertEqual(result, expected)

  def test_format_issue_filing_event_failure(self):
    """Verify the retrieval of a failed issue filing event information."""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.ISSUE_FILING,
        issue_created=False,
        timestamp=datetime.datetime(2023, 1, 6, 0, 0, 0)).put()

    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.ISSUE_FILING)

    expected = {
        'event_type': 'Issue Filing',
        'timestamp': '2023-01-06 00:00:00.000000 UTC',
        'event_info': 'Failed to create the issue'
    }
    self.assertEqual(result, expected)

  def test_format_testcase_grouping_event_simple(self):
    """Verify the retrieval of a simple testcase grouping event information."""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_GROUPING,
        group_id=101,
        previous_group_id=0,
        similar_testcase_id=999,
        grouping_reason=events.GroupingReason.SIMILAR_CRASH,
        timestamp=datetime.datetime(2023, 1, 9, 0, 0, 0)).put()

    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_GROUPING)

    expected = {
        'event_type':
            'Testcase Grouping',
        'timestamp':
            '2023-01-09 00:00:00.000000 UTC',
        'event_info': ('Grouping reason: similar_crash\n'
                       'Group ID: 101\n'
                       'Previous group ID: ungrouped\n'
                       'Similar testcase ID: 999')
    }
    self.assertEqual(result, expected)

  def test_format_testcase_grouping_event_merge(self):
    """Verify the retrieval of a group merge event information."""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_GROUPING,
        group_id=102,
        previous_group_id=101,
        similar_testcase_id=998,
        grouping_reason=events.GroupingReason.GROUP_MERGE,
        group_merge_reason=events.GroupingReason.SAME_ISSUE,
        timestamp=datetime.datetime(2023, 1, 8, 0, 0, 0)).put()

    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_GROUPING)

    expected = {
        'event_type':
            'Testcase Grouping',
        'timestamp':
            '2023-01-08 00:00:00.000000 UTC',
        'event_info': ('Grouping reason: group_merge\n'
                       'Group ID: 102\n'
                       'Previous group ID: 101\n'
                       'Similar testcase ID: 998\n'
                       'Group merge reason: same_issue')
    }
    self.assertEqual(result, expected)

  def test_format_testcase_grouping_event_ungrouped(self):
    """Verify the retrieval of an ungrouped event information"""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_GROUPING,
        group_id=0,
        previous_group_id=103,
        grouping_reason=events.GroupingReason.UNGROUPED,
        timestamp=datetime.datetime(2023, 1, 9, 0, 0, 0)).put()

    result = self.status_info_instance.get_last_event_info(
        event_type=events.EventTypes.TESTCASE_GROUPING)

    expected = {
        'event_type':
            'Testcase Grouping',
        'timestamp':
            '2023-01-09 00:00:00.000000 UTC',
        'event_info': ('Grouping reason: ungrouped\n'
                       'Group ID: ungrouped\n'
                       'Previous group ID: 103')
    }
    self.assertEqual(result, expected)

  def test_get_last_event_info_no_event(self):
    """Verify that an empty dict is returned when no event is found."""
    result = self.status_info_instance.get_last_event_info(
        event_type='non_existent_event_type')
    self.assertEqual(result, {})
