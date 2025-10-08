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
from unittest import mock

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.testcase_detail import testcase_status_events


class EventsInfoBasicTest(unittest.TestCase):
  """Helper class with basic setup for tests involving retrieving events."""

  def setUp(self):
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_id = self.testcase.key.id()
    self.status_info_instance = testcase_status_events.TestcaseStatusInfo(
        self.testcase_id)
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        'clusterfuzz._internal.base.utils.is_chromium'
    ])
    self.mock.ProjectConfig.return_value = {'events.storage': 'datastore'}
    self.mock.is_chromium.return_value = True


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

  def test_get_testcase_status_info_no_events_no_chromium(self):
    """Verify that Chrome tasks are not retrieved by non-chromium fuzzing instances."""
    self.mock.is_chromium.return_value = False
    result = self.status_info_instance.get_info()

    expected_task_events = [
        {
            'task_name': 'Analyze'
        },
        {
            'task_name': 'Minimize'
        },
        {
            'task_name': 'Regression'
        },
        {
            'task_name': 'Progression'
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
        task_id='1',
        task_name='analyze',
        task_stage='stage1',
        task_status='status1',
        task_outcome='outcome1',
        timestamp=datetime.datetime(2023, 1, 1, 10, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_id='1',
        task_name='analyze',
        task_stage='stage2',
        task_status='status2',
        task_outcome='outcome2',
        timestamp=datetime.datetime(2023, 1, 1, 11, 3, 11)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_id='2',
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
        'task_name': 'Progression'
    }, {
        'task_name': 'Regression'
    }, {
        'task_name': 'Impact'
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
        'event_type': 'Testcase Grouping'
    }, {
        'event_type': 'Testcase Rejection'
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

  def test_get_testcase_status_info_chronological_order(self):
    """Verify that testcase information is retrieved in chronological order."""
    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='progression',
        timestamp=datetime.datetime(2023, 1, 1, 11, 4, 9, 1000)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='impact',
        timestamp=datetime.datetime(2023, 1, 1, 11, 4, 9, 500)).put()

    result = self.status_info_instance.get_info()

    task_events = result['task_events_info']
    lifecycle_events = result['lifecycle_events_info']

    task_timestamps = [
        event['timestamp'] for event in task_events if 'timestamp' in event
    ]
    lifecycle_timestamps = [
        event['timestamp'] for event in lifecycle_events if 'timestamp' in event
    ]

    expected_task_timestamps = [
        '2023-01-01 11:03:11.000000 UTC',
        '2023-01-01 11:04:09.000000 UTC',
        '2023-01-01 11:04:09.000500 UTC',
        '2023-01-01 11:04:09.001000 UTC',
        '2023-01-01 13:00:00.000000 UTC',
        '2023-01-01 14:00:00.000000 UTC',
    ]
    self.assertEqual(task_timestamps, expected_task_timestamps)
    expected_lifecycle_timestamps = [
        '2023-01-01 09:00:00.000000 UTC',
        '2023-01-02 00:00:00.000000 UTC',
        '2023-01-03 00:00:00.000000 UTC',
        '2023-01-04 00:00:00.000000 UTC',
    ]
    self.assertEqual(lifecycle_timestamps, expected_lifecycle_timestamps)


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


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseEventHistoryTest(EventsInfoTest):
  """Test retrieving testcase event history."""

  def setUp(self):
    super().setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_logging_cloud_project_id',
        'clusterfuzz._internal.base.utils.utcnow'
    ])
    self.mock.get_logging_cloud_project_id.return_value = 'test-project'
    self.mock.utcnow.return_value = datetime.datetime(2025, 2, 1, 0, 0, 0)

  def test_get_history(self):
    """Verify that testcase event history is retrieved correctly."""
    history = testcase_status_events.get_testcase_event_history(
        self.testcase_id)

    expected_history = [
        {
            'event_type': 'issue_closing',
            'closing_reason': 'testcase_fixed',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-04 00:00:00.000000 UTC',
        },
        {
            'event_type': 'issue_filing',
            'issue_created': True,
            'issue_id': '123456',
            'issue_reporter': '@gmail.com',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-03 00:00:00.000000 UTC',
        },
        {
            'event_type': 'testcase_fixed',
            'fixed_revision': '123:456',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-02 00:00:00.000000 UTC',
        },
        {
            'event_type': 'task_execution',
            'task_name': 'variant',
            'task_stage': 'stage2',
            'task_status': 'status3',
            'task_outcome': 'outcome2',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-01 14:00:00.000000 UTC',
        },
        {
            'event_type': 'task_execution',
            'task_name': 'blame',
            'task_stage': 'stage4',
            'task_status': 'status4',
            'task_outcome': 'outcome5',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-01 13:00:00.000000 UTC',
        },
        {
            'event_type':
                'task_execution',
            'task_name':
                'minimize',
            'task_stage':
                'stage3',
            'task_status':
                'status3',
            'testcase_id':
                self.testcase_id,
            'task_id':
                '2',
            'timestamp':
                '2023-01-01 11:04:09.000000 UTC',
            'gcp_log_url': (
                'https://console.cloud.google.com/logs/viewer'
                '?project=test-project&query=jsonPayload.extras.task_id%3D%222%22%20AND%20'
                f'jsonPayload.extras.testcase_id%3D%22{self.testcase_id}%22%20AND%20jsonPayload.extras.task_name'
                '%3D%22minimize%22%20AND%20timestamp%20%3E%3D%20%222025-01-01T00%3A00%3A00Z%22'
            )
        },
        {
            'event_type':
                'task_execution',
            'task_name':
                'analyze',
            'task_stage':
                'stage2',
            'task_status':
                'status2',
            'testcase_id':
                self.testcase_id,
            'task_id':
                '1',
            'task_outcome':
                'outcome2',
            'timestamp':
                '2023-01-01 11:03:11.000000 UTC',
            'gcp_log_url': (
                'https://console.cloud.google.com/logs/viewer'
                '?project=test-project&query=jsonPayload.extras.task_id%3D%221%22%20AND%20'
                f'jsonPayload.extras.testcase_id%3D%22{self.testcase_id}%22%20AND%20jsonPayload.extras.task_name'
                '%3D%22analyze%22%20AND%20timestamp%20%3E%3D%20%222025-01-01T00%3A00%3A00Z%22'
            )
        },
        {
            'event_type':
                'task_execution',
            'task_name':
                'analyze',
            'task_stage':
                'stage1',
            'task_status':
                'status1',
            'testcase_id':
                self.testcase_id,
            'task_id':
                '1',
            'task_outcome':
                'outcome1',
            'timestamp':
                '2023-01-01 10:00:00.000000 UTC',
            'gcp_log_url': (
                'https://console.cloud.google.com/logs/viewer'
                '?project=test-project&query=jsonPayload.extras.task_id%3D%221%22%20AND%20'
                f'jsonPayload.extras.testcase_id%3D%22{self.testcase_id}%22%20AND%20jsonPayload.extras.task_name'
                '%3D%22analyze%22%20AND%20timestamp%20%3E%3D%20%222025-01-01T00%3A00%3A00Z%22'
            )
        },
        {
            'event_type': 'testcase_creation',
            'creation_origin': 'manual_upload',
            'uploader': '@gmail.com',
            'testcase_id': self.testcase_id,
            'timestamp': '2023-01-01 09:00:00.000000 UTC',
        },
    ]

    self.assertEqual(list(history), expected_history)


@test_utils.with_cloud_emulators('datastore')
class TestcaseEventHistoryTest(unittest.TestCase):
  """Tests for TestcaseEventHistory."""

  def setUp(self):
    """Set up test environment."""
    super().setUp()
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_id = self.testcase.key.id()
    self.event_history = testcase_status_events.TestcaseEventHistory(
        self.testcase_id)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.get_logging_cloud_project_id',
        'google.cloud.logging_v2.Client',
        'clusterfuzz._internal.base.utils.utcnow',
        'clusterfuzz._internal.metrics.logs.error',
    ])
    self.mock.utcnow.return_value = datetime.datetime(2025, 2, 1, 0, 0, 0)

  def test_get_time_range_filter(self):
    """Verify that the time range filter is generated correctly."""
    result = self.event_history._get_time_range_filter(days=1)
    self.assertEqual(result, 'timestamp >= "2025-01-31T00:00:00Z"')

  def test_get_task_log_query_filter(self):
    """Verify that the task log query filter is generated correctly."""
    result = self.event_history._get_task_log_query_filter(
        'task123', 'minimize')
    expected = (f'jsonPayload.extras.task_id="task123" AND '
                f'jsonPayload.extras.testcase_id="{self.testcase_id}" AND '
                'jsonPayload.extras.task_name="minimize" AND '
                'timestamp >= "2025-01-01T00:00:00Z"')
    self.assertEqual(result, expected)

  def test_enrich_event_info_with_gcp_log_url_no_project(self):
    """Verify that no log URL is added when the project ID is missing."""
    self.mock.get_logging_cloud_project_id.return_value = None
    event_info = {'task_id': 'task123', 'task_name': 'minimize'}
    self.event_history._enrich_event_info_with_gcp_log_url(event_info)
    self.assertNotIn('gcp_log_url', event_info)
    self.mock.error.assert_called_once_with(
        'Unable to generate GCP log URL due to missing info. '
        "Missing info: ['project_id']")

  def test_enrich_event_info_with_gcp_log_url_no_task_info(self):
    """Verify that no log URL is added when the task info is missing."""
    self.mock.get_logging_cloud_project_id.return_value = 'test-project'
    event_info = {'other_key': 'value'}
    self.event_history._enrich_event_info_with_gcp_log_url(event_info)
    self.assertNotIn('gcp_log_url', event_info)
    self.mock.error.assert_called_once_with(
        'Unable to generate GCP log URL due to missing info. '
        "Missing info: ['task_id', 'task_name']")

  def test_enrich_event_info_with_gcp_log_url_success(self):
    """Verify that the log URL is correctly added to the event info."""
    self.mock.get_logging_cloud_project_id.return_value = 'test-project'
    event_info = {'task_id': 'task123', 'task_name': 'minimize'}
    self.event_history._enrich_event_info_with_gcp_log_url(event_info)

    url_query = (
        'jsonPayload.extras.task_id%3D%22task123%22%20AND%20jsonPayload.extras.'
        'testcase_id%3D%221%22%20AND%20jsonPayload.extras.task_name%3D%22minimize%22%20AND%20timestamp'
        '%20%3E%3D%20%222025-01-01T00%3A00%3A00Z%22')

    self.assertIn('gcp_log_url', event_info)
    self.assertIn('project=test-project', event_info['gcp_log_url'])
    self.assertIn(f'query={url_query}', event_info['gcp_log_url'])

  def test_format_event_for_history(self):
    """Verify that an event is formatted correctly for the history view."""
    test_event = events.TestcaseCreationEvent(
        testcase_id=self.testcase_id,
        creation_origin=events.TestcaseOrigin.MANUAL_UPLOAD,
        uploader='user@example.com',
        source=None)
    test_event.timestamp = datetime.datetime(2023, 1, 1, 10, 0, 0)

    result = self.event_history._format_event_for_history(test_event)
    self.assertIn('timestamp', result)
    self.assertEqual(result['timestamp'], '2023-01-01 10:00:00.000000 UTC')
    self.assertEqual(result['creation_origin'], 'manual_upload')
    self.assertNotIn('source', result)

  def test_get_task_log_no_project_id(self):
    """Verify that get_task_log returns an empty string if no project ID is available."""
    self.mock.get_logging_cloud_project_id.return_value = None
    self.mock.Client.return_value.list_entries.return_value = []
    result = self.event_history.get_task_log('task123', 'minimize')
    self.assertEqual(result, '')

  def test_get_task_log_api_call(self):
    """Verify that get_task_log calls the logging API correctly."""
    self.mock.get_logging_cloud_project_id.return_value = 'test-project'
    mock_client_instance = self.mock.Client.return_value
    mock_entry1 = mock.Mock()
    mock_entry1.to_api_repr.return_value = {'payload': 'log1'}
    mock_entry2 = mock.Mock()
    mock_entry2.to_api_repr.return_value = {'payload': 'log2'}
    mock_client_instance.list_entries.return_value = [mock_entry2, mock_entry1]
    expected_filter = (
        f'jsonPayload.extras.task_id="task123" AND '
        f'jsonPayload.extras.testcase_id="{self.testcase_id}" AND '
        'jsonPayload.extras.task_name="minimize" AND '
        'timestamp >= "2025-01-01T00:00:00Z"')

    result = self.event_history.get_task_log('task123', 'minimize')
    self.mock.Client.assert_called_with(project='test-project')
    mock_client_instance.list_entries.assert_called_with(
        filter_=expected_filter, max_results=500, order_by=mock.ANY)

    self.assertIn('"payload": "log1"', result)
    self.assertIn('"payload": "log2"', result)
    self.assertLess(
        result.find('"payload": "log1"'), result.find('"payload": "log2"'))
    self.assertEqual(result.count('\n'), 5)
