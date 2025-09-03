# Copyright 2023 Google LLC
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
from handlers.testcase_detail import testcase_status


class EventsInfoTest(unittest.TestCase):
  """Helper class for tests involving retrieving events information."""

  def setUp(self):
    self.testcase = test_utils.create_generic_testcase()
    self.testcase_id = self.testcase.key.id()
    self.status_info_instance = testcase_status.TestcaseStatusInfo(self.testcase_id)
    test_helpers.patch(
        self, ['clusterfuzz._internal.config.local_config.ProjectConfig'])
    self.mock.ProjectConfig.return_value = {'events.storage': 'datastore'}

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
        timestamp=datetime.datetime(2023, 1, 1, 11, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TASK_EXECUTION,
        task_name='minimize',
        task_stage='stage3',
        task_status='status3',
        task_outcome=None,
        timestamp=datetime.datetime(2023, 1, 1, 12, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.TESTCASE_CREATION,
        creation_origin=events.TestcaseOrigin.FUZZ_TASK,
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
        timestamp=datetime.datetime(2023, 1, 3, 0, 0, 0)).put()

    data_types.TestcaseLifecycleEvent(
        testcase_id=self.testcase_id,
        event_type=events.EventTypes.ISSUE_CLOSING,
        closing_reason=events.ClosingReason.TESTCASE_FIXED,
        timestamp=datetime.datetime(2023, 1, 4, 0, 0, 0)).put()


@test_utils.with_cloud_emulators('datastore')
class GetLastEventInfoTest(EventsInfoTest):
  """Test retrieving information from the last event based on filters."""

  def test_get_last_event_info(self):
    """Verify that event info is retrieved and formatted correctly."""
    result = self.status_info_instance._get_last_event_info(
        fields_to_extract=['timestamp', 'creation_origin'],
        event_type=events.EventTypes.TESTCASE_CREATION)

    expected = {
        'timestamp': '2023-01-01 09:00:00.000000 UTC',
        'creation_origin': 'fuzz_task'
    }
    self.assertEqual(result, expected)

  def test_get_last_event_info_no_event(self):
    """Verify that an empty dict is returned when no event is found."""
    result = self.status_info_instance._get_last_event_info(
        fields_to_extract=['timestamp'], event_type='non_existent_event_type')
    self.assertEqual(result, {})


@test_utils.with_cloud_emulators('datastore')
class GetTestcaseStatusMachineInfoTest(EventsInfoTest):
  """Test retrieving testcase status machine information."""

  def test_get_testcase_status_info(self):
    """Verify that testcase information is retrieved correctly from events."""
    result = self.status_info_instance.get_info()

    expected_task_events = {
        'analyze': {
            'task_stage': 'stage2',
            'task_status': 'status2',
            'task_outcome': 'outcome2',
            'timestamp': '2023-01-01 11:00:00.000000 UTC'
        },
        'minimize': {
            'task_stage': 'stage3',
            'task_status': 'status3',
            'task_outcome': None,
            'timestamp': '2023-01-01 12:00:00.000000 UTC'
        },
        'impact': {},
        'regression': {},
        'progression': {},
    }

    expected_lifecycle_events = {
        events.EventTypes.TESTCASE_CREATION: {
            'timestamp': '2023-01-01 09:00:00.000000 UTC',
            'extra': events.TestcaseOrigin.FUZZ_TASK,
        },
        events.EventTypes.TESTCASE_FIXED: {
            'timestamp': '2023-01-02 00:00:00.000000 UTC',
            'extra': '123:456',
        },
        events.EventTypes.TESTCASE_REJECTION: {},
        events.EventTypes.ISSUE_CLOSING: {
            'timestamp': '2023-01-04 00:00:00.000000 UTC',
            'extra': events.ClosingReason.TESTCASE_FIXED,
        },
        events.EventTypes.ISSUE_FILING: {
            'timestamp': '2023-01-03 00:00:00.000000 UTC',
            'extra': True,
        },
        events.EventTypes.TESTCASE_GROUPING: {},
    }

    expected_result = {
        'task_events_info': expected_task_events,
        'lifecycle_events_info': expected_lifecycle_events,
    }

    self.assertEqual(result, expected_result)
