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
"""Helper functions for getting testcase status information."""

import datetime
from typing import Mapping

from clusterfuzz._internal.metrics import events


class TestcaseStatusInfo:
  """Provides methods to retrieve and format testcase status information."""

  TASK_EVENTS_NAMES = ('analyze', 'minimize', 'impact', 'regression',
                       'progression')
  LIFECYCLE_EVENTS_TYPES = (
      events.EventTypes.TESTCASE_REJECTION,
      events.EventTypes.TESTCASE_CREATION,
      events.EventTypes.TESTCASE_FIXED,
      events.EventTypes.ISSUE_CLOSING,
      events.EventTypes.ISSUE_FILING,
      events.EventTypes.TESTCASE_GROUPING,
  )

  def __init__(self, testcase_id: int):
    """Initializes the TestcaseStatusInfo with a testcase ID."""
    self._testcase_id = testcase_id
    self._formatters = {
        events.EventTypes.TASK_EXECUTION:
            self._format_task_execution_event,
        events.EventTypes.TESTCASE_CREATION:
            lambda event: self._format_lifecycle_event_with_attribute_info(
                event, 'Creation origin', 'creation_origin'),
        events.EventTypes.TESTCASE_REJECTION:
            lambda event: self._format_lifecycle_event_with_attribute_info(
                event, 'Rejection reason', 'rejection_reason'),
        events.EventTypes.TESTCASE_FIXED:
            lambda event: self._format_lifecycle_event_with_attribute_info(
                event, 'Fixed revision', 'fixed_revision'),
        events.EventTypes.ISSUE_CLOSING:
            lambda event: self._format_lifecycle_event_with_attribute_info(
                event, 'Closing reason', 'closing_reason'),
        events.EventTypes.ISSUE_FILING:
            self._format_issue_filing_event,
        events.EventTypes.TESTCASE_GROUPING:
            self._format_testcase_grouping_event,
    }

  def _format_timestamp(self,
                        timestamp: datetime.datetime) -> str | None:
    """Formats a timestamp."""
    return timestamp.strftime('%Y-%m-%d %H:%M:%S.%f UTC')

  def _format_string(self, text: str | None) -> str | None:
    """Formats a string by capitalizing words and replacing underscores."""
    if not text:
      return None
    return text.replace('_', ' ').title()

  def _format_task_execution_event(self,
                                   event: events.TaskExecutionEvent) -> dict[str, str | None]:
    """Formats a task execution event."""
    return {
        'task_name': self._format_string(event.task_name),
        'task_stage': event.task_stage,
        'task_status': event.task_status,
        'task_outcome': event.task_outcome,
        'timestamp': self._format_timestamp(event.timestamp),
    }

  def _format_lifecycle_events_common_fields(self, event: events.Event) -> dict[str, str | None]:
    """Formats common fields for lifecycle events."""
    return {
        'event_type': self._format_string(event.event_type),
        'timestamp': self._format_timestamp(event.timestamp),
        'event_info': None,
    }

  def _format_lifecycle_event_with_attribute_info(
      self, event: events.Event, event_info_prefix: str, attribute_name: str) -> dict[str, str | None]:
    """Formats a standard lifecycle event info."""
    info = self._format_lifecycle_events_common_fields(event)
    attribute_value = getattr(event, attribute_name)
    info['event_info'] = f'{event_info_prefix}: {attribute_value}'
    return info

  def _format_issue_filing_event(self, event: events.IssueFilingEvent) -> dict[str, str | None]:
    """Formats an issue filing event."""
    info = self._format_lifecycle_events_common_fields(event)
    info['event_info'] = 'Issue created' if (
        event.issue_created) else 'Failed to create the issue'
    return info

  def _format_testcase_grouping_event(
      self, event: events.TestcaseGroupingEvent) -> dict[str, str | None]:
    """Formats a testcase grouping event."""
    info = self._format_lifecycle_events_common_fields(event)
    event_info_data = {
        'Grouping reason': event.grouping_reason,
        'Group ID': event.group_id if event.group_id != 0 else 'ungrouped',
        'Previous group ID':
            event.previous_group_id
            if event.previous_group_id != 0 else 'ungrouped',
    }

    if event.grouping_reason != events.GroupingReason.UNGROUPED:
      event_info_data['Similar testcase ID'] = event.similar_testcase_id
    if event.grouping_reason == events.GroupingReason.GROUP_MERGE:
      event_info_data['Group merge reason'] = event.group_merge_reason

    event_info = '\n'.join(
        f'{key}: {value}' for key, value in event_info_data.items())
    info['event_info'] = event_info
    return info

  def get_last_event_info(self,
                          event_type: str | None = None,
                          task_name: str | None = None) -> dict[str, str | None]:
    """Get information from the last event that matches the criteria."""
    last_event = next(
        events.get_events_from_testcase(
            self._testcase_id, event_type=event_type, task_name=task_name),
        None)

    return formatter(last_event) if (last_event and
                                     (formatter := self._formatters.get(
                                         last_event.event_type))) else {}

  def get_info(self) -> Mapping[str, list[dict[str, str | None]]]:
    """Get testcase status information"""
    task_events_info = [
        self.get_last_event_info(
            event_type=events.EventTypes.TASK_EXECUTION, task_name=task_name)
        | {
            'task_name': self._format_string(task_name)
        } for task_name in self.TASK_EVENTS_NAMES
    ]
    lifecycle_events_info = [
        self.get_last_event_info(event_type=event_type) | {
            'event_type': self._format_string(event_type)
        } for event_type in self.LIFECYCLE_EVENTS_TYPES
    ]

    return {
        'task_events_info': task_events_info,
        'lifecycle_events_info': lifecycle_events_info,
    }


def get_testcase_status_info(testcase_id: int) -> Mapping[str, list[dict[str, str | None]]]:
  """Public function to retrieve testcase status information."""
  return TestcaseStatusInfo(testcase_id).get_info()
