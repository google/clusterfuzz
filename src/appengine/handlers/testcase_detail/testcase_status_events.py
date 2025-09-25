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
"""Helper functions for getting testcase status information from events."""
from dataclasses import asdict
import datetime
import json
from typing import Generator
from typing import Mapping
from typing import TypeAlias
import urllib.parse

from google.cloud import logging_v2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.metrics import events

EventInfo: TypeAlias = dict[str, str | None]


def _format_timestamp(timestamp: datetime.datetime) -> str:
  """Formats a timestamp."""
  return timestamp.strftime('%Y-%m-%d %H:%M:%S.%f UTC')


class TestcaseStatusInfo:
  """Methods to retrieve and format testcase events information."""

  TASK_EVENTS_NAMES = ('analyze', 'minimize', 'impact', 'regression',
                       'progression', 'blame', 'variant')
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
            self._format_testcase_creation_event,
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

  def _format_string(self, text: str | None) -> str | None:
    """Formats a string by capitalizing words and replacing underscores."""
    if not text:
      return None
    return text.replace('_', ' ').title()

  def _format_task_execution_event(
      self, event: events.TaskExecutionEvent) -> EventInfo:
    """Formats a task execution event."""
    return {
        'task_name': self._format_string(event.task_name),
        'task_stage': event.task_stage,
        'task_status': event.task_status,
        'task_outcome': event.task_outcome,
        'timestamp': _format_timestamp(event.timestamp),
    }

  def _format_lifecycle_events_common_fields(self,
                                             event: events.Event) -> EventInfo:
    """Formats common fields for lifecycle events."""
    return {
        'event_type': self._format_string(event.event_type),
        'timestamp': _format_timestamp(event.timestamp),
        'event_info': None,
    }

  def _format_lifecycle_event_with_attribute_info(
      self, event: events.Event, event_info_prefix: str,
      attribute_name: str) -> EventInfo:
    """Formats a standard lifecycle event info."""
    info = self._format_lifecycle_events_common_fields(event)
    attribute_value = getattr(event, attribute_name)
    info['event_info'] = f'{event_info_prefix}: {attribute_value}'
    return info

  def _format_testcase_creation_event(
      self, event: events.TestcaseCreationEvent) -> EventInfo:
    """Formats a testcase creation event."""
    info = self._format_lifecycle_events_common_fields(event)
    event_info = f'Creation origin: {event.creation_origin}'
    if event.uploader:
      event_info += f'\nUploaded by {event.uploader}'
    info['event_info'] = event_info
    return info

  def _format_issue_filing_event(self,
                                 event: events.IssueFilingEvent) -> EventInfo:
    """Formats an issue filing event."""
    info = self._format_lifecycle_events_common_fields(event)
    info['event_info'] = (f'Issue created ({event.issue_id})' if
                          event.issue_created else 'Failed to create the issue')
    if event.issue_created and event.issue_reporter:
      info['event_info'] += f'\nManually created by {event.issue_reporter}'
    return info

  def _format_testcase_grouping_event(
      self, event: events.TestcaseGroupingEvent) -> EventInfo:
    """Formats a testcase grouping event."""
    info = self._format_lifecycle_events_common_fields(event)
    event_info_data = {
        'Grouping reason':
            event.grouping_reason,
        'Group ID':
            event.group_id if event.group_id != 0 else 'ungrouped',
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
                          task_name: str | None = None) -> EventInfo:
    """Get information from the last event that matches the criteria."""
    last_event = next(
        events.get_events_from_testcase(
            self._testcase_id, event_type=event_type, task_name=task_name),
        None)

    if last_event and (formatter := self._formatters.get(
        last_event.event_type)):
      return formatter(last_event)
    return {}

  def get_info(self) -> Mapping[str, list[EventInfo]]:
    """Get testcase status information from events.
    
    The lists of events are returned in chronological order.
    """
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

    # String sorting works here because timestamps are in the
    # `strftime('%Y-%m-%d %H:%M:%S.%f UTC')` format.
    task_events_info.sort(key=lambda x: x.get('timestamp', ''))
    lifecycle_events_info.sort(key=lambda x: x.get('timestamp', ''))

    return {
        'task_events_info': task_events_info,
        'lifecycle_events_info': lifecycle_events_info
    }


class TestcaseEventHistory:
  """Methods to retrieve the testcase events history."""

  def __init__(self, testcase_id: int):
    self._testcase_id = testcase_id

  def _get_time_range_filter(self, days: int) -> str:
    """Returns a filter string for a time range."""
    start_time = utils.utcnow() - datetime.timedelta(days=days)
    return f'timestamp >= "{start_time.isoformat()}Z"'

  def _get_task_log_query_filter(self, task_id: str, task_name: str) -> str:
    """Returns the filter string for querying task logs."""
    query = (f'jsonPayload.extras.task_id="{task_id}" AND '
             f'jsonPayload.extras.testcase_id="{self._testcase_id}" AND '
             f'jsonPayload.extras.task_name="{task_name}"')
    query += f' AND {self._get_time_range_filter(days=31)}'
    return query

  def _enrich_event_info_with_gcp_log_url(self, event_info: EventInfo) -> None:
    """Adds the GCP log URL to the event info."""
    project_id = utils.get_logging_cloud_project_id()
    task_id = event_info.get('task_id')
    task_name = event_info.get('task_name')
    if project_id and task_id and task_name:
      query = self._get_task_log_query_filter(task_id, task_name)
      encoded_query = urllib.parse.quote(query)
      event_info['gcp_log_url'] = (
          f'https://console.cloud.google.com/logs/viewer'
          f'?project={project_id}&query={encoded_query}')

  def _format_event_for_history(self, event: events.Event) -> EventInfo:
    """Formats an event for display in the event history table."""
    event_info = {k: v for k, v in asdict(event).items() if v is not None}
    event_info['timestamp'] = _format_timestamp(event.timestamp)
    return event_info

  def get_history(self) -> Generator[Mapping, None, None]:
    """Get all testcase events information in reverse chronological order."""
    event_history = events.get_events_from_testcase(self._testcase_id)
    for event in event_history:
      event_info = self._format_event_for_history(event)
      self._enrich_event_info_with_gcp_log_url(event_info)
      yield event_info

  def get_task_log(self, task_id: str, task_name: str) -> str:
    """Returns the logs for a given task as a string."""
    project_id = utils.get_logging_cloud_project_id()
    client = logging_v2.Client(project=project_id)
    filter_str = self._get_task_log_query_filter(task_id, task_name)
    entries = client.list_entries(
        filter_=filter_str, max_results=500, order_by=logging_v2.ASCENDING)

    return '\n'.join(
        json.dumps(entry.to_api_repr(), indent=2) for entry in entries)


def get_testcase_status_info(testcase_id: int) -> Mapping[str, list[EventInfo]]:
  """Public function to retrieve testcase status information."""
  return TestcaseStatusInfo(testcase_id).get_info()


def get_testcase_event_history(testcase_id: int) -> list[Mapping]:
  """Public function to get event history (reverse chronological order)."""
  return list(TestcaseEventHistory(testcase_id).get_history())


def get_task_log(testcase_id: int, task_id: str, task_name: str) -> str:
  """Public function to return the logs for a given task as a string."""
  return TestcaseEventHistory(testcase_id).get_task_log(task_id, task_name)
