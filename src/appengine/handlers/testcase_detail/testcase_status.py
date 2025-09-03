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
"""Helper functions for getting testcase status information."""

from types import MappingProxyType
from typing import Sequence

from clusterfuzz._internal.metrics import events

class TestcaseStatusInfo:
  """Provides methods to retrieve and format testcase status information."""

  TASK_EVENTS_NAMES = ('analyze', 'minimize', 'impact', 'regression',
                       'progression')
  TASK_EVENTS_FIELDS_TO_EXTRACT = ('task_stage', 'task_status', 'task_outcome',
                                   'timestamp')
  LIFECYCLE_EVENTS_TYPES = (
      events.EventTypes.TESTCASE_REJECTION,
      events.EventTypes.TESTCASE_CREATION,
      events.EventTypes.TESTCASE_FIXED,
      events.EventTypes.ISSUE_CLOSING,
      events.EventTypes.ISSUE_FILING,
      events.EventTypes.TESTCASE_GROUPING,
  )
  LIFECYCLE_EVENTS_EXTRA_FIELD_MAP = MappingProxyType({
      events.EventTypes.TESTCASE_CREATION: 'creation_origin',
      events.EventTypes.TESTCASE_REJECTION: 'rejection_reason',
      events.EventTypes.ISSUE_FILING: 'issue_created',
      events.EventTypes.TESTCASE_FIXED: 'fixed_revision',
      events.EventTypes.ISSUE_CLOSING: 'closing_reason',
      events.EventTypes.TESTCASE_GROUPING: 'grouping_reason',
  })
  LIFECYCLE_EVENTS_FIELDS_TO_EXTRACT = ('timestamp',)

  def __init__(self, testcase_id: int):
    """Initializes the TestcaseStatusInfo with a testcase ID."""
    self._testcase_id = testcase_id
  
  def _get_last_event_info(self,
                           fields_to_extract: Sequence[str],
                           event_type: str | None = None,
                           task_name: str | None = None) -> dict:
    """Get last event info for a specific filter set for the current testcase."""
    last_event = next(
        events.get_events_from_testcase(
            self._testcase_id, event_type=event_type, task_name=task_name), None)
    info = {}
    if last_event:
      for field in fields_to_extract:
        if hasattr(last_event, field):
          attr_value = getattr(last_event, field)
          if field == 'timestamp' and attr_value:
            attr_value = attr_value.strftime('%Y-%m-%d %H:%M:%S.%f UTC')
          info[field] = attr_value
    return info

  def get_info(self) -> dict:
    """Get comprehensive testcase status information.

    Returns a dictionary with task-related and lifecycle-related events info.
    """
    task_events_info = {
        task_name:
        self._get_last_event_info(
            self.TASK_EVENTS_FIELDS_TO_EXTRACT,
            event_type=events.EventTypes.TASK_EXECUTION,
            task_name=task_name) for task_name in self.TASK_EVENTS_NAMES
    }
    lifecycle_events_info = {}
    for event_type in self.LIFECYCLE_EVENTS_TYPES:
      fields_to_extract = list(self.LIFECYCLE_EVENTS_FIELDS_TO_EXTRACT)
      extra_field = self.LIFECYCLE_EVENTS_EXTRA_FIELD_MAP.get(event_type)
      if extra_field:
        fields_to_extract.append(extra_field)
  
      event_info = self._get_last_event_info(
          fields_to_extract, event_type=event_type)

      if extra_field and extra_field in event_info:
        event_info['extra'] = event_info.pop(extra_field)

      lifecycle_events_info[event_type] = event_info
  
    return {
        'task_events_info': task_events_info,
        'lifecycle_events_info': lifecycle_events_info,
    }


def get_testcase_status_info(testcase_id: int) -> dict:
  """Get testcase status information."""
  return TestcaseStatusInfo(testcase_id).get_info()
  