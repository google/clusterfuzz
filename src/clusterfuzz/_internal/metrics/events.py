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
"""Events definition and handling."""

from abc import ABC
from abc import abstractmethod
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from dataclasses import InitVar
import datetime
from typing import Any

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


@dataclass(kw_only=True)
class Event:
  """Base class for ClusterFuzz events."""
  # Event type (required if a generic event class is used).
  event_type: str
  # Source location (optional).
  source: str | None = None
  # Timestamp when the event was created.
  timestamp: datetime.datetime = field(
      init=False, default=datetime.datetime.now(datetime.timezone.utc))

  # Common metadata retrieved from running environment.
  clusterfuzz_version: str | None = field(init=False, default=None)
  clusterfuzz_config_version: str | None = field(init=False, default=None)
  instance_id: str | None = field(init=False, default=None)
  operating_system: str | None = field(init=False, default=None)
  os_version: str | None = field(init=False, default=None)

  def __post_init__(self, **kwargs):
    del kwargs
    common_ctx = logs.get_common_log_context()
    for key, val in common_ctx.items():
      setattr(self, key, val)


@dataclass(kw_only=True)
class TestcaseEvent(Event):
  """Base class for testcase-related events."""
  # Testcase entity (only used in init to set the event data).
  testcase: InitVar[data_types.Testcase | None] = None

  # Testcase metadata (retrieved from the testcase entity, if available).
  testcase_id: str | None = None
  fuzzer: str | None = None
  job: str | None = None
  crash_revision: str | None = None

  def __post_init__(self, testcase=None, **kwargs):
    if testcase is not None:
      self.testcase_id = testcase.key.id()
      self.fuzzer = testcase.fuzzer_name
      self.job = testcase.job_type
      self.crash_revision = testcase.crash_revision
    return super().__post_init__(**kwargs)


@dataclass(kw_only=True)
class TaskEvent(Event):
  """Base class for task-related events."""
  # Task ID retrieved from environment var (if not directly set).
  task_id: str | None = None

  def __post_init__(self, **kwargs):
    if self.task_id is None:
      self.task_id = environment.get_value('CF_TASK_ID', None)
    return super().__post_init__(**kwargs)


@dataclass(kw_only=True)
class TestcaseCreationEvent(TestcaseEvent, TaskEvent):
  """Testcase creation event."""
  event_type: str = field(default='testcase_creation', init=False)
  # Either manual upload, fuzz task or corpus pruning.
  origin: str | None = None
  # User email, if testcase manually uploaded.
  uploader: str | None = None


@dataclass(kw_only=True)
class TestcaseRejectionEvent(TestcaseEvent, TaskEvent):
  """Testcase rejection event."""
  event_type: str = field(default='testcase_rejection', init=False)
  # Reason for rejection (e.g., triage_duplicated)
  reason: str | None = None
