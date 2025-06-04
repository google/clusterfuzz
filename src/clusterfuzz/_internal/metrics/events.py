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
"""Events handling and emitting."""

from abc import ABC
from abc import abstractmethod
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from dataclasses import InitVar
import datetime
from typing import Any

from clusterfuzz._internal.datastore import data_handler
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
      init=False, default=datetime.datetime.now())

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
  testcase_id: int | None = None
  fuzzer: str | None = None
  job: str | None = None
  crash_revision: int | None = None

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


# Mapping of specific event types to their classes.
_EVENT_TYPE_CLASSES = {
    'testcase_creation': TestcaseCreationEvent,
}


class IEventRepository(ABC):
  """Event repository abstract class (interface).

  This class is responsable for defining the expected operations for event
  storage and retrieval in a repository/database.
  All concrete event repositories must implement these methods.
  """

  @abstractmethod
  def serialize_event(self, event: Event) -> Any:
    """Serialize an event into the underlying database entity."""

  @abstractmethod
  def deserialize_event(self, entity: Any) -> Event | None:
    """Deserialize a database entity into an event."""

  @abstractmethod
  def store_event(self, event: Event) -> str | int | None:
    """Save an event into the underlying database and return its ID."""

  @abstractmethod
  def get_event(self, event_id: str | int,
                event_type: str | None = None) -> Event | None:
    """Retrieve an event from the underlying database and return it."""


class NDBEventRepository(IEventRepository):
  """Implements the event repository for Datastore.
  
  Handles conversion between Event objects and Datastore entities. If a new
  Datastore entity model is needed, it relies on mapping the event types to
  the correct entity.
  """
  # Maps `event_type` to a Datastore model.
  # For now, only testcase lifecycle events are being traced.
  _event_to_entity_map = {}
  _default_entity = data_types.TestcaseLifecycleEvent

  def _to_entity(self, event: Event) -> data_types.Model:
    """Converts the event object into the Datastore entity."""
    entity_model = self._event_to_entity_map.get(event.event_type,
                                                 self._default_entity)

    event_entity = entity_model(event_type=event.event_type)
    for key, val in asdict(event).items():
      setattr(event_entity, key, val)
    return event_entity

  def _from_entity(self, entity: data_types.Model) -> Event:
    """Converts a Datastore entity into an event object."""
    if not hasattr(entity, 'event_type'):
      raise TypeError('Datastore model should contain an event_type.')

    event_type = entity.event_type  # type: ignore
    event_class = _EVENT_TYPE_CLASSES.get(event_type, None)
    if event_class is None:
      event = Event(event_type=event_type)
    else:
      event = event_class()
    for key, val in entity.to_dict().items():
      if hasattr(event, key):
        setattr(event, key, val)
    return event

  def serialize_event(self, event: Event) -> data_types.Model | None:
    """Converts an event object into the Datastore entity."""
    try:
      event_entity = self._to_entity(event)
      return event_entity
    except:
      logs.error(
          f'Error serializing event of type {event.event_type} to Datastore.')
    return None

  def deserialize_event(self, entity: data_types.Model) -> Event | None:
    """Converts a Datastore entity into an event object, if possible."""
    try:
      event = self._from_entity(entity)
      return event
    except:
      logs.error('Error deserializing Datastore entity to event.')
    return None

  def store_event(self, event: Event) -> str | int | None:
    """Stores a Datastore entity and returns its ID."""
    entity = self.serialize_event(event)
    if entity is None:
      return None
    try:
      entity.put()
      return entity.key.id()
    except:
      logs.error('Error storing Datastore event entity.')
    return None

  def get_event(self, event_id: str | int,
                event_type: str | None = None) -> Event | None:
    """Retrieve an event from a Datastore entity id."""
    entity_kind = self._event_to_entity_map.get(event_type,
                                                self._default_entity)
    event_entity = data_handler.get_entity_by_type_and_id(entity_kind, event_id)
    if event_entity is None:
      logs.error(f'Event entity {event_id} not found.')
      return None

    event = self.deserialize_event(event_entity)
    return event


_repository: IEventRepository | None = None


def config_repository() -> None:
  """Config the repository used to handle and store events."""
  global _repository
  # Any other repository implementations should be added here
  # based on the project config.
  _repository = NDBEventRepository()


def get_repository() -> IEventRepository | None:
  """Return the repository interface to handle and store events."""
  if not _repository:
    config_repository()
  return _repository


def emit(event: Event) -> str | int | None:
  """Emit an event to be stored in the configured repository."""
  repository = get_repository()
  if repository is None:
    return None

  event_id = repository.store_event(event)
  return event_id
