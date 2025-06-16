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

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def _get_datetime_now():
  """Returns the current datetime (useful for testing)."""
  return datetime.datetime.now()


class EventTypes:
  """Specific event types."""
  TESTCASE_CREATION = 'testcase_creation'
  TESTCASE_REJECTION = 'testcase_rejection'


class TestcaseOrigin:
  """Testcase creation origins."""
  MANUAL_UPLOAD = 'manual_upload'
  FUZZ_TASK = 'fuzz_task'
  CORPUS_PRUNING = 'corpus_pruning'


class RejectionReason:
  """Explanation for the testcase rejection values."""
  ANALYZE_NO_REPRO = 'analyze_no_repro'
  ANALYZE_FLAKE_ON_FIRST_ATTEMPT = 'analyze_flake_on_first_attempt'


@dataclass(kw_only=True)
class Event:
  """Base class for ClusterFuzz events."""
  # Event type (required if a generic event class is used).
  event_type: str
  # Source location (optional).
  source: str | None = None
  # Timestamp when the event was created.
  timestamp: datetime.datetime = field(init=False)

  # Common metadata retrieved from running environment.
  clusterfuzz_version: str | None = field(init=False, default=None)
  clusterfuzz_config_version: str | None = field(init=False, default=None)
  instance_id: str | None = field(init=False, default=None)
  operating_system: str | None = field(init=False, default=None)
  os_version: str | None = field(init=False, default=None)

  def __post_init__(self, **kwargs):
    del kwargs
    self.timestamp = _get_datetime_now()
    common_ctx = logs.get_common_log_context()
    for key, val in common_ctx.items():
      setattr(self, key, val)


@dataclass(kw_only=True)
class BaseTestcaseEvent(Event):
  """Base class for testcase-related events."""
  # Testcase entity (only used in init to set the event data).
  testcase: InitVar[data_types.Testcase | None] = None

  # Testcase metadata (retrieved from the testcase entity, if available).
  testcase_id: int | None = field(init=False, default=None)
  fuzzer: str | None = field(init=False, default=None)
  job: str | None = field(init=False, default=None)
  crash_revision: int | None = field(init=False, default=None)

  def __post_init__(self, testcase=None, **kwargs):
    if testcase is not None:
      self.testcase_id = testcase.key.id()
      self.fuzzer = testcase.fuzzer_name
      self.job = testcase.job_type
      self.crash_revision = testcase.crash_revision
    return super().__post_init__(**kwargs)


@dataclass(kw_only=True)
class BaseTaskEvent(Event):
  """Base class for task-related events."""
  # Task ID retrieved from environment var (if not directly set).
  task_id: str | None = None
  # Task name retrieved from environment var (if not directly set).
  task_name: str | None = None

  def __post_init__(self, **kwargs):
    if self.task_id is None:
      self.task_id = environment.get_value('CF_TASK_ID', None)
    if self.task_name is None:
      self.task_name = environment.get_value('CF_TASK_NAME', None)
    return super().__post_init__(**kwargs)


@dataclass(kw_only=True)
class TestcaseCreationEvent(BaseTestcaseEvent, BaseTaskEvent):
  """Testcase creation event."""
  event_type: str = field(default=EventTypes.TESTCASE_CREATION, init=False)
  # Either manual upload, fuzz task or corpus pruning.
  creation_origin: str | None = None
  # User email, if testcase manually uploaded.
  uploader: str | None = None


@dataclass(kw_only=True)
class TestcaseRejectionEvent(BaseTestcaseEvent, BaseTaskEvent):
  """Testcase rejection event."""
  event_type: str = field(default=EventTypes.TESTCASE_REJECTION, init=False)
  # Explanation for the testcase rejection, e.g., analyze_flake_on_first_attempt
  # or analyze_no_repro or triage_duplicate_testcase.
  rejection_reason: str | None = None


# Mapping of specific event types to their data classes.
_EVENT_TYPE_CLASSES = {
    EventTypes.TESTCASE_CREATION: TestcaseCreationEvent,
    EventTypes.TESTCASE_REJECTION: TestcaseRejectionEvent,
}


class EventHandler(ABC):
  """Base class that defines an event handler.
  
  Handlers represent any class responsible for executing an action when an event
  occurs. These may be the repository to persist the events, the issue tracker
  to send a notification in the related bug, and so on.
  """

  @abstractmethod
  def emit(self, event: Event) -> Any:
    """Emit event."""


class IEventRepository(ABC):
  """Event repository abstract class (interface).

  This class is responsable for defining the expected operations for event
  storage and retrieval in a repository/database.
  All concrete event repositories must implement these methods.
  """

  @abstractmethod
  def store_event(self, event: Event) -> str | int | None:
    """Save an event into the underlying database and return its ID."""

  @abstractmethod
  def get_event(self, event_id: str | int,
                event_type: str | None = None) -> Event | None:
    """Retrieve an event from the underlying database and return it."""


class NDBEventRepository(IEventRepository, EventHandler):
  """Implements the event repository for Datastore.
  
  Handles conversion between Event objects and Datastore entities. If a new
  Datastore entity model is needed, it relies on mapping the event types to
  the correct entity.
  """
  # Maps `event_type` to a Datastore model.
  # For now, only testcase lifecycle events are being traced.
  _event_to_entity_map = {}
  _default_entity = data_types.TestcaseLifecycleEvent

  def _serialize_event(self, event: Event) -> data_types.Model | None:
    """Converts an event object into the Datastore entity."""
    try:
      entity_model = self._event_to_entity_map.get(event.event_type,
                                                   self._default_entity)
      event_entity = entity_model(event_type=event.event_type)
      for key, val in asdict(event).items():
        setattr(event_entity, key, val)
      return event_entity
    except:
      logs.error(f'Error serializing event to Datastore: {event}.')
    return None

  def _deserialize_event(self, entity: data_types.Model) -> Event | None:
    """Converts a Datastore entity into an event object, if possible."""
    try:
      if not hasattr(entity, 'event_type'):
        raise TypeError(
            f'Datastore entity should contain an event_type: {entity.key}.')

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
    except:
      logs.error(f'Error deserializing Datastore entity to event: {entity}.')
    return None

  def store_event(self, event: Event) -> int | None:
    """Stores a Datastore entity and returns its ID."""
    entity = self._serialize_event(event)
    if entity is None:
      return None
    try:
      entity.put()
      return entity.key.id()
    except:
      logs.error(f'Error storing Datastore event entity: {entity}.')
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

    event = self._deserialize_event(event_entity)
    return event

  def emit(self, event: Event) -> Any:
    """Emit an event by persisting it to Datastore."""
    return self.store_event(event)


_handlers: list[EventHandler] | None = None


def get_repository() -> IEventRepository | None:
  """Return the repository used to handle and persist events."""
  # Any other repository implementations should define here the project config
  # event storage name.
  storage_cfg = local_config.ProjectConfig().get('events.storage')
  repository = None
  if storage_cfg == 'datastore':
    repository = NDBEventRepository()
  else:
    logs.warning('Events storage in project config not found/available.')
  return repository


def config_handlers() -> None:
  """Configure event handlers based on project config."""
  global _handlers
  _handlers = []

  # Handlers config should be added here.
  repository = get_repository()
  event_handlers = [
      repository,
  ]

  for handler in event_handlers:
    if handler is None:
      continue
    if not isinstance(handler, EventHandler):
      raise TypeError(
          f'Event handler should extend EventHandler class: {type(handler)}.')
    _handlers.append(handler)


def get_handlers() -> list[EventHandler] | None:
  """Retrieve the list of configured event handlers."""
  if _handlers is None:
    config_handlers()
  return _handlers


def emit(event: Event) -> None:
  """Emit an event using the configured handlers.

  Actions taken with emit depend on the project configuration. Mainly, it
  should persist the event in a storage and send notifications in the issue
  tracker, if available.
  """
  handlers = get_handlers()
  if handlers is None:
    logs.error(
        f'Failed setting event handlers. Event will not be processed: {event}.')
    return

  # Log as warning in case `handlers` is empty, since it could mean that the
  # project config disabled all event handlers (not necessarily an error).
  if not handlers:
    logs.warning('No event handlers were registered for this project.')
    return

  for handler in handlers:
    handler.emit(event)
