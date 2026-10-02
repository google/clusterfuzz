# Copyright 2026 Google LLC
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
"""A fake Swarming pRPC server for integration tests.

Spins up a WireMock container on 127.0.0.1:9014 serving the Swarming v2 Tasks
pRPC endpoints used by ClusterFuzz:
  - POST /prpc/swarming.v2.Tasks/CountTasks
  - POST /prpc/swarming.v2.Tasks/NewTask

Serves static responses matched against request paths, headers, and JSON body
patterns.

Usage:
  with swarming_server.swarming_emulator() as swarming:
    swarming.set_task_count(swarming_pb2.QUERY_PENDING, 5)
    ...
"""

# pylint: disable=no-member

import contextlib
from datetime import datetime
from datetime import timezone
from http import HTTPStatus

from google.protobuf import json_format
from google.protobuf import timestamp_pb2
from wiremock.client import HttpMethods
from wiremock.client import Mapping
from wiremock.client import MappingRequest
from wiremock.client import MappingResponse
from wiremock.client import Mappings
from wiremock.constants import Config
from wiremock.testing.testcontainer import wiremock_container

from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.swarming import constants
from test_suites.fixtures.common import wiremock_faults

_DEFAULT_PORT = 9014
_DEFAULT_ADDRESS = f'127.0.0.1:{_DEFAULT_PORT}'
_DEFAULT_TASK_ID = 'fake-task-1'
_HIGHEST_PRIORITY = 1

_JSON_HEADERS = {
    'Content-Type': 'application/json; charset=utf-8',
}
_TEXT_HEADERS = {
    'Content-Type': 'text/plain; charset=utf-8',
}

_ALL_QUERY_STATES: list[swarming_pb2.StateQuery.ValueType] = [
    swarming_pb2.QUERY_PENDING,
    swarming_pb2.QUERY_RUNNING,
    swarming_pb2.QUERY_PENDING_RUNNING,
    swarming_pb2.QUERY_COMPLETED,
    swarming_pb2.QUERY_COMPLETED_SUCCESS,
    swarming_pb2.QUERY_COMPLETED_FAILURE,
    swarming_pb2.QUERY_EXPIRED,
    swarming_pb2.QUERY_TIMED_OUT,
    swarming_pb2.QUERY_BOT_DIED,
    swarming_pb2.QUERY_CANCELED,
    swarming_pb2.QUERY_ALL,
    swarming_pb2.QUERY_DEDUPED,
    swarming_pb2.QUERY_KILLED,
    swarming_pb2.QUERY_NO_RESOURCE,
    swarming_pb2.QUERY_CLIENT_ERROR,
]


def _now_timestamp() -> timestamp_pb2.Timestamp:
  """Returns the current UTC time as a protobuf Timestamp."""
  timestamp = timestamp_pb2.Timestamp()
  timestamp.FromDatetime(datetime.now(timezone.utc))
  return timestamp


def _register_mapping(admin_url: str, mapping: Mapping) -> None:
  """Registers a single Mapping with the WireMock admin API."""
  Config.base_url = admin_url
  Mappings.create_mapping(mapping)


def _add_auth_filter(admin_url: str) -> None:
  """Rejects requests missing a non-empty Bearer token with HTTP 401."""
  unauthenticated_header_matchers = [
      {
          'Authorization': {
              'absent': True
          }
      },
      {
          'Authorization': {
              'doesNotMatch': r'^Bearer \S+.*$'
          }
      },
  ]
  for headers in unauthenticated_header_matchers:
    _register_mapping(
        admin_url,
        Mapping(
            priority=_HIGHEST_PRIORITY,
            persistent=True,
            request=MappingRequest(
                method=HttpMethods.ANY,
                url_pattern=r'/prpc/.*',
                headers=headers,
            ),
            response=MappingResponse(
                status=HTTPStatus.UNAUTHORIZED,
                body='Unauthorized\n',
                headers=_TEXT_HEADERS,
            ),
        ),
    )


def _add_count_tasks(
    admin_url: str,
    task_state: swarming_pb2.StateQuery.ValueType,
    count: int,
    persistent: bool = False,
) -> None:
  """Adds a Mapping serving a TasksCount pRPC response for task_state."""
  # TODO(fuzzing-infra): Support filtering task counts by tags
  # (e.g. pool, os).
  response_proto = swarming_pb2.TasksCount(count=count, now=_now_timestamp())
  body = constants.XSSI_PREFIX + json_format.MessageToJson(response_proto)

  if task_state == swarming_pb2.QUERY_PENDING:
    matcher = {'expression': '$.state', 'absent': True}
  else:
    state_name = swarming_pb2.StateQuery.Name(task_state)
    matcher = {'expression': '$.state', 'equalTo': state_name}

  _register_mapping(
      admin_url,
      Mapping(
          persistent=persistent,
          request=MappingRequest(
              method=HttpMethods.POST,
              url_path=constants.COUNT_TASKS_ENDPOINT,
              body_patterns=[{
                  'matchesJsonPath': matcher
              }],
          ),
          response=MappingResponse(
              status=HTTPStatus.OK,
              body=body,
              headers=_JSON_HEADERS,
          ),
      ),
  )


def _add_new_task(
    admin_url: str,
    task_id: str = _DEFAULT_TASK_ID,
    persistent: bool = False,
) -> None:
  """Adds a Mapping serving a TaskRequestMetadataResponse for NewTask."""
  now = _now_timestamp()
  response_proto = swarming_pb2.TaskRequestMetadataResponse(
      task_id=task_id,
      request=swarming_pb2.TaskRequestResponse(
          task_id=task_id,
          created_ts=now,
      ),
      task_result=swarming_pb2.TaskResultResponse(
          task_id=task_id,
          created_ts=now,
          state=swarming_pb2.PENDING,
      ),
  )
  body = constants.XSSI_PREFIX + json_format.MessageToJson(response_proto)

  _register_mapping(
      admin_url,
      Mapping(
          persistent=persistent,
          request=MappingRequest(
              method=HttpMethods.POST,
              url_path=constants.NEW_TASK_ENDPOINT,
          ),
          response=MappingResponse(
              status=HTTPStatus.OK,
              body=body,
              headers=_JSON_HEADERS,
          ),
      ),
  )


class SwarmingEmulatorClient:
  """Facade for controlling a running WireMock Swarming emulator."""

  def __init__(
      self,
      hostport: str = _DEFAULT_ADDRESS,
      fault_injector: wiremock_faults.FaultInjector | None = None,
  ):
    """Registers the baseline stubs on a running emulator.

    Args:
      hostport: The emulator's 'host:port'.
      fault_injector: Injector for faults. Defaults to a WireMockFaultInjector
        targeting this emulator.
    """
    self.hostport = hostport
    self.admin_url = f'http://{hostport}/__admin'
    self._fault_injector = (
        fault_injector or wiremock_faults.WireMockFaultInjector(
            admin_url=self.admin_url,
            response_headers=_TEXT_HEADERS,
        ))
    self._task_counts: dict[swarming_pb2.StateQuery.ValueType, int] = {
        task_state: 0 for task_state in _ALL_QUERY_STATES
    }

    self._setup_baseline_mappings()

  @property
  def url(self) -> str:
    """Returns the base HTTP URL of the emulator."""
    return f'http://{self.hostport}'

  def _setup_baseline_mappings(self) -> None:
    """Registers persistent auth, zero-count, and NewTask baseline stubs."""
    _add_auth_filter(self.admin_url)
    for task_state in _ALL_QUERY_STATES:
      _add_count_tasks(self.admin_url, task_state, count=0, persistent=True)
    _add_new_task(self.admin_url, persistent=True)

  def reset_mappings(self) -> None:
    """Clears all non-persistent mappings and resets task counts to 0."""
    for task_state in _ALL_QUERY_STATES:
      self._task_counts[task_state] = 0
    Config.base_url = self.admin_url
    Mappings.reset_mappings()

  def set_task_count(self, task_state: swarming_pb2.StateQuery.ValueType,
                     count: int) -> None:
    """Sets the number of tasks returned by CountTasks for task_state.

    Args:
      task_state: The StateQuery to serve the count for.
      count: The task count to serve.

    Raises:
      ValueError: If task_state is unsupported or count is negative.
    """
    if task_state not in self._task_counts:
      raise ValueError(f'Unsupported Swarming StateQuery: {task_state}')
    if count < 0:
      raise ValueError(f'Task count must be >= 0, got {count}')

    self._task_counts[task_state] = count
    _add_count_tasks(self.admin_url, task_state, count=count, persistent=False)

  def get_task_count(self,
                     task_state: swarming_pb2.StateQuery.ValueType) -> int:
    """Returns the current configured task count for task_state.

    Args:
      task_state: The StateQuery to look up.

    Returns:
      The count last set for task_state, or 0.

    Raises:
      ValueError: If task_state is unsupported.
    """
    if task_state not in self._task_counts:
      raise ValueError(f'Unsupported Swarming StateQuery: {task_state}')
    return self._task_counts[task_state]

  def inject_fault(
      self,
      endpoint: str,
      status: int = HTTPStatus.INTERNAL_SERVER_ERROR,
      times: int = 1,
      delay_seconds: float = 0,
      method: str = HttpMethods.POST,
  ) -> None:
    """Makes the emulator fail a Swarming pRPC endpoint.

    Args:
      endpoint: A Swarming pRPC endpoint path (e.g.
        constants.COUNT_TASKS_ENDPOINT or constants.NEW_TASK_ENDPOINT).
      status: The HTTP status to return.
      times: How many requests to affect. 0 means indefinitely until
        clear_faults() or reset_mappings() is called.
      delay_seconds: How long the emulator should stall before responding.
      method: HTTP method to match (defaults to HttpMethods.POST).

    Raises:
      ValueError: If times is negative.
    """
    self._fault_injector.inject_fault(
        path=endpoint,
        status=status,
        times=times,
        delay_seconds=delay_seconds,
        method=method,
    )

  def clear_faults(self) -> None:
    """Removes every injected fault mapping while keeping task counts."""
    self._fault_injector.clear_faults()


# TODO(b/555371204): Make this into real pytest fixtures
@contextlib.contextmanager
def swarming_emulator(hostport: str = _DEFAULT_ADDRESS):
  """Yields a running WireMock Swarming emulator bound to hostport.

  Args:
    hostport: The 'host:port' to bind the emulator to.

  Yields:
    A SwarmingEmulatorClient for the running emulator.

  Raises:
    WireMockContainerException: If the container fails to start, e.g. because
      the port is already taken.
  """
  _, _, port = hostport.partition(':')

  with wiremock_container(
      secure=False, verify_ssl_certs=False, start=False) as wm:
    wm.with_bind_ports(wm.http_server_port, int(port))
    with wm:
      yield SwarmingEmulatorClient(hostport=hostport)
