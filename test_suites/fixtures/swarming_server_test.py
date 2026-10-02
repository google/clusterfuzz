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
"""Tests for the fake Swarming pRPC server."""

# pylint: disable=no-member

from http import HTTPStatus
import os
from unittest import mock

from google.protobuf import json_format
import pytest
import requests
from wiremock.testing.testcontainer import WireMockContainerException

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.protos import swarming_pb2
from clusterfuzz._internal.swarming import constants
from clusterfuzz._internal.swarming.api import SwarmingApi
from clusterfuzz._internal.swarming.api import SwarmingApiError
from test_suites.fixtures import swarming_server

# SwarmingApi sends every request through utils.post_url, which retries a
# failed request this many times after the first attempt.
_DEFAULT_RETRIES = utils.URL_REQUEST_RETRIES
_FAKE_TOKEN = 'fake-swarming-token'


def _sample_new_task_request(name: str = 'fuzz-task-1',
                            ) -> swarming_pb2.NewTaskRequest:
  """Builds a sample NewTaskRequest protobuf for testing."""
  return swarming_pb2.NewTaskRequest(
      name=name,
      priority=1,
      realm='realm-name',
      service_account='test-clusterfuzz-service-account-email',
      task_slices=[
          swarming_pb2.TaskSlice(
              expiration_secs=86400,
              properties=swarming_pb2.TaskProperties(
                  command=['./linux_entry_point.sh'],
                  dimensions=[
                      swarming_pb2.StringPair(key='os', value='Linux'),
                      swarming_pb2.StringPair(key='pool', value='pool-name'),
                  ],
                  execution_timeout_secs=3600,
              ),
          )
      ],
  )


def _raw_count_tasks(url: str) -> requests.Response:
  """Sends a single authenticated CountTasks request to url, without retries.

  Args:
    url: The full CountTasks endpoint URL, including the pRPC path.
  """
  return requests.post(
      url,
      data=json_format.MessageToJson(swarming_pb2.TasksCountRequest()),
      headers={
          'Authorization': f'Bearer {_FAKE_TOKEN}',
          'Content-Type': 'application/json',
      },
      timeout=5,
  )


def _parse_tasks_count(response: requests.Response) -> swarming_pb2.TasksCount:
  """Parses a raw CountTasks response body, dropping the pRPC XSSI prefix."""
  body = response.text.removeprefix(constants.XSSI_PREFIX)
  return json_format.Parse(body, swarming_pb2.TasksCount())


class TestSwarmingEmulator:
  """Integration tests for the fake Swarming pRPC server."""

  api: SwarmingApi | None = None

  # TODO(b/555371391): Remove this setup once we have our own butler.py command
  @pytest.fixture(scope='class', autouse=True)
  @classmethod
  def _emulator(cls):
    """Starts the Swarming WireMock emulator for the test class."""
    os.environ['CONFIG_DIR_OVERRIDE'] = './configs/test'
    os.environ['PY_UNITTESTS'] = 'True'
    with swarming_server.swarming_emulator() as emulator:
      cls.swarming_server = emulator
      yield

  @pytest.fixture(autouse=True)
  def _setup_test(self, monkeypatch):
    """Configures fake credentials and resets emulator state after each test."""
    monkeypatch.setattr(retry, 'sleep', lambda _: None)
    fake_creds = mock.MagicMock(token=_FAKE_TOKEN, valid=True)
    monkeypatch.setattr(
        credentials,
        'get_scoped_service_account_credentials',
        lambda scopes: fake_creds,
    )
    self.api = SwarmingApi.create()
    yield
    self.swarming_server.reset_mappings()

  def test_default_task_counts_are_zero(self):
    """Verifies that all StateQuery counts start at 0."""
    for query in (
        swarming_pb2.QUERY_PENDING,
        swarming_pb2.QUERY_RUNNING,
        swarming_pb2.QUERY_PENDING_RUNNING,
        swarming_pb2.QUERY_COMPLETED,
        swarming_pb2.QUERY_EXPIRED,
        swarming_pb2.QUERY_ALL,
    ):
      request = swarming_pb2.TasksCountRequest(
          state=query, tags=['pool:pool-name'])
      response = self.api.count_tasks(request)
      assert response.count == 0

  def test_set_and_query_task_counts_across_states(self):
    """Verifies that CountTasks answers each StateQuery with the count set for
    it through set_task_count()."""
    # Distinct counts, so a stub answering the wrong StateQuery gets caught.
    expected_counts = {
        swarming_pb2.QUERY_PENDING: 4,
        swarming_pb2.QUERY_RUNNING: 3,
        swarming_pb2.QUERY_PENDING_RUNNING: 7,
        swarming_pb2.QUERY_COMPLETED: 5,
        swarming_pb2.QUERY_EXPIRED: 2,
        swarming_pb2.QUERY_BOT_DIED: 1,
    }
    for query, count in expected_counts.items():
      self.swarming_server.set_task_count(query, count)

    for query, expected_count in expected_counts.items():
      request = swarming_pb2.TasksCountRequest(state=query)
      assert self.api.count_tasks(request).count == expected_count

  def test_push_task_returns_valid_task_metadata(self):
    """Verifies that NewTask returns a valid TaskRequestResponse."""
    response = self.api.push_task(_sample_new_task_request('fuzz-task-1'))
    assert response.task_id == 'fake-task-1'
    assert response.HasField('created_ts')

  def test_reset_mappings_resets_counts_and_clears_faults(self):
    """Verifies that reset_mappings() drops set_task_count() overrides and
    injected faults: CountTasks serves 0 again and NewTask succeeds."""
    self.swarming_server.set_task_count(swarming_pb2.QUERY_PENDING, 5)
    self.swarming_server.inject_fault(
        constants.NEW_TASK_ENDPOINT,
        status=HTTPStatus.SERVICE_UNAVAILABLE,
        times=0,
    )

    self.swarming_server.reset_mappings()

    pending = self.api.count_tasks(
        swarming_pb2.TasksCountRequest(state=swarming_pb2.QUERY_PENDING))
    assert pending.count == 0
    task = self.api.push_task(_sample_new_task_request())
    assert task.task_id == 'fake-task-1'

  def test_requests_without_bearer_token_are_rejected_with_401(
      self, monkeypatch):
    """Verifies that missing or empty Authorization headers return HTTP 401."""
    raw_response = requests.post(
        f'{self.swarming_server.url}{constants.COUNT_TASKS_ENDPOINT}',
        json={},
        timeout=5,
    )
    assert raw_response.status_code == HTTPStatus.UNAUTHORIZED

    monkeypatch.setattr(
        credentials,
        'get_scoped_service_account_credentials',
        lambda scopes: None,
    )
    with pytest.raises(SwarmingApiError):
      self.api.count_tasks(swarming_pb2.TasksCountRequest())

    with pytest.raises(SwarmingApiError):
      self.api.push_task(_sample_new_task_request())

  def test_fault_fails_every_attempt_but_the_last(self):
    """Verifies that a CountTasks fault injected with times=_DEFAULT_RETRIES
    fails exactly that many requests, so the last of SwarmingApi's attempts is
    served the configured count.

    Sends raw requests because SwarmingApi's retries would hide a fault that
    never fires, e.g. one shadowed by a set_task_count() stub added after it.
    """
    self.swarming_server.set_task_count(swarming_pb2.QUERY_PENDING, 9)
    self.swarming_server.inject_fault(
        constants.COUNT_TASKS_ENDPOINT,
        status=HTTPStatus.INTERNAL_SERVER_ERROR,
        times=_DEFAULT_RETRIES,
    )

    count_tasks_url = (
        f'{self.swarming_server.url}{constants.COUNT_TASKS_ENDPOINT}')
    responses = [
        _raw_count_tasks(count_tasks_url) for _ in range(_DEFAULT_RETRIES + 1)
    ]

    assert [response.status_code for response in responses] == (
        [HTTPStatus.INTERNAL_SERVER_ERROR] * _DEFAULT_RETRIES + [HTTPStatus.OK])
    assert _parse_tasks_count(responses[-1]).count == 9

  def test_count_tasks_raises_once_every_attempt_fails(self):
    """Verifies that count_tasks() stops retrying and raises SwarmingApiError
    when all of its attempts fail."""
    self.swarming_server.inject_fault(
        constants.COUNT_TASKS_ENDPOINT,
        status=HTTPStatus.INTERNAL_SERVER_ERROR,
        times=_DEFAULT_RETRIES + 1,
    )

    with pytest.raises(SwarmingApiError):
      self.api.count_tasks(swarming_pb2.TasksCountRequest())

  def test_indefinite_fault_is_not_used_up_by_retries(self):
    """Verifies that a fault injected with times=0 keeps failing requests after
    a push_task() call has exhausted all of its attempts."""
    self.swarming_server.inject_fault(
        constants.NEW_TASK_ENDPOINT,
        status=HTTPStatus.SERVICE_UNAVAILABLE,
        times=0,
    )

    with pytest.raises(SwarmingApiError):
      self.api.push_task(_sample_new_task_request())
    # A fault with times=_DEFAULT_RETRIES + 1 would be used up by now.
    with pytest.raises(SwarmingApiError):
      self.api.push_task(_sample_new_task_request())

  def test_clear_faults_keeps_task_counts(self):
    """Verifies that clear_faults(), unlike reset_mappings(), only removes the
    injected faults: NewTask succeeds again and set_task_count() overrides are
    still served."""
    self.swarming_server.set_task_count(swarming_pb2.QUERY_PENDING, 3)
    self.swarming_server.inject_fault(
        constants.NEW_TASK_ENDPOINT,
        status=HTTPStatus.SERVICE_UNAVAILABLE,
        times=0,
    )

    self.swarming_server.clear_faults()

    task = self.api.push_task(_sample_new_task_request())
    assert task.task_id == 'fake-task-1'
    pending = self.api.count_tasks(
        swarming_pb2.TasksCountRequest(state=swarming_pb2.QUERY_PENDING))
    assert pending.count == 3

  def test_invalid_arguments_raise_value_error(self):
    """Verifies that set_task_count, get_task_count, and inject_fault raise
    ValueError when given an unknown StateQuery or a negative count."""
    with pytest.raises(ValueError):
      self.swarming_server.set_task_count(999, 1)

    with pytest.raises(ValueError):
      self.swarming_server.set_task_count(swarming_pb2.QUERY_PENDING, -1)

    with pytest.raises(ValueError):
      self.swarming_server.get_task_count(999)

    with pytest.raises(ValueError):
      self.swarming_server.inject_fault(
          constants.COUNT_TASKS_ENDPOINT, times=-1)

  def test_a_second_emulator_cannot_take_a_held_address(self):
    """Verifies that starting a second emulator on the default port fails."""
    with pytest.raises(WireMockContainerException):
      with swarming_server.swarming_emulator():
        pass
