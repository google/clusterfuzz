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
"""Shared WireMock error injection for service emulators."""

import abc
from http import HTTPStatus
import uuid

from wiremock.client import HttpMethods
from wiremock.client import Mapping
from wiremock.client import MappingRequest
from wiremock.client import MappingResponse
from wiremock.client import Mappings
from wiremock.constants import Config

_DEFAULT_RESPONSE_HEADERS = {
    'Content-Type': 'text/plain; charset=utf-8',
}


class ErrorInjector(abc.ABC):
  """Interface for injecting and clearing HTTP errors in service emulators."""

  @abc.abstractmethod
  def inject_error(
      self,
      path: str,
      status: int = HTTPStatus.INTERNAL_SERVER_ERROR,
      times: int = 1,
      delay_seconds: float = 0,
      method: str = HttpMethods.ANY,
  ) -> None:
    """Makes the emulator fail requests to path."""

  @abc.abstractmethod
  def clear_errors(self) -> None:
    """Removes every injected error."""


class WireMockErrorInjector(ErrorInjector):
  """Injects and clears HTTP errors in a running WireMock container."""

  def __init__(
      self,
      admin_url: str,
      path_prefix: str = '',
      request_headers: dict | None = None,
      response_headers: dict | None = None,
  ):
    self._admin_url = admin_url
    self._path_prefix = path_prefix
    self._request_headers = request_headers
    self._response_headers = response_headers or _DEFAULT_RESPONSE_HEADERS

  def _create_mapping(self, mapping: Mapping) -> None:
    Config.base_url = self._admin_url
    Mappings.create_mapping(mapping)

  def _all_mappings(self) -> list[Mapping]:
    Config.base_url = self._admin_url
    return Mappings.retrieve_all_mappings().mappings

  def _delete_mapping(self, mapping_id: str) -> None:
    Config.base_url = self._admin_url
    Mappings.delete_mapping(mapping_id)

  def _error_mapping(
      self,
      path: str,
      status_code: int,
      method: str = HttpMethods.ANY,
      delay_ms: int | None = None,
      scenario_name: str | None = None,
      required_state: str | None = None,
      new_state: str | None = None,
  ) -> Mapping:
    """Returns a non-persistent Mapping that injects an HTTP error for path."""
    request_kwargs: dict = {
        'method': method,
        'url_path': f'{self._path_prefix}{path}',
    }
    if self._request_headers is not None:
      request_kwargs['headers'] = self._request_headers

    response_kwargs: dict = {
        'status': status_code,
        'body': f'injected error for {path}\n',
        'headers': self._response_headers,
    }
    if delay_ms is not None:
      response_kwargs['fixed_delay_milliseconds'] = delay_ms

    return Mapping(
        persistent=False,
        scenario_name=scenario_name,
        required_scenario_state=required_state,
        new_scenario_state=new_state,
        metadata={
            'error': True,
            'error_path': path,
        },
        request=MappingRequest(**request_kwargs),
        response=MappingResponse(**response_kwargs),
    )

  def _remove_existing_errors_for_path(self, path: str) -> None:
    """Removes any active error mappings targeting path."""
    for mapping in self._all_mappings():
      metadata = mapping.metadata or {}
      if metadata.get('error') and metadata.get('error_path') == path:
        self._delete_mapping(mapping.id)

  def inject_error(
      self,
      path: str,
      status: int = HTTPStatus.INTERNAL_SERVER_ERROR,
      times: int = 1,
      delay_seconds: float = 0,
      method: str = HttpMethods.ANY,
  ) -> None:
    """Makes the emulator fail requests to path.

    Args:
      path: Endpoint path (relative to path_prefix if configured).
      status: The HTTP status to return.
      times: How many requests to affect. 0 means indefinitely until
        clear_errors() is called.
      delay_seconds: How long the emulator should stall before responding.
      method: HTTP method to match (defaults to HttpMethods.ANY).
    """
    status_code = status or HTTPStatus.INTERNAL_SERVER_ERROR
    delay_ms = int(delay_seconds * 1000) if delay_seconds > 0 else None
    if times < 0:
      raise ValueError(f'times must be >= 0, got {times}')

    self._remove_existing_errors_for_path(path)

    if times == 0:
      self._create_mapping(
          self._error_mapping(
              path, status_code, method=method, delay_ms=delay_ms))
      return

    scenario_name = f'error-{path}-{uuid.uuid4().hex}'
    for i in range(times):
      self._create_mapping(
          self._error_mapping(
              path,
              status_code,
              method=method,
              delay_ms=delay_ms,
              scenario_name=scenario_name,
              required_state='Started' if i == 0 else f'step_{i}',
              new_state=f'step_{i + 1}',
          ))

  def clear_errors(self) -> None:
    """Removes every injected error mapping."""
    for mapping in self._all_mappings():
      metadata = mapping.metadata or {}
      if metadata.get('error'):
        self._delete_mapping(mapping.id)
