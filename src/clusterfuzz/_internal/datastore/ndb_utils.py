# Copyright 2019 Google LLC
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
"""NDB utilities. Provides utility functions for NDB."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Iterator
from typing import Any
from typing import TypeVar

from google.cloud import ndb

_ModelT = TypeVar('_ModelT', bound=ndb.Model)
_T = TypeVar('_T')

_GET_BATCH_SIZE: int = 1000
_MODIFY_BATCH_SIZE: int = 500


def is_true(boolean_prop: Any) -> Any:
  """Helper for boolean property filters to avoid lint errors."""
  return boolean_prop == True  # pylint: disable=g-explicit-bool-comparison,singleton-comparison


def is_false(boolean_prop: Any) -> Any:
  """Helper for boolean property filters to avoid lint errors."""
  return boolean_prop == False  # pylint: disable=g-explicit-bool-comparison,singleton-comparison


def get_all_from_model(model: type[_ModelT]) -> Iterator[_ModelT]:
  """Get all results from a ndb.Model."""
  return get_all_from_query(model.query())


def get_all_from_query(query: ndb.Query, **kwargs: Any) -> Iterator[Any]:
  """Return all entities based on the query by paging, to avoid query
  expirations on App Engine."""
  # TODO(ochang): Queries no longer expire with new NDB. Remove this and all
  # fix up callers.
  kwargs.pop('batch_size', None)  # No longer supported.
  yield from query.iter(**kwargs)


def _gen_chunks(values: Iterable[_T], size: int) -> Iterator[list[_T]]:
  """Generate chunks of iterable."""
  values_list = list(values)
  for i in range(0, len(values_list), size):
    yield values_list[i:i + size]


def get_multi(keys: Iterable[ndb.Key]) -> list[Any]:
  """Get multiple entities, working around a limitation in the NDB library with
  the maximum number of keys allowed."""
  result = []
  for chunk in _gen_chunks(keys, _GET_BATCH_SIZE):
    result.extend(ndb.get_multi(chunk))

  return result


def put_multi(entities: Iterable[ndb.Model]) -> list[ndb.Key]:
  """Put multiple entities, working around a limitation in the NDB library with
  the maximum number of keys allowed."""
  result = []
  for chunk in _gen_chunks(entities, _MODIFY_BATCH_SIZE):
    result.extend(ndb.put_multi(chunk))

  return result


def delete_multi(keys: Iterable[ndb.Key]) -> None:
  """Delete multiple entities, working around a limitation in the NDB library
  with the maximum number of keys allowed."""
  for chunk in _gen_chunks(keys, _MODIFY_BATCH_SIZE):
    ndb.delete_multi(chunk)
