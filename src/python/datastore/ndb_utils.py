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

from google.cloud import ndb

_GET_BATCH_SIZE = 1000
_MODIFY_BATCH_SIZE = 500


def is_true(boolean_prop):
  """Helper for boolean property filters to avoid lint errors."""
  return boolean_prop == True  # pylint: disable=g-explicit-bool-comparison,singleton-comparison


def is_false(boolean_prop):
  """Helper for boolean property filters to avoid lint errors."""
  return boolean_prop == False  # pylint: disable=g-explicit-bool-comparison,singleton-comparison


def get_all_from_model(model):
  """Get all results from a ndb.Model."""
  return get_all_from_query(model.query())


def get_all_from_query(query, **kwargs):
  """Return all entities based on the query by paging, to avoid query
  expirations on App Engine."""
  # TODO(ochang): Queries no longer expire with new NDB. Remove this and all
  # fix up callers.
  kwargs.pop('batch_size', None)  # No longer supported.
  for entity in query.iter(**kwargs):
    yield entity


def _gen_chunks(values, size):
  """Generate chunks of iterable."""
  values = list(values)
  for i in range(0, len(values), size):
    yield values[i:i + size]


def get_multi(keys):
  """Get multiple entities, working around a limitation in the NDB library with
  the maximum number of keys allowed."""
  result = []
  for chunk in _gen_chunks(keys, _GET_BATCH_SIZE):
    result.extend(ndb.get_multi(chunk))

  return result


def put_multi(entities):
  """Put multiple entities, working around a limitation in the NDB library with
  the maximum number of keys allowed."""
  result = []
  for chunk in _gen_chunks(entities, _MODIFY_BATCH_SIZE):
    result.extend(ndb.put_multi(chunk))

  return result


def delete_multi(keys):
  """Delete multiple entities, working around a limitation in the NDB library
  with the maximum number of keys allowed."""
  for chunk in _gen_chunks(keys, _MODIFY_BATCH_SIZE):
    ndb.delete_multi(chunk)
