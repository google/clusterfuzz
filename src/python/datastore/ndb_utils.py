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

from base import utils
from datastore import ndb_patcher

DEFAULT_BATCH_SIZE = 1000


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
  if isinstance(query, ndb_patcher.Query):
    # Not necessary with ndb_patcher.Query.
    for result in query.iter(**kwargs):
      yield result

    return

  batch_size = kwargs.pop('batch_size', DEFAULT_BATCH_SIZE)
  kwargs['batch_size'] = batch_size

  while True:
    entities, cursor, more = query.fetch_page(batch_size, **kwargs)
    if not entities:
      break

    for entity in entities:
      yield entity

    kwargs['start_cursor'] = cursor

    if not more:
      # No more results to process, bail out.
      break

    # Free up some memory in between batches.
    del entities
    utils.python_gc()
