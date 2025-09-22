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
"""Migrate fuzzer-based task events to the correct entity."""

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import events
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

_MIGRATE_FIELDS = [
    'timestamp', 'source', 'clusterfuzz_version', 'clusterfuzz_config_version',
    'instance_id', 'operating_system', 'os_version', 'task_id', 'task_name',
    'task_stage', 'task_status', 'task_outcome', 'task_job', 'task_fuzzer'
]

_BATCH_SIZE = 500
_DELETE_ALL = True


def execute(args):
  """Deletes/Migrates fuzzer-based task events."""
  del args
  environment.set_bot_environment()
  logs.configure('run_bot')

  task_event_type = events.EventTypes.TASK_EXECUTION
  task_names = ['corpus_pruning', 'fuzz']

  # If we choose to delete all entities from the old model.
  if _DELETE_ALL:
    total_deleted = 0
    for task_name in task_names:
      print(f'Started deleting for {task_name}.')
      query = data_types.TestcaseLifecycleEvent.query(
          data_types.TestcaseLifecycleEvent.event_type == task_event_type,
          data_types.TestcaseLifecycleEvent.task_name == task_name)

      keys_batch, next_cursor, more = query.fetch_page(
          _BATCH_SIZE, keys_only=True)
      while keys_batch:
        ndb.delete_multi(keys_batch)
        total_deleted += len(keys_batch)
        print(f"Deleted {len(keys_batch)} entities (Total: {total_deleted})")
        if not more:
          break
        if total_deleted >= 10000:
          break
        keys_batch, next_cursor, more = query.fetch_page(
            _BATCH_SIZE, keys_only=True, start_cursor=next_cursor)

    logs.info('Done deleting fuzzer-based task execution events!')
    return


# If we choose to migrate them into the new entity model.
  query = data_types.TestcaseLifecycleEvent.query(
      data_types.TestcaseLifecycleEvent.event_type == task_event_type,
      data_types.TestcaseLifecycleEvent.task_name.IN(task_names))
  to_update = []
  to_delete = []
  total_count = 0
  for event in ndb_utils.get_all_from_query(query):
    migrate_event = data_types.FuzzerTaskEvent(
        event_type=events.EventTypes.FUZZER_TASK_EXECUTION)
    for attr in _MIGRATE_FIELDS:
      setattr(migrate_event, attr, getattr(event, attr))
    to_update.append(migrate_event)
    to_delete.append(event.key)
    total_count += 1
    if len(to_update) == _BATCH_SIZE:
      logs.info(f'Migrated {total_count} fuzzer-based task events.')
      ndb_utils.put_multi(to_update)
      ndb_utils.delete_multi(to_delete)
      to_update = []
      to_delete = []
