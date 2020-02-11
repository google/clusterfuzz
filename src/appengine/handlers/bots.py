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
"""Handlers for the bot list."""

import datetime

from base import tasks
from base import utils
from datastore import data_types
from datastore import ndb_utils
from handlers import base_handler
from libs import handler
from libs import helpers


def _get_alive_cutoff():
  """Get the time before which we consider bots to be dead."""
  seconds_to_wait_for_dead_bot = (
      tasks.TASK_LEASE_SECONDS + tasks.TASK_COMPLETION_BUFFER +
      data_types.HEARTBEAT_WAIT_INTERVAL)
  alive_cutoff = utils.utcnow() - datetime.timedelta(
      seconds=seconds_to_wait_for_dead_bot)
  return alive_cutoff


def _convert_heartbeats_to_dicts(heartbeats):
  """Format heartbeats for template."""
  alive_cutoff = _get_alive_cutoff()
  result = []
  for heartbeat in heartbeats:
    result.append({
        'bot_name':
            heartbeat.bot_name,
        'source_version':
            heartbeat.source_version,
        'task_payload':
            heartbeat.task_payload,
        'task_end_time':
            utils.utc_datetime_to_timestamp(heartbeat.task_end_time)
            if heartbeat.task_end_time else '',
        'last_beat_time':
            utils.utc_datetime_to_timestamp(heartbeat.last_beat_time)
            if heartbeat.last_beat_time else '',
        'alive':
            'alive' if heartbeat.last_beat_time > alive_cutoff else 'dead'
    })

  return result


def _get_host_workers_heartbeats():
  """Return host worker heartbeats."""
  page_size = 30

  query = data_types.HostWorkerAssignment.query()
  cursor = None

  while True:
    results, cursor, more = query.fetch_page(page_size, start_cursor=cursor)
    key_ids = [assignment.key.id() for assignment in results]
    if not key_ids:
      break

    worker_mapping = dict(
        (assignment.key.id(), assignment.worker_name) for assignment in results)

    for heartbeat in data_types.Heartbeat.query(
        data_types.Heartbeat.bot_name.IN(key_ids)):
      heartbeat.bot_name = '{host_name} ({worker_name})'.format(
          host_name=heartbeat.bot_name,
          worker_name=worker_mapping[heartbeat.bot_name])
      yield heartbeat

    if not more:
      break


class Handler(base_handler.Handler):
  """Handler that gets the bot list."""

  @handler.check_admin_access_if_oss_fuzz
  @handler.check_user_access(need_privileged_access=False)
  @handler.get(handler.HTML)
  def get(self):
    """Render the bot list HTML."""
    if utils.is_oss_fuzz():
      heartbeats = _get_host_workers_heartbeats()
    else:
      heartbeats = ndb_utils.get_all_from_model(data_types.Heartbeat)

    bots = _convert_heartbeats_to_dicts(heartbeats)
    self.render('bots.html', {
        'bots': bots,
    })


class DeadBotsHandler(base_handler.Handler):
  """Output dead bots as json."""

  @handler.get(handler.JSON)
  def get(self):
    """Render dead bots as json (used by automated scripts)."""

    # This a publicly exposed chromium-specific page.
    if utils.is_chromium():
      heartbeats = ndb_utils.get_all_from_model(data_types.Heartbeat)
    else:
      raise helpers.EarlyExitException('Dead bots list unavailable.', 400)

    result = {}
    alive_cutoff = _get_alive_cutoff()
    for heartbeat in heartbeats:
      if heartbeat.last_beat_time <= alive_cutoff:
        result[heartbeat.bot_name] = 'dead'

    self.render_json(result)
