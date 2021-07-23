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

from flask import request

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from handlers import base_handler
from libs import filters
from libs import handler
from libs import helpers
from libs.query import datastore_query

PAGE_SIZE = 10
MORE_LIMIT = 50 - PAGE_SIZE  # exactly 5 pages

FILTERS = [
    filters.Keyword([], 'keywords', 'q'),
]


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
        'platform_id':
            heartbeat.platform_id,
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


def get_results():
  """Get results for the bots page."""
  # Return bots sorted alphabetically by bot_name
  query = datastore_query.Query(data_types.Heartbeat)
  query.order('bot_name', is_desc=False)
  params = dict(request.iterparams())
  filters.add(query, params, FILTERS)

  page = helpers.cast(request.get('page', 1), int, "'page' is not an int.")
  items, total_pages, total_items, has_more = query.fetch_page(
      page=page, page_size=PAGE_SIZE, projection=None, more_limit=MORE_LIMIT)
  items = _convert_heartbeats_to_dicts(items)
  helpers.log('Bots', helpers.VIEW_OPERATION)

  result = {
      'hasMore': has_more,
      'items': items,
      'page': page,
      'pageSize': PAGE_SIZE,
      'totalItems': total_items,
      'totalPages': total_pages,
  }
  return result, params


class Handler(base_handler.Handler):
  """Handler that gets the bot list."""

  @handler.get(handler.HTML)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_user_access(need_privileged_access=False)
  def get(self):
    """Render the bot list HTML."""
    result, params = get_results()
    return self.render('bots.html', {
        'result': result,
        'params': params,
    })


class JsonHandler(base_handler.Handler):
  """Handler that gets the bots when user clicks on next page."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.check_admin_access_if_oss_fuzz
  @handler.check_user_access(need_privileged_access=False)
  def post(self):
    """Get and render the bots in JSON."""
    result, _ = get_results()
    return self.render_json(result)


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

    return self.render_json(result)
