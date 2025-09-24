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
"""Test script."""

import datetime
import json
import os

from google.cloud import logging_v2

from appengine.handlers.testcase_detail import testcase_status_events
from clusterfuzz._internal.system import environment


def download_logs():
  """Downloads up to 10 log entries based on a specific query."""
  project_id = environment.get_value('PROJECT_ID') or 'clusterfuzz-development'
  client = logging_v2.Client(project=project_id)

  # Add a time range to the filter. The Logs API may not find older entries
  # without one. A 30-day window is a reasonable default for debugging.
  end_time = datetime.datetime.utcnow()
  start_time = end_time - datetime.timedelta(days=30)
  time_format = '%Y-%m-%dT%H:%M:%S.%fZ'

  filter_str = (
      f'jsonPayload.extras.task_id="c67a1bf0-ccab-43f8-b137-9eb3ba1e2291" '
      f'timestamp >= "{start_time.strftime(time_format)}" AND timestamp <= "{end_time.strftime(time_format)}"'
  )

  entries = client.list_entries(
      filter_=filter_str, max_results=3, order_by=logging_v2.DESCENDING)

  print('Log entries:')
  count = 0
  for entry in entries:
    print(json.dumps(entry.to_api_repr(), indent=2))
    count += 1

  if not count:
    print('No log entries found.')


def execute(args):
  """"""
  del args

  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['LOG_TO_GCP'] = ''

  # history = testcase_status_events.get_testcase_event_history(5183725214138368)
  # download_logs()
  response = testcase_status_events.get_task_log(
      5183725214138368, 'bfc3e657-8861-4f4d-8a29-300f23b6dadd')
  print(response)
