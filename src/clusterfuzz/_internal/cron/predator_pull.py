# Copyright 2023 Google LLC
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
"""Process results from Predator and update test cases accordingly."""

import json

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.metrics import logs


def main():
  """Periodically gathers new results from Predator requests."""
  subscription = db_config.get_value('predator_result_topic')
  if not subscription:
    logs.info('No Predator subscription configured. Aborting.')
    return False

  client = pubsub.PubSubClient()
  messages = client.pull_from_subscription(subscription, acknowledge=True)
  for message in messages:
    message = json.loads(message.data)
    testcase_id = message['crash_identifiers']
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      logs.info('Testcase %s no longer exists.' % str(testcase_id))
      continue

    testcase.set_metadata('predator_result', message, update_testcase=False)
    testcase.delete_metadata('blame_pending', update_testcase=False)
    testcase.put()
    logs.info('Set predator result for testcase %d.' % testcase.key.id())

  logs.info('Finished processing predator results. %d total.' % len(messages))
  return True
