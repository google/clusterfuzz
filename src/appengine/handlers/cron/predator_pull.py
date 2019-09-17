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
"""Process results from Predator and update test cases accordingly."""

import json

from base import errors
from config import db_config
from datastore import data_handler
from google_cloud_utils import pubsub
from handlers import base_handler
from libs import handler
from metrics import logs


class Handler(base_handler.Handler):
  """Handler to periodically gather new results from Predator requests."""

  @handler.check_cron()
  def get(self):
    """Process a GET request."""
    subscription = db_config.get_value('predator_result_topic')
    if not subscription:
      logs.log('No Predator subscription configured. Aborting.')
      return

    client = pubsub.PubSubClient()
    messages = client.pull_from_subscription(subscription, acknowledge=True)
    for message in messages:
      message = json.loads(message.data)
      testcase_id = message['crash_identifiers']
      try:
        testcase = data_handler.get_testcase_by_id(testcase_id)
      except errors.InvalidTestcaseError:
        logs.log('Testcase %s no longer exists.' % str(testcase_id))
        continue

      testcase.set_metadata('predator_result', message, update_testcase=False)
      testcase.delete_metadata('blame_pending', update_testcase=False)
      testcase.put()
      logs.log('Set predator result for testcase %d.' % testcase.key.id())

    logs.log('Finished processing predator results. %d total.' % len(messages))
