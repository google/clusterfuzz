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
"""Tests for bots."""
import collections
import datetime
import string
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import bots


@test_utils.with_cloud_emulators('datastore')
class BotsTest(unittest.TestCase):
  """Jobs tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.access.get_access',
        'libs.gcs.prepare_blob_upload',
    ])
    self.mock.prepare_blob_upload.return_value = (
        collections.namedtuple('GcsUpload', [])())
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=bots.JsonHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

  def _create_bot(self,
                  bot_name,
                  last_beat_time=datetime.datetime(2020, 1, 25, 0, 0),
                  task_payload='',
                  task_end_time=datetime.datetime(2020, 1, 25, 0, 0),
                  source_version='',
                  platform_id=''):
    """Create a test job."""
    bot = data_types.Heartbeat()
    bot.bot_name = bot_name
    bot.last_beat_time = last_beat_time
    bot.task_payload = task_payload
    bot.task_end_time = task_end_time
    bot.source_version = source_version
    bot.platform_id = platform_id
    bot.put()

    return bot

  def test_pagination(self):
    """Test bots pagination and post method."""
    self.mock.has_access.return_value = True
    expected_items = {1: [], 2: [], 3: []}

    for bot_num, bot_suffix in enumerate(string.ascii_lowercase):
      bot_name = "test_bot_" + bot_suffix
      bot = self._create_bot(bot_name=bot_name)
      expected_items[(bot_num // bots.PAGE_SIZE) + 1].append(bot.bot_name)

    resp = self.app.post_json('/', {'page': 1})
    self.assertListEqual(expected_items[1],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 2})
    self.assertListEqual(expected_items[2],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 3})
    self.assertListEqual(expected_items[3],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 4})
    self.assertListEqual([], [item['bot_name'] for item in resp.json['items']])

  def test_search(self):
    """Test bots search."""
    self.mock.has_access.return_value = True

    bot_a = self._create_bot(bot_name='test_bot_a', task_payload='pay_x')
    bot_b = self._create_bot(bot_name='test_bot_b', task_payload='pay_y')

    resp = self.app.post_json('/', {'q': 'a'})
    self.assertListEqual([bot_a.bot_name],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'b'})
    self.assertListEqual([bot_b.bot_name],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'c'})
    self.assertListEqual([], [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'bot'})
    self.assertListEqual([bot_a.bot_name, bot_b.bot_name],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'x'})
    self.assertListEqual([bot_a.bot_name],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'y'})
    self.assertListEqual([bot_b.bot_name],
                         [item['bot_name'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': 'pay'})
    self.assertListEqual([bot_a.bot_name, bot_b.bot_name],
                         [item['bot_name'] for item in resp.json['items']])
