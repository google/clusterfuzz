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
"""Pubsub tests."""

import time
import unittest

import six

from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

ACK_DEADLINE = 3

# Additional amount of time to sleep to let ack deadline elapse.
ACK_DEADLINE_WINDOW = 1
PROJECT_NAME = 'fake-project'


@test_utils.integration
@test_utils.with_cloud_emulators('pubsub')
class PubSubTest(unittest.TestCase):
  """Tests for pubsub."""

  def setUp(self):
    helpers.patch_environ(self)
    self.topic = pubsub.topic_name(PROJECT_NAME, 'test-topic')
    self.subscription = pubsub.subscription_name(PROJECT_NAME, 'subscription')

    self.client = pubsub.PubSubClient()
    self.client.create_topic(self.topic)
    self.client.create_subscription(
        self.subscription, self.topic, ack_deadline=ACK_DEADLINE)

  def test_pull_from_subscription(self):
    """Test pull_from_subscription."""
    self.client.publish(
        self.topic, [
            pubsub.Message(data=b'123'),
            pubsub.Message(data=b'123', attributes={'a': '1337'}),
            pubsub.Message(data=b'456'),
            pubsub.Message(data=b'456'),
        ])

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))
    self.assertEqual(b'123', messages[0].data)
    self.assertIsNone(messages[0].attributes)

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))
    self.assertEqual(b'123', messages[0].data)
    self.assertDictEqual({'a': '1337'}, messages[0].attributes)

    messages = self.client.pull_from_subscription(
        self.subscription, acknowledge=True)
    self.assertEqual(2, len(messages))

    for message in messages:
      self.assertEqual(b'456', message.data)

    # Test messages which were not acked in time. They will be re-sent and can
    # be re-pulled.
    time.sleep(ACK_DEADLINE + ACK_DEADLINE_WINDOW)
    messages = self.client.pull_from_subscription(self.subscription)
    self.assertEqual(2, len(messages))
    six.assertCountEqual(self, [
        {
            'data': 'MTIz',
        },
        {
            'data': 'MTIz',
            'attributes': {
                'a': '1337',
            }
        },
    ], [pubsub._message_to_dict(message) for message in messages])  # pylint: disable=protected-access

  def test_ack(self):
    """Test a single message ack."""
    self.client.publish(
        self.topic, [
            pubsub.Message(data=b'123'),
        ])

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))

    # Acknowledging the message means it shouldn't get pulled again.
    messages[0].ack()
    time.sleep(ACK_DEADLINE + ACK_DEADLINE_WINDOW)

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(0, len(messages))

  def test_modify_ack_deadline(self):
    """Test modify ACK deadline."""
    self.client.publish(
        self.topic, [
            pubsub.Message(data=b'123'),
        ])
    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))

    # Make message instantly available again.
    messages[0].modify_ack_deadline(0)
    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))

  def test_list_topics(self):
    """Test listing topics."""
    expected = []
    for i in range(5):
      topic = pubsub.topic_name(PROJECT_NAME, 'topic-{}'.format(i))
      expected.append(topic)
      self.client.create_topic(topic)

    expected.append('projects/fake-project/topics/test-topic')

    topics = list(self.client.list_topics('projects/' + PROJECT_NAME))
    six.assertCountEqual(self, expected, topics)

    # Note: Page size appears to be ignored by the emulator. Even when creating
    # large amounts of topics to force paging, the nextPageToken returned is
    # buggy and results in infinite loops.
    topics = list(
        self.client.list_topics('projects/' + PROJECT_NAME, page_size=1))
    six.assertCountEqual(self, expected, topics)

  def test_list_topic_subscriptions(self):
    """Test listing topic subscriptions."""
    expected = []
    for i in range(5):
      subscription = pubsub.subscription_name(PROJECT_NAME, 'sub-{}'.format(i))
      expected.append(subscription)
      self.client.create_subscription(subscription, self.topic)

    expected.append('projects/fake-project/subscriptions/subscription')

    subscriptions = list(self.client.list_topic_subscriptions(self.topic))
    six.assertCountEqual(self, expected, subscriptions)

    # Note: Page size appears to be ignored by the emulator. Even when creating
    # large amounts of topics to force paging, the nextPageToken returned is
    # buggy and results in infinite loops.
    subscriptions = list(
        self.client.list_topic_subscriptions(self.topic, page_size=1))
    six.assertCountEqual(self, expected, subscriptions)

  def test_get_topic(self):
    """Test getting a topic."""
    topic = self.client.get_topic(self.topic)
    self.assertEqual(self.topic, topic.name)
    self.assertIsNone(topic.labels)

  def test_get_subscription(self):
    """Test getting a subscription."""
    subscription = self.client.get_subscription(self.subscription)
    self.assertEqual(self.subscription, subscription.name)
    self.assertEqual(self.topic, subscription.topic)
    self.assertEqual(ACK_DEADLINE, subscription.ack_deadline)
    self.assertIsNone(subscription.labels)

  def test_delete_topic(self):
    """Test deleting a topic."""
    self.client.delete_topic(self.topic)
    self.assertIsNone(self.client.get_topic(self.topic))

  def test_delete_subscription(self):
    """Test deleting a subscription."""
    self.client.delete_subscription(self.subscription)
    self.assertIsNone(self.client.get_subscription(self.subscription))
