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
"""Pub/Sub helpers."""

import base64
import collections
import googleapiclient
import httplib2
import json
import threading

from base import retry
from google_cloud_utils import credentials
from system import environment

MAX_ACK_DEADLINE = 10 * 60  # 10 minutes (the maximum).
_DEFAULT_MAX_MESSAGES = 1000  # Arbitrary reasonably large limit.
_PUBSUB_FAIL_RETRIES = 5
_PUBSUB_FAIL_WAIT = 2

Topic = collections.namedtuple('Topic', ['name', 'labels'])
Subscription = collections.namedtuple(
    'Subsciption', ['name', 'topic', 'ack_deadline', 'labels'])


class Message(object):
  """Pubsub message."""

  def __init__(self, data=None, attributes=None):
    self.data = data
    self.attributes = attributes


class ReceivedMessage(Message):
  """Received pubsub message."""

  def __init__(self, client, subscription, data, attributes, message_id,
               publish_time, ack_id):
    super(ReceivedMessage, self).__init__(data, attributes)
    self._client = client
    self.ack_id = ack_id
    self.message_id = message_id
    self.subscription = subscription
    self.publish_time = publish_time

  def ack(self):
    """Acknowledge the message."""
    self._client.ack(self.subscription, [self.ack_id])

  def modify_ack_deadline(self, seconds):
    """Modify the acknowledgement deadline."""
    self._client.modify_ack_deadline(self.subscription, [self.ack_id], seconds)


class PubSubClient(object):
  """Helper class that provides wrappers around some Pub/Sub functionality."""

  def __init__(self, emulator_host=None):
    self._local = threading.local()
    self._emulator_host = emulator_host

  @retry.wrap(
      retries=_PUBSUB_FAIL_RETRIES,
      delay=_PUBSUB_FAIL_WAIT,
      function='google_cloud_utils.pubsub._api_client')
  def _api_client(self):
    """Get the client for the current thread."""
    if hasattr(self._local, 'api_client'):
      return self._local.api_client

    emulator_host = environment.get_value('PUBSUB_EMULATOR_HOST')
    creds = credentials.get_default()[0]
    if emulator_host:
      # Replace real discovery document's root url with the emulator.
      _, discovery_doc = httplib2.Http().request(
          googleapiclient.discovery.DISCOVERY_URI.format(
              api='pubsub', apiVersion='v1'))
      discovery_doc = json.loads(discovery_doc)
      discovery_doc['rootUrl'] = 'http://{}/'.format(emulator_host)

      self._local.api_client = googleapiclient.discovery.build_from_document(
          discovery_doc, credentials=creds)
    else:
      self._local.api_client = googleapiclient.discovery.build(
          'pubsub', 'v1', cache_discovery=False, credentials=creds)

    return self._local.api_client

  @retry.wrap(
      retries=_PUBSUB_FAIL_RETRIES,
      delay=_PUBSUB_FAIL_WAIT,
      function='google_cloud_utils.pubsub._execute_with_retry')
  def _execute_with_retry(self, request):
    """Execute a request (with retries)."""
    try:
      return request.execute()
    except googleapiclient.errors.HttpError as e:
      if e.resp.status == 404:
        return None

      raise

  def ack(self, subscription, ack_ids):
    """Acknowledge messages."""
    ack_body = {'ackIds': ack_ids}
    request = self._api_client().projects().subscriptions().acknowledge(
        subscription=subscription, body=ack_body)
    self._execute_with_retry(request)

  def modify_ack_deadline(self, subscription, ack_ids, seconds):
    """Modify acknowledgement deadline of messages."""
    body = {
        'ackIds': ack_ids,
        'ackDeadlineSeconds': int(seconds),  # since time.time() is float.
    }

    request = self._api_client().projects().subscriptions().modifyAckDeadline(
        subscription=subscription, body=body)
    self._execute_with_retry(request)

  def publish(self, topic, messages):
    """Publish a message to a topic."""
    request_body = {
        'messages': [_message_to_dict(message) for message in messages]
    }
    request = self._api_client().projects().topics().publish(
        topic=topic, body=request_body)

    response = self._execute_with_retry(request)
    if response is None:
      raise RuntimeError('Invalid topic: ' + topic)

    return sorted(response.get('messageIds'))

  def pull_from_subscription(self,
                             subscription,
                             max_messages=_DEFAULT_MAX_MESSAGES,
                             acknowledge=False):
    """Pull messages from a subscription to a topic."""
    request_body = {
        'returnImmediately': True,
        'maxMessages': max_messages,
    }
    request = self._api_client().projects().subscriptions().pull(
        subscription=subscription, body=request_body)
    response = self._execute_with_retry(request)
    if response is None:
      raise RuntimeError('Invalid subscription: ' + subscription)

    received_messages = response.get('receivedMessages')
    if not received_messages:
      # |receivedMessages| attribute may not exist if there are no messages in
      # the subscription. In that case, return an empty list.
      return []

    if acknowledge:
      ack_ids = [message['ackId'] for message in received_messages]
      self.ack(subscription, ack_ids)

    return [
        _raw_message_to_message(self, subscription, message)
        for message in received_messages
    ]

  def create_topic(self, name, labels=None):
    """Create a new topic."""
    body = {
        'labels': {},
    }

    if labels:
      body['labels'] = labels

    request = self._api_client().projects().topics().create(
        name=name, body=body)
    self._execute_with_retry(request)

  def delete_topic(self, name):
    """Deletes a topic."""
    request = self._api_client().projects().topics().delete(topic=name)
    self._execute_with_retry(request)

  def get_topic(self, name):
    """Get a topic, or None if it does not exist."""
    request = self._api_client().projects().topics().get(topic=name)
    response = self._execute_with_retry(request)
    if not response:
      return None

    return Topic(response['name'], response.get('labels'))

  def create_subscription(self,
                          name,
                          topic,
                          ack_deadline=MAX_ACK_DEADLINE,
                          labels=None):
    """Create a new subscription."""
    body = {'topic': topic, 'ackDeadlineSeconds': ack_deadline, 'labels': {}}

    if labels:
      body['labels'] = labels

    request = self._api_client().projects().subscriptions().create(
        name=name, body=body)
    self._execute_with_retry(request)

  def delete_subscription(self, name):
    """Delete a subscription."""
    request = self._api_client().projects().subscriptions().delete(
        subscription=name)
    self._execute_with_retry(request)

  def get_subscription(self, name):
    """Get a subscription, or None if it does not exist."""
    request = self._api_client().projects().subscriptions().get(
        subscription=name)
    response = self._execute_with_retry(request)
    if not response:
      return None

    return Subscription(response['name'], response['topic'],
                        response['ackDeadlineSeconds'], response.get('labels'))

  def list_topics(self, project, page_size=1000):
    """List topics."""
    request = self._api_client().projects().topics().list(
        project=project, pageSize=page_size)
    response = self._execute_with_retry(request)

    while True:
      for topic in response['topics']:
        yield topic['name']

      next_page_token = response.get('nextPageToken')
      if not next_page_token:
        break

      request = self._api_client().projects().topics().list(
          project=project, pageToken=next_page_token, pageSize=page_size)
      response = self._execute_with_retry(request)

  def list_topic_subscriptions(self, topic, page_size=1000):
    """List topic subscriptions."""
    request = self._api_client().projects().topics().subscriptions().list(
        topic=topic, pageSize=page_size)
    response = self._execute_with_retry(request)

    while True:
      for subscription in response.get('subscriptions', []):
        yield subscription

      next_page_token = response.get('nextPageToken')
      if not next_page_token:
        break

      request = self._api_client().projects().topics().subscriptions().list(
          topic=topic, pageToken=next_page_token, pageSize=page_size)
      response = self._execute_with_retry(request)


def project_name(project):
  return 'projects/' + project


def subscription_name(project, name):
  """Get subscription name."""
  return 'projects/{project}/subscriptions/{name}'.format(
      project=project, name=name)


def topic_name(project, name):
  """Get topic name."""
  return 'projects/{project}/topics/{name}'.format(project=project, name=name)


def parse_name(name):
  """Parse the topic or subscription name."""
  components = name.split('/')
  if len(components) != 4:
    raise ValueError('Invalid pubsub name.')

  project = components[1]
  name = components[3]
  return project, name


def _raw_message_to_message(client, subscription, raw_message_response):
  """Convert a raw message response to a Message."""
  raw_message = raw_message_response['message']
  data = (
      base64.b64decode(raw_message['data']) if 'data' in raw_message else None)
  return ReceivedMessage(client, subscription, data,
                         raw_message.get('attributes'),
                         raw_message['messageId'], raw_message['publishTime'],
                         raw_message_response['ackId'])


def _message_to_dict(message):
  """Convert the message to a dict."""
  result = {}

  if message.data:
    result['data'] = base64.b64encode(message.data).decode('utf-8')

  if message.attributes:
    result['attributes'] = message.attributes

  return result
