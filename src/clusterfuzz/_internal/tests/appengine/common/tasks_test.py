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
"""Tests for tasks."""
import os
import shutil
import tempfile
import time
import unittest

import mock

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class RedoTestcaseTest(unittest.TestCase):
  """Test redo_testcase()."""

  def test_invalid_task(self):
    """Raise an exception on an invalid task."""
    with self.assertRaises(tasks.InvalidRedoTask) as cm:
      tasks.redo_testcase(None, ['blame', 'rand'], 'test@user.com')

    self.assertEqual("The task 'rand' is invalid.", str(cm.exception))


@test_utils.integration
@test_utils.with_cloud_emulators('datastore', 'pubsub')
class GetTaskTest(unittest.TestCase):
  """GetTask tests."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.persistent_cache.get_value',
        'clusterfuzz._internal.base.persistent_cache.set_value',
        'clusterfuzz._internal.base.utils.utcnow',
        'time.sleep',
    ])

    self.mock.get_value.return_value = None
    self.mock.sleep.return_value = None
    data_types.Job(name='job').put()

    client = pubsub.PubSubClient()
    topic = pubsub.topic_name('test-clusterfuzz', 'jobs-linux')
    client.create_topic(topic)
    client.create_subscription(
        pubsub.subscription_name('test-clusterfuzz', 'jobs-linux'), topic)

    topic = pubsub.topic_name('test-clusterfuzz', 'high-end-jobs-linux')
    client.create_topic(topic)
    client.create_subscription(
        pubsub.subscription_name('test-clusterfuzz', 'high-end-jobs-linux'),
        topic)

    self.mock.utcnow.return_value = test_utils.CURRENT_TIME.replace(
        microsecond=0)

  def test_high_end(self):
    """Test high end tasks."""
    environment.set_value('THREAD_MULTIPLIER', 4)
    tasks.add_task(
        'test', 'high', 'job', queue='high-end-jobs-linux', wait_time=0)
    tasks.add_task('test', 'normal', 'job', queue='jobs-linux', wait_time=0)

    task = tasks.get_task()
    self.assertEqual('test', task.command)
    self.assertEqual('high', task.argument)
    self.assertEqual('job', task.job)
    self.assertEqual('test high job', task.payload())

  def test_regular(self):
    """Test regular tasks."""
    environment.set_value('THREAD_MULTIPLIER', 1)
    tasks.add_task(
        'test', 'high', 'job', queue='high-end-jobs-linux', wait_time=0)
    tasks.add_task('test', 'normal', 'job', queue='jobs-linux', wait_time=0)

    task = tasks.get_task()
    self.assertEqual('test', task.command)
    self.assertEqual('normal', task.argument)
    self.assertEqual('job', task.job)
    self.assertEqual('test normal job', task.payload())

  def test_preemptible(self):
    """Test preemptible bot tasks."""
    environment.set_value('PREEMPTIBLE', True)
    environment.set_value('THREAD_MULTIPLIER', 1)
    tasks.add_task(
        'test', 'high', 'job', queue='high-end-jobs-linux', wait_time=0)
    tasks.add_task('test', 'normal', 'job', queue='jobs-linux', wait_time=0)

    task = tasks.get_task()
    self.assertIsNone(task)

  def test_defer(self):
    """Test deferring tasks which shouldn't be run yet."""
    tasks.add_task('test', 'normal1', 'job', wait_time=60)
    tasks.add_task('test', 'normal2', 'job', wait_time=600)
    tasks.add_task('test', 'normal3', 'job', wait_time=700)
    tasks.add_task('test', 'normal4', 'job', wait_time=0)

    with mock.patch.object(pubsub.ReceivedMessage,
                           'modify_ack_deadline') as mock_modify:
      task = tasks.get_task()
      self.assertEqual('test', task.command)
      self.assertEqual('normal4', task.argument)
      self.assertEqual('job', task.job)
      self.assertEqual('test normal4 job', task.payload())

      self.assertEqual(3, mock_modify.call_count)
      mock_modify.assert_has_calls([
          mock.call(60),
          mock.call(600),
          mock.call(600),
      ])

  def test_command_override(self):
    """Test command override."""
    environment.set_value('COMMAND_OVERRIDE', 'test override job')
    tasks.add_task('test', 'normal', 'job', wait_time=0)

    task = tasks.get_task()
    self.assertEqual('test', task.command)
    self.assertEqual('override', task.argument)
    self.assertEqual('job', task.job)
    self.assertEqual('test override job', task.payload())


class LeaseTaskTest(unittest.TestCase):
  """Tests for leasing tasks."""

  def setUp(self):
    helpers.patch_environ(self)

    helpers.patch(self, [
        'clusterfuzz._internal.datastore.data_handler.update_heartbeat',
        'time.time',
    ])

    self.temp_dir = tempfile.mkdtemp()
    os.environ['CACHE_DIR'] = self.temp_dir
    self.mock.time.return_value = 1337

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_lease_finish_before_latest(self):
    """Test leasing a task and finishing before the latest time."""
    message = mock.MagicMock()
    message.attributes = {
        'command': 'cmd',
        'argument': 'arg',
        'job': 'job',
        'eta': time.time(),
    }

    task = tasks.PubSubTask(message)
    self.mock.time.side_effect = [0, 0, 0, 600, 1200]

    with task.lease() as thread:
      self.assertEqual('21600', os.environ['TASK_LEASE_SECONDS'])

    self.assertEqual(1, message.modify_ack_deadline.call_count)
    message.modify_ack_deadline.assert_has_calls([
        mock.call(600),
    ])

    self.assertFalse(thread.is_alive())
    self.assertEqual(1, message.ack.call_count)

  def test_lease_reach_latest(self):
    """Test leasing a task and reaching the maximum lease time."""
    message = mock.MagicMock()
    message.attributes = {
        'command': 'cmd',
        'argument': 'arg',
        'job': 'job',
        'eta': time.time(),
    }

    task = tasks.PubSubTask(message)

    event = mock.MagicMock()
    event.wait.side_effect = [False, False, False]
    self.mock.time.side_effect = [
        0, 0, 0, 600, tasks.TASK_LEASE_SECONDS - 30, tasks.TASK_LEASE_SECONDS
    ]

    with task.lease(_event=event) as thread:
      self.assertEqual('21600', os.environ['TASK_LEASE_SECONDS'])
      thread.join()

    self.assertEqual(3, message.modify_ack_deadline.call_count)
    # Last extension should be until TASK_LEASE_SECONDS.
    message.modify_ack_deadline.assert_has_calls([
        mock.call(600),
        mock.call(600),
        mock.call(30),
    ])

    self.assertEqual(1, message.ack.call_count)
    self.assertFalse(thread.is_alive())

  def test_lease_exception(self):
    """Test lease with an exception during the task."""
    message = mock.MagicMock()
    message.attributes = {
        'command': 'cmd',
        'argument': 'arg',
        'job': 'job',
        'eta': time.time(),
    }

    task = tasks.PubSubTask(message)

    class Error(Exception):
      """Fake error."""

    with self.assertRaises(Error):
      with task.lease() as thread:
        raise Error

    self.assertFalse(thread.is_alive())
    self.assertEqual(0, message.ack.call_count)


@test_utils.with_cloud_emulators('datastore')
class QueueForTestcaseTest(unittest.TestCase):
  """Tests for queue_for_testcase."""

  def setUp(self):
    helpers.patch_environ(self)

    data_types.Job(name='job_linux', platform='LINUX').put()
    data_types.Job(name='job_project', platform='PROJECT_LINUX_LIB').put()

  def test_regular_queue(self):
    """Test testcase with regular queue."""
    t = data_types.Testcase(job_type='job_linux', queue='old')
    self.assertEqual('jobs-linux', tasks.queue_for_testcase(t))

    t = data_types.Testcase(job_type='job_project', queue='old')
    self.assertEqual('jobs-project-linux-lib', tasks.queue_for_testcase(t))

  def test_high_end_queue(self):
    """Test testcase with high end queue."""
    t = data_types.Testcase(job_type='job_linux', queue='high-end-jobs')
    self.assertEqual('high-end-jobs-linux', tasks.queue_for_testcase(t))

    t = data_types.Testcase(job_type='job_project', queue='high-end-jobs')
    self.assertEqual('high-end-jobs-project-linux-lib',
                     tasks.queue_for_testcase(t))


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class ExternalTasksTest(unittest.TestCase):
  """Tests for adding external tasks."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.read_key',
    ])

    self.mock.read_key.return_value = b'reproducer'

    self.client = pubsub.PubSubClient()
    self.topic = pubsub.topic_name('proj', 'repro')
    self.client.create_topic(self.topic)
    self.subscription = pubsub.subscription_name('proj', 'repro')
    self.client.create_subscription(self.subscription, self.topic)

    data_types.Job(
        name='libfuzzer_asan_blah_external',
        platform='LINUX',
        environment_string=(
            'RELEASE_BUILD_BUCKET_PATH = gs://bucket/a/b/release-([0-9]+).zip\n'
            'PROJECT_NAME = proj\n'),
        external_reproduction_topic=self.topic,
        external_updates_subscription='projects/proj/subscriptions/updates'
    ).put()

    data_types.Job(
        name='libfuzzer_msan_blah_external',
        platform='LINUX',
        environment_string=('FUZZ_TARGET_BUILD_BUCKET_PATH = '
                            'gs://bucket/a/b/%TARGET%/release-([0-9]+).zip\n'
                            'PROJECT_NAME = proj\n'),
        external_reproduction_topic=self.topic,
        external_updates_subscription='projects/proj/subscriptions/updates'
    ).put()

    data_types.FuzzTarget(
        id='libFuzzer_abc', engine='libFuzzer', binary='abc').put()

    self.testcase_0 = data_types.Testcase(
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_abc',
        crash_revision=1336,
        minimized_keys='key')
    self.testcase_0.set_metadata('last_tested_revision', 1337)
    self.testcase_0.put()

    self.testcase_1 = data_types.Testcase(
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libFuzzer_abc',
        crash_revision=1336,
        fuzzed_keys='key')
    self.testcase_1.put()

  def test_progression_0(self):
    """Test adding a ASAN progression (reproduction) task."""
    tasks.add_task('progression', self.testcase_0.key.id(),
                   'libfuzzer_asan_blah_external')

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))

    message = messages[0]
    self.assertEqual(b'reproducer', message.data)
    self.assertDictEqual({
        'buildPath': 'gs://bucket/a/b/release-([0-9]+).zip',
        'fuzzer': 'libFuzzer',
        'job': 'libfuzzer_asan_blah_external',
        'minRevisionAbove': '1337',
        'project': 'proj',
        'sanitizer': 'address',
        'target': 'abc',
        'testcaseId': str(self.testcase_0.key.id()),
    }, message.attributes)

  def test_progression_1(self):
    """Test adding an MSAN progression (reproduction) task."""
    tasks.add_task('progression', self.testcase_1.key.id(),
                   'libfuzzer_msan_blah_external')

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(1, len(messages))

    message = messages[0]
    self.assertEqual(b'reproducer', message.data)
    self.assertDictEqual({
        'buildPath': 'gs://bucket/a/b/%TARGET%/release-([0-9]+).zip',
        'fuzzer': 'libFuzzer',
        'job': 'libfuzzer_msan_blah_external',
        'minRevisionAbove': '1336',
        'project': 'proj',
        'sanitizer': 'memory',
        'target': 'abc',
        'testcaseId': str(self.testcase_1.key.id()),
    }, message.attributes)

  def test_not_progression(self):
    """Test trying to add a task that isn't progression."""
    tasks.add_task('impact', self.testcase_1.key.id(),
                   'libfuzzer_msan_blah_external')

    messages = self.client.pull_from_subscription(
        self.subscription, max_messages=1)
    self.assertEqual(0, len(messages))
