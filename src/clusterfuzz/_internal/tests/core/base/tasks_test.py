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
"""Tests for tasks."""

import unittest
from unittest import mock

from clusterfuzz._internal.base import tasks


class InitializeTaskTest(unittest.TestCase):
  """Tests for initialize_task."""

  def setUp(self):
    self.command = 'symbolize'
    self.argument = 'blah'
    self.job = 'linux_asan_chrome_mp'
    self.bucket = 'mybucket'
    self.path = 'worker.output'
    self.message = mock.MagicMock()

  def test_initialize_trusted_task(self):
    """Tests that a normal trusted task is initialized properly."""
    self.message.attributes = {
        'command': self.command,
        'argument': self.argument,
        'job': self.job,
        'eta': 1,
    }
    task = tasks.initialize_task([self.message])
    self.assertIsInstance(task, tasks.PubSubTask)
    self.assertEqual(task.command, self.command)
    self.assertEqual(task.argument, self.argument)
    self.assertEqual(task.job, self.job)

  def test_initialize_untrusted_task(self):
    """Tests that an untrusted task is initialized properly."""
    self_link = f'https://www.googleapis.com/storage/v1/b/{self.bucket}/o/{self.path}'
    self.message.attributes = {
        'kind': 'storage#object',
        'selfLink': self_link,
        'command': self.command,
        'argument': self.argument,
        'job': self.job,
    }
    task = tasks.initialize_task([self.message])
    self.assertFalse(isinstance(task, tasks.PubSubTask))
    self.assertEqual(task.command, 'postprocess')
    self.assertEqual(task.argument, '/mybucket/worker.output')
    self.assertEqual(task.job, 'none')

  def test_initialize_untrusted_from_reupload(self):
    """Tests that an untrusted task is not initialized when the uworker output
    was uploaded a second time. This tests checks that uworkers can't DoS or
    worse by reuploading their output multiple times."""
    # Test version 2 of an output.
    self_link = f'https://www.googleapis.com/storage/v2/b/{self.bucket}/o/{self.path}'
    self.message.attributes = {
        'kind': 'storage#object',
        'selfLink': self_link,
    }
    with self.assertRaises(tasks.Error):
      tasks.initialize_task([self.message])
