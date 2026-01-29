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
"""Tests for remote_task_types."""

import unittest

from clusterfuzz._internal.remote_task import remote_task_types


class RemoteTaskTest(unittest.TestCase):
  """Tests for RemoteTask."""

  def test_to_pubsub_message(self):
    """Test to_pubsub_message."""
    task = remote_task_types.RemoteTask(
        command='fuzz',
        job_type='libfuzzer_asan',
        input_download_url='gs://bucket/input')

    message = task.to_pubsub_message()

    self.assertEqual(message.attributes['command'], 'fuzz')
    self.assertEqual(message.attributes['job'], 'libfuzzer_asan')
    self.assertEqual(message.attributes['argument'], 'gs://bucket/input')

  def test_to_pubsub_message_none_url(self):
    """Test to_pubsub_message with None input_download_url."""
    task = remote_task_types.RemoteTask(
        command='fuzz', job_type='libfuzzer_asan', input_download_url=None)

    message = task.to_pubsub_message()

    self.assertEqual(message.attributes['command'], 'fuzz')
    self.assertEqual(message.attributes['job'], 'libfuzzer_asan')
    self.assertEqual(message.attributes['argument'], 'None')
