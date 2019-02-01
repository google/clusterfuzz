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
"""run_bot tests."""
# pylint: disable=protected-access
import unittest

import mock

from bot.startup import run_bot
from metrics import monitor
from metrics import monitoring_metrics
from tests.test_libs import helpers


class MonitorTest(unittest.TestCase):
  """Test _Monitor."""

  def setUp(self):
    self.time = helpers.MockTime()
    monitor.metrics_store().reset_for_testing()

  def test_succeed(self):
    """Test succeed."""
    task = mock.Mock()
    task.command = 'task'
    task.job = 'job'

    with run_bot._Monitor(task, time_module=self.time):
      self.time.advance(5)

    self.assertEqual(
        1, monitoring_metrics.TASK_COUNT.get({
            'task': 'task',
            'job': 'job'
        }))
    task_time = monitoring_metrics.TASK_TIME.get({
        'task': 'task',
        'job': 'job',
        'error': False
    })
    self.assertEqual(5, task_time.sum)
    self.assertEqual(1, task_time.count)

    expected_buckets = [0 for _ in xrange(102)]
    expected_buckets[14] = 1
    self.assertListEqual(expected_buckets, task_time.buckets)

  def test_empty(self):
    """Test empty."""
    task = mock.Mock()
    task.command = None
    task.job = None

    with run_bot._Monitor(task, time_module=self.time):
      self.time.advance(5)

    self.assertEqual(1,
                     monitoring_metrics.TASK_COUNT.get({
                         'task': '',
                         'job': ''
                     }))
    task_time = monitoring_metrics.TASK_TIME.get({
        'task': '',
        'job': '',
        'error': False
    })
    self.assertEqual(5, task_time.sum)
    self.assertEqual(1, task_time.count)

    expected_buckets = [0 for _ in xrange(102)]
    expected_buckets[14] = 1
    self.assertListEqual(expected_buckets, task_time.buckets)

  def test_exception(self):
    """Test raising exception."""
    task = mock.Mock()
    task.command = 'task'
    task.job = 'job'

    with self.assertRaises(Exception):
      with run_bot._Monitor(task, time_module=self.time):
        self.time.advance(5)
        raise Exception('test')

    self.assertEqual(
        1, monitoring_metrics.TASK_COUNT.get({
            'task': 'task',
            'job': 'job'
        }))
    task_time = monitoring_metrics.TASK_TIME.get({
        'task': 'task',
        'job': 'job',
        'error': True
    })
    self.assertEqual(5, task_time.sum)
    self.assertEqual(1, task_time.count)

    expected_buckets = [0 for _ in xrange(102)]
    expected_buckets[14] = 1
    self.assertListEqual(expected_buckets, task_time.buckets)
