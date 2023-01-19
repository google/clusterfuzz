# Copyright 2020 Google LLC
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

# This can be run using `python3 -m unittest clusterfuzz/tests/test.py`
"""libClusterFuzz tests."""

import os
import unittest

import clusterfuzz.stacktraces

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'testdata')


def _load_test_data(path):
  """Load test data."""
  with open(os.path.join(TEST_DATA_DIR, path), 'r') as f:
    return f.read()


class StacktracesTest(unittest.TestCase):
  """Tests for the stacktraces module."""

  def test_basic(self):
    """Basic test."""
    stacktrace = _load_test_data('asan_stacktrace.txt')
    parser = clusterfuzz.stacktraces.StackParser()
    crash_info = parser.parse(stacktrace)

    self.assertEqual('Heap-buffer-overflow\nWRITE 16', crash_info.crash_type)
    self.assertEqual('0x0d37d6e0', crash_info.crash_address)
    self.assertEqual(
        'blink::TimerBase::stop\n'
        'blink::HTMLInputElement::onSearch\n'
        'blink::internal::CallClosureTask::performTask\n',
        crash_info.crash_state)
    self.assertEqual(stacktrace, crash_info.crash_stacktrace)
