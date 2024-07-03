# Copyright 2024 Google LLC
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
"""Helper module for fuzz_task that tracks fuzzing time."""

import unittest

from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.tests.test_libs import helpers

from clusterfuzz._internal.bot.tasks.utasks import track_fuzz_time

class TrackFuzzerRunResultTest(unittest.TestCase):
  """Test track_fuzzer_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_fuzzer_run_result(self):
    """Ensure track_fuzzer_run_result set the right metrics."""
    track_fuzz_time.track_fuzzer_run_result('name', 10, 100, 2)
    track_fuzz_time.track_fuzzer_run_result('name', 100, 200, 2)
    track_fuzz_time.track_fuzzer_run_result('name', 1000, 2000, 2)
    track_fuzz_time.track_fuzzer_run_result('name', 1000, 500, 0)
    track_fuzz_time.track_fuzzer_run_result('name', 0, 1000, -1)
    track_fuzz_time.track_fuzzer_run_result('name', 0, 0, 2)

    self.assertEqual(
        4,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': 2
        }))
    self.assertEqual(
        1,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': 0
        }))
    self.assertEqual(
        1,
        monitoring_metrics.FUZZER_RETURN_CODE_COUNT.get({
            'fuzzer': 'name',
            'return_code': -1
        }))

    testcase_count_ratio = (
        monitoring_metrics.FUZZER_TESTCASE_COUNT_RATIO.get({
            'fuzzer': 'name'
        }))
    self.assertEqual(3.1, testcase_count_ratio.sum)
    self.assertEqual(5, testcase_count_ratio.count)

    expected_buckets = [0 for _ in range(22)]
    expected_buckets[1] = 1
    expected_buckets[3] = 1
    expected_buckets[11] = 2
    expected_buckets[21] = 1
    self.assertListEqual(expected_buckets, testcase_count_ratio.buckets)


class TrackBuildRunResultTest(unittest.TestCase):
  """Test track_build_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_build_run_result(self):
    """Ensure track_build_run_result set the right metrics."""
    track_fuzz_time.track_build_run_result('name', 10000, True)
    track_fuzz_time.track_build_run_result('name', 10001, True)
    track_fuzz_time.track_build_run_result('name', 10002, False)

    self.assertEqual(
        2,
        monitoring_metrics.JOB_BAD_BUILD_COUNT.get({
            'job': 'name',
            'bad_build': True
        }))
    self.assertEqual(
        1,
        monitoring_metrics.JOB_BAD_BUILD_COUNT.get({
            'job': 'name',
            'bad_build': False
        }))


class TrackTestcaseRunResultTest(unittest.TestCase):
  """Test track_testcase_run_result."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def test_testcase_run_result(self):
    """Ensure track_testcase_run_result sets the right metrics."""
    track_fuzz_time.track_testcase_run_result('fuzzer', 'job', 2, 5)
    track_fuzz_time.track_testcase_run_result('fuzzer', 'job', 5, 10)

    self.assertEqual(7,
                     monitoring_metrics.JOB_NEW_CRASH_COUNT.get({
                         'job': 'job'
                     }))
    self.assertEqual(
        15, monitoring_metrics.JOB_KNOWN_CRASH_COUNT.get({
            'job': 'job'
        }))
    self.assertEqual(
        7, monitoring_metrics.FUZZER_NEW_CRASH_COUNT.get({
            'fuzzer': 'fuzzer'
        }))
    self.assertEqual(
        15, monitoring_metrics.FUZZER_KNOWN_CRASH_COUNT.get({
            'fuzzer': 'fuzzer'
        }))


class TrackFuzzTimeTest(unittest.TestCase):
  """Test TrackFuzzTime."""

  def setUp(self):
    monitor.metrics_store().reset_for_testing()

  def _test(self, timeout):
    """Test helper."""
    time_module = helpers.MockTime()
    with track_fuzz_time.TrackFuzzTime('fuzzer', 'job', time_module) as tracker:
      time_module.advance(5)
      tracker.timeout = timeout

    fuzzer_total_time = monitoring_metrics.FUZZER_TOTAL_FUZZ_TIME.get({
        'fuzzer': 'fuzzer',
        'timeout': timeout
    })
    self.assertEqual(5, fuzzer_total_time)

  def test_success(self):
    """Test report metrics."""
    self._test(False)

  def test_timeout(self):
    """Test timeout."""
    self._test(True)
