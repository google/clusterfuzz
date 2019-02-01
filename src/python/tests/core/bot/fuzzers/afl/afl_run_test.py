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
"""Tests for fuzzer.py."""

import os

from bot.fuzzers.afl import fuzzer
from tests.core.bot.fuzzers import builtin_test
from tests.test_libs import helpers


class FuzzerTest(builtin_test.BaseEngineFuzzerTest):
  """Unit tests for fuzzer."""

  def setUp(self):
    super(FuzzerTest, self).setUp()
    helpers.patch(self, [
        'metrics.logs.log_warn',
    ])

  def _test_passed(self):
    self.assertTrue(os.path.exists('/output/fuzz-0'))
    self.assertTrue(os.path.exists('/output/flags-0'))
    self.assertTrue(os.path.exists('/input/proj_target/in1'))

    with open('/output/flags-0') as f:
      self.assertEqual('%TESTCASE% target', f.read())

  def _test_failed(self):
    self.assertFalse(os.path.exists('/output/fuzz-0'))
    self.assertFalse(os.path.exists('/output/flags-0'))
    self.assertFalse(os.path.exists('/input/proj_target/in1'))

  def test_run(self):
    """Test running afl fuzzer."""
    afl = fuzzer.Afl()
    afl.run('/input', '/output', 1)

    self._test_passed()

  def test_run_with_correct_core_pattern(self):
    """Test correct kernel core_pattern."""
    self.fs.CreateFile('/proc/sys/kernel/core_pattern', contents='core')

    afl = fuzzer.Afl()
    afl.run('/input', '/output', 1)

    self._test_passed()

  def test_run_with_wrong_core_pattern(self):
    """Test wrong kernel core_pattern."""
    self.fs.CreateFile('/proc/sys/kernel/core_pattern', contents='bad')

    afl = fuzzer.Afl()

    with self.assertRaises(SystemExit):
      afl.run('/input', '/output', 1)

    self._test_failed()

  def test_run_with_correct_cpu_scaling(self):
    """Test no warning is logged with correct cpu scaling."""
    self.fs.CreateFile(
        '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor',
        contents='performance')

    afl = fuzzer.Afl()
    afl.run('/input', '/output', 1)

    self.assertEqual(0, self.mock.log_warn.call_count)
    self._test_passed()

  def test_run_with_wrong_cpu_scaling(self):
    """Test warning is logged on wrong cpu scaling."""
    self.fs.CreateFile(
        '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor',
        contents='powersave')

    afl = fuzzer.Afl()
    afl.run('/input', '/output', 1)

    self.assertEqual(1, self.mock.log_warn.call_count)
    self._test_passed()
