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

from clusterfuzz._internal.bot.fuzzers.afl import fuzzer
from clusterfuzz._internal.tests.core.bot.fuzzers import builtin_test
from clusterfuzz._internal.tests.test_libs import helpers


class FuzzerTest(builtin_test.BaseEngineFuzzerTest):
  """Unit tests for fuzzer."""

  def setUp(self):
    super(FuzzerTest, self).setUp()
    helpers.patch(self, [
        'clusterfuzz._internal.metrics.logs.log_warn',
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
