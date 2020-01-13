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
"""Tests for the Delta minimizer."""

import unittest

from bot.minimizer import delta_minimizer


class DeltaMinimizerTest(unittest.TestCase):
  """Test for Delta Minimizer."""

  def setUp(self):
    self.line_minimizer = delta_minimizer.DeltaMinimizer(
        self._mock_test_function)

  def _mock_test_function(self, data_file):
    """Mock test function to reduce time minimizer takes and simplify tests."""
    data = open(data_file, "r").read()
    if "error" in data:
      return False
    return True

  def test_minimizer_still_contains_error(self):
    """Tests a simple minimization. Should remove the first and last lines."""
    testcase = 'x = 2 \n error \n return x'
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, " error ")

  def test_minimizer_accepts_empty_data(self):
    """Tests that the minimizer does not break on empty string."""
    testcase = ""
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, "")

  def test_minimizer_does_not_minimize_non_errored_code(self):
    """"Test that the minimizer does not break when there is nothing to min."""
    testcase = "This \n Code \n Has \n No \n Error"
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, testcase)
