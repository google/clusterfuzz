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
"""Base Class for the Delta and Chunk minimizers."""

import unittest


class BaseMinimizerTester(unittest.TestCase):
  """Base class for chunk and delta minimizer tests."""

  def setUp(self):
    raise NotImplementedError

  def _mock_test_function(self, data_file):
    """Mock test function to reduce time minimizer takes and simplify tests."""
    data = open(data_file, 'rb').read()
    if b'error' in data:
      return False
    return True

  def test_minimizer_still_contains_error(self):
    """Tests a simple minimization. Should remove the first and last lines."""
    testcase = b'x = 2 \n error \n return x'
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, b' error ')

  def test_minimizer_accepts_empty_data(self):
    """Tests that the minimizer does not break on empty string."""
    testcase = b''
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, b'')

  def test_minimizer_does_not_minimize_non_errored_code(self):
    """"Test that the minimizer does not break when there is nothing to min."""
    testcase = b'This \n Code \n Has \n No \n Error'
    minimized = self.line_minimizer.minimize(testcase)
    self.assertEqual(minimized, testcase)
