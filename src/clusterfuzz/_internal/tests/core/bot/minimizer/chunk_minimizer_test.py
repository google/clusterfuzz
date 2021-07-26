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
"""Tests for the Chunk minimizer."""

from clusterfuzz._internal.bot.minimizer import chunk_minimizer

from . import base_minimizer_tester


class ChunkMinimizerTest(base_minimizer_tester.BaseMinimizerTester):
  """Test for Chunk Minimizer. Sets up the minimizer being used and then
  runs all of the tests in BaseMinimizerTester."""

  def setUp(self):
    self.line_minimizer = chunk_minimizer.ChunkMinimizer(
        self._mock_test_function)
