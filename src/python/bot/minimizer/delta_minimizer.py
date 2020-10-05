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
"""Minimizer based on the delta debugging algorithm."""

from . import errors
from . import minimizer
from . import utils


class DeltaTestcase(minimizer.Testcase):
  """Test case for the delta minimizer."""

  def _process_test_result(self, test_passed, hypothesis):
    """Update state based on test_passed and hypothesis."""
    # If we crashed or cannot split the test into smaller chunks, we're done.
    if not test_passed or len(hypothesis) <= 1:
      return

    # Test passed. Break this up into sub-tests.
    middle = len(hypothesis) // 2
    front = hypothesis[:middle]
    back = hypothesis[middle:]

    # Working back to front works better for some formats.
    self.prepare_test(back)
    self.prepare_test(front)


class DeltaMinimizer(minimizer.Minimizer):
  """Minimizer based on the delta algorithm."""

  def _execute(self, data):
    """Prepare tests for delta minimization and process."""
    testcase = DeltaTestcase(data, self)
    if not self.validate_tokenizer(data, testcase):
      raise errors.TokenizationFailureError('Delta Minimizer')

    tokens = testcase.tokens

    step = max(1, len(tokens) // self.max_threads)
    for start in range(0, len(tokens), step):
      end = min(len(tokens), start + step)
      hypothesis = list(range(start, end))
      testcase.prepare_test(hypothesis)

    testcase.process()
    return testcase

  @staticmethod
  def run(data, thread_count=minimizer.DEFAULT_THREAD_COUNT, file_extension=''):
    """Try to minimize |data| using a simple line tokenizer."""
    delta_minimizer = DeltaMinimizer(
        utils.test, max_threads=thread_count, file_extension=file_extension)
    return delta_minimizer.minimize(data)
