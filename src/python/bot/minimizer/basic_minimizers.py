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
"""Simple minimizers for common tasks."""

from . import minimizer


class SinglePassMinimizer(minimizer.Minimizer):  # pylint:disable=abstract-method
  """Do a single pass over the token list."""

  def _execute(self, data):
    """Attempt to remove each token starting from the last one."""
    testcase = minimizer.Testcase(data, self)
    for i in reversed(list(range(len(testcase.tokens)))):
      hypothesis = [i]
      testcase.prepare_test(hypothesis)

    testcase.process()
    return testcase


class EmptyTokenRemover(minimizer.Minimizer):  # pylint:disable=abstract-method
  """Attempt to remove empty tokens."""

  def __init__(self, *args, **kwargs):
    self.is_empty = self._handle_constructor_argument(
        'is_empty', kwargs, default=lambda s: not s.strip())
    minimizer.Minimizer.__init__(self, *args, **kwargs)

  def _execute(self, data):
    """Try to remove all blank tokens, then individual ones."""
    testcase = minimizer.Testcase(data, self)
    tokens = testcase.tokens
    empty_tokens = []

    for i, token in enumerate(tokens):
      if self.is_empty(token):
        empty_tokens.append(i)

    # Try to remove all of them.
    testcase.prepare_test(empty_tokens)

    # The minimizer will automatically skip the following tests if all tokens
    # were removed at once, with the exception of runs started parallel to it.
    for token in empty_tokens:
      testcase.prepare_test([token])

    testcase.process()
    return testcase
