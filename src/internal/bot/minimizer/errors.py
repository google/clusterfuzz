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
"""Exception classes for minimizers."""


class MinimizationDeadlineExceededError(Exception):
  """Exception thrown if the deadline for minimization has been exceeded."""

  def __init__(self, testcase):
    Exception.__init__(self, 'Deadline exceeded.')
    self.testcase = testcase


class NoCommandError(Exception):
  """Exception thrown if no command is configured for test runs."""

  def __init__(self):
    Exception.__init__(self, 'Attempting to run with no command configured.')


class TokenizationFailureError(Exception):

  def __init__(self, minimization_type):
    Exception.__init__(self, 'Unable to perform ' + minimization_type + '.')


class AntlrDecodeError(Exception):
  """Raised when Antlr can't minimize input because it is not unicode."""
