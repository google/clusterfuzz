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
"""Class for helping manage a crash result."""

# pylint: disable=unpacking-non-sequence

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer


class CrashResult(object):
  """Represents a crash result from a test run."""

  def __init__(self, return_code, crash_time, output):
    self.return_code = return_code
    self.crash_time = crash_time
    self.output = utils.decode_to_unicode(output) if output else 'No output!'

    self._symbolized_crash_data = None
    self._unsymbolized_crash_data = None

  def get_crash_time(self):
    """Return the crash time."""
    return self.crash_time

  def get_symbolized_data(self):
    """Compute symbolized crash data if necessary or return cached result."""
    if self._symbolized_crash_data:
      return self._symbolized_crash_data

    self._symbolized_crash_data = stack_analyzer.get_crash_data(
        self.output, symbolize_flag=True)
    return self._symbolized_crash_data

  def get_unsymbolized_data(self):
    """Compute unsymbolized crash data if necessary or return cached result."""
    if self._unsymbolized_crash_data:
      return self._unsymbolized_crash_data

    self._unsymbolized_crash_data = stack_analyzer.get_crash_data(
        self.output, symbolize_flag=False)
    return self._unsymbolized_crash_data

  def get_state(self, symbolized=True):
    """Return the crash state."""
    if symbolized:
      state = self.get_symbolized_data()
    else:
      state = self.get_unsymbolized_data()

    return state.crash_state

  def get_stacktrace(self, symbolized=True):
    """Return the crash stacktrace."""
    if symbolized:
      state = self.get_symbolized_data()
    else:
      state = self.get_unsymbolized_data()

    return state.crash_stacktrace

  def get_type(self):
    """Return the crash type."""
    # It does not matter whether we use symbolized or unsymbolized data.
    state = self.get_unsymbolized_data()
    return state.crash_type

  def is_crash(self, ignore_state=False):
    """Return True if this result was a crash."""
    crashed = crash_analyzer.is_crash(self.return_code, self.output)
    if not crashed:
      return False

    state = self.get_state(symbolized=False)
    if not state.strip() and not ignore_state:
      return False
    return True

  def should_ignore(self):
    """Return True if this crash should be ignored."""
    state = self.get_symbolized_data()
    return crash_analyzer.ignore_stacktrace(state.crash_stacktrace)

  def is_security_issue(self):
    """Return True if this crash is a security issue."""
    state = self.get_unsymbolized_data()
    return crash_analyzer.is_security_issue(
        state.crash_stacktrace, state.crash_type, state.crash_address)
