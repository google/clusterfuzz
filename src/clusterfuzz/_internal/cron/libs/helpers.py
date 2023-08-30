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
"""helper.py is a kitchen sink. It contains static methods that are used by
   multiple handlers."""

import sys
import traceback

class EarlyExitError(Exception):
  """Serve as an exception for exiting a handler's method early."""

  def __init__(self, message, status, trace_dump=None):
    super().__init__(message)
    self.status = status
    self.trace_dump = trace_dump
    if self.trace_dump is None:
      if sys.exc_info()[0] is not None:
        self.trace_dump = traceback.format_exc()
      else:
        self.trace_dump = ''.join(traceback.format_stack())

  def to_dict(self):
    """Build dict that is used for JSON serialisation."""
    return {
        'traceDump': self.trace_dump,
        'message': str(self),
        # 'email': get_user_email(),
        'status': self.status,
        'type': self.__class__.__name__
    }
