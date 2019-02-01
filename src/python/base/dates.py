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
"""Date or time helper functions."""

import time

from base import utils
from system import environment


def initialize_timezone_from_environment():
  """Initializes timezone for date functions based on environment."""
  plt = environment.platform()
  if plt == 'WINDOWS':
    return

  # Only available on Unix platforms.
  time.tzset()


def time_has_expired(timestamp,
                     compare_to=None,
                     days=0,
                     hours=0,
                     minutes=0,
                     seconds=0):
  """Checks to see if a timestamp is older than another by a certain amount."""
  if compare_to is None:
    compare_to = utils.utcnow()

  total_time = days * 3600 * 24 + hours * 3600 + minutes * 60 + seconds
  return (compare_to - timestamp).total_seconds() > total_time
