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
"""Gestures related functions."""

import os
import random

from . import adb

# Fixed delay in milliseconds between consecutive monkey events.
MONKEY_THROTTLE_DELAY = 100

# Maximum number of monkey events per testcase.
NUM_MONKEY_EVENTS = 25


def get_random_gestures(_):
  """Return a random gesture seed from monkey framework natively supported by
  Android OS."""
  random_seed = random.getrandbits(32)
  gesture = 'monkey,%s' % str(random_seed)
  return [gesture]


def run_gestures(gestures, *_):
  """Run the provided interaction gestures."""
  package_name = os.getenv('PKG_NAME')
  if not package_name:
    # No package to send gestures to, bail out.
    return

  if len(gestures) != 1 or not gestures[0].startswith('monkey'):
    # Bad gesture string, bail out.
    return

  monkey_seed = gestures[0].split(',')[-1]
  adb.run_shell_command([
      'monkey', '-p', package_name, '-s', monkey_seed, '--throttle',
      str(MONKEY_THROTTLE_DELAY), '--ignore-security-exceptions',
      str(NUM_MONKEY_EVENTS)
  ])
