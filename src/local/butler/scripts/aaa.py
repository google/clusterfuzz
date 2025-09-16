# Copyright 2025 Google LLC
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
"""Test script."""

from clusterfuzz._internal.system import environment
from appengine.handlers.testcase_detail import show
from appengine.handlers.testcase_detail import testcase_status_events

import os


def execute(args):
  """"""
  del args

  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['LOG_TO_GCP'] = ''

  # dev 4566648589582336
  # dev 5095170395537408
  # dev 4506375602241536

  history = testcase_status_events.get_testcase_event_history(5095170395537408)
  for event in history:
    print(event['timestamp'])
