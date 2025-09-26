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

import datetime
import json
import os

from google.cloud import logging_v2

from appengine.handlers.testcase_detail import testcase_status_events
from clusterfuzz._internal.system import environment

def execute(args):
  """"""
  del args

  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['LOG_TO_GCP'] = ''

  # history = testcase_status_events.get_testcase_event_history(5183725214138368)
  response = testcase_status_events.get_task_log(
      5183725214138368, 'bfc3e657-8861-4f4d-8a29-300f23b6dadd', 'impact')
  print(response)
