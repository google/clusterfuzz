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
"""Debugger script."""

from clusterfuzz._internal.system import environment
from appengine.handlers.testcase_detail import show

import os


def execute(args):
  """"""
  del args

  environment.set_bot_environment()
  os.environ['LOG_TO_CONSOLE'] = 'True'
  os.environ['LOCAL_DEVELOPMENT'] = 'True'
  os.environ['LOG_TO_GCP'] = ''

  # event = events.get_latest_testcase_analyze_event(5122269407805440)
  # event = events.get_latest_testcase_analyze_event(4566648589582336)
  # event = events.get_latest_testcase_rejection_event(5095170395537408)

  boards = show.get_testcase_status_machine_info(4506375602241536)
  for board_name, board_data in boards.items():
    print(f"{board_name}:")
    for key, value in board_data.items():
      print(f"  {key}: {value}")