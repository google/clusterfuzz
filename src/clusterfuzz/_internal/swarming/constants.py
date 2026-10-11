# Copyright 2026 Google LLC
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
"""Constants for Swarming API interaction."""

from google.protobuf import json_format
from google.protobuf.timestamp_pb2 import \
    Timestamp  # pylint: disable=no-name-in-module

# TODO(b/516627559): Move scopes to config file
SWARMING_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email',
]

COUNT_TASKS_ENDPOINT = '/prpc/swarming.v2.Tasks/CountTasks'
NEW_TASK_ENDPOINT = '/prpc/swarming.v2.Tasks/NewTask'

XSSI_PREFIX = ")]}'\n"

MIN_TASK_START_TIME = '2026-06-01T00:00:00Z'
MIN_TASK_START_TIME_PROTO = json_format.Parse(f'"{MIN_TASK_START_TIME}"',
                                              Timestamp())
