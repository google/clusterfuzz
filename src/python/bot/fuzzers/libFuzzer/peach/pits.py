# Copyright 2020 Google LLC
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
"""Dictionary to keep track of pit information."""

from system import environment
import os

PIT_DIR = os.path.join(environment.get_platform_resources_directory(), 'peach',
                       'pits')
PATH = 0
TITLE = 1
# The key is the name of the grammar as defined in the libfuzzer options file.
# The value is the path to the pit, and the title of the pit.
PIT_INFORMATION = {"PDF": (os.path.join(PIT_DIR, 'pdf.xml'), 'PDF')}


def validate(grammar):
  return grammar in PIT_INFORMATION


def get_path(grammar):
  return PIT_INFORMATION[grammar][PATH]


def get_title(grammar):
  return PIT_INFORMATION[grammar][TITLE]
