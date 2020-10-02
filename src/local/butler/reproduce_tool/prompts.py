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
"""Console input functions for the reproduce tool."""


def get_string(prompt):
  """Prompt the user for a string from console input."""
  return input(prompt + ': ')


def get_boolean(prompt):
  """Return a boolean representing a yes/no answer to a prompt."""
  result = get_string(prompt + ' (Y/n)')
  return result.lower() == 'y'
