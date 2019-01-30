# Copyright 2018 Google LLC
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
"""Android helpers."""


def is_build_at_least(current_version, other_version):
  """Returns whether or not |current_version| is at least as new as
  |other_version|."""
  if current_version is None:
    return False

  # Turn master build versions into a large value for comparison.
  if current_version == 'A':
    current_version = chr(255)

  if other_version == 'A':
    other_version = chr(255)

  return current_version >= other_version
