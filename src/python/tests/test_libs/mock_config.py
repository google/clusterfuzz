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
"""Mock config."""


class MockConfig(object):
  """Mock config."""

  def __init__(self, data):
    self._data = data

  def get(self, key_name='', default=None):
    """Get key value using a key name."""
    parts = key_name.split('.')
    value = self._data
    for part in parts:
      if part not in value:
        return default

      value = value[part]

    return value

  def sub_config(self, path):
    return MockConfig(self.get(path))
