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
"""Get values from the global configuration."""

import base64

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment

BASE64_MARKER = 'base64;'


def get():
  """Return configuration data."""
  # The reproduce tool does not have access to datastore. Rather than try to
  # catch all uses and handle them individually, we catch any accesses here.
  if environment.get_value('REPRODUCE_TOOL'):
    return None

  return data_types.Config.query().get()


def get_value(key):
  """Return a configuration key value."""
  config = get()
  if not config:
    return None

  value = config.__getattribute__(key)

  # Decode if the value is base64 encoded.
  if value.startswith(BASE64_MARKER):
    return base64.b64decode(value[len(BASE64_MARKER):])

  return value


def get_value_for_job(data, target_job_type):
  """Parses a value for a particular job type. If job type is not found,
  return the default value."""
  # All data is in a single line, just return that.
  if ';' not in data:
    return data

  result = ''
  for line in data.splitlines():
    job_type, value = (line.strip()).split(';')
    if job_type == target_job_type or (job_type == 'default' and not result):
      result = value

  return result


def set_value(key, value):
  """Sets a configuration key value and commits change."""
  config = get()
  if not config:
    return

  try:
    config.__setattr__(key, value)
  except UnicodeDecodeError:
    value = '%s%s' % (BASE64_MARKER, base64.b64encode(value))
    config.__setattr__(key, value)

  config.put()
