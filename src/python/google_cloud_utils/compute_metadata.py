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
"""GCE metadata."""

import requests
import socket

from base import retry
from system import environment

_METADATA_SERVER = 'metadata.google.internal'

_RETRIES = 3
_DELAY = 1


@retry.wrap(
    retries=_RETRIES,
    delay=_DELAY,
    function='python.google_cloud_utils.compute_metadata.get')
def get(path):
  """Get GCE metadata value."""
  attribute_url = (
      'http://{}/computeMetadata/v1/'.format(_METADATA_SERVER) + path)
  headers = {'Metadata-Flavor': 'Google'}
  operations_timeout = environment.get_value('URL_BLOCKING_OPERATIONS_TIMEOUT')

  response = requests.get(
      attribute_url, headers=headers, timeout=operations_timeout)
  response.raise_for_status()
  return response.text


def is_gce():
  """Return whether or not we're on GCE."""
  try:
    sock = socket.create_connection((_METADATA_SERVER, 80))
    sock.close()
  except Exception:
    return False

  return True
