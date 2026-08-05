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

import socket

import requests

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.system import environment

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


def get_preempted_status():
  """Gets the preemption status of the instance."""
  attribute_url = 'http://{}/computeMetadata/v1/instance/preempted'.format(
      _METADATA_SERVER)
  headers = {'Metadata-Flavor': 'Google'}
  # We use a short timeout and no retries because this is called frequently
  # in a background loop and should fail fast.
  response = requests.get(attribute_url, headers=headers, timeout=5)
  response.raise_for_status()
  return response.text


def is_preemptible():
  """Returns True if the instance is preemptible (or Spot)."""
  if is_gce():
    try:
      if get('instance/scheduling/preemptible').strip().upper() == 'TRUE':
        return True
    except Exception:
      pass

    try:
      if get('instance/scheduling/provisioning-model').strip().upper() == 'SPOT':
        return True
    except Exception:
      pass

  return bool(environment.get_value('PREEMPTIBLE'))


