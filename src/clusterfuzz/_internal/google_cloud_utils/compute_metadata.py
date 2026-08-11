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
_METADATA_URL = 'http://{}/computeMetadata/v1/'.format(_METADATA_SERVER)

_RETRIES = 3
_DELAY = 1


def _get_raw(path, timeout=None):
  """Internal helper to get metadata without retries."""
  attribute_url = _METADATA_URL + path
  headers = {'Metadata-Flavor': 'Google'}
  if timeout is None:
    timeout = environment.get_value('URL_BLOCKING_OPERATIONS_TIMEOUT')

  response = requests.get(attribute_url, headers=headers, timeout=timeout)
  response.raise_for_status()
  return response.text


@retry.wrap(
    retries=_RETRIES,
    delay=_DELAY,
    function='python.google_cloud_utils.compute_metadata.get')
def get(path):
  """Get GCE metadata value."""
  return _get_raw(path)


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
  # We use a short timeout and no retries because this is called frequently
  # in a background loop and should fail fast.
  return _get_raw('instance/preempted', timeout=5)


def is_preemptible():
  """Returns True if the instance is preemptible (or Spot)."""
  # Skip metadata queries on App Engine or K8s. These environments emulate or
  # proxy the metadata server but lack standard GCE scheduling keys, returning
  # 404 and causing unnecessary latency or errors if queried.
  if environment.is_running_on_app_engine() or environment.is_running_on_k8s():
    return bool(environment.get_value('PREEMPTIBLE'))

  if is_gce():
    # We ignore exceptions (mainly HTTPError if a key doesn't exist) to avoid
    # log noise for standard VMs where these keys might not be present.
    for path in [
        'instance/scheduling/preemptible',
        'instance/scheduling/provisioning-model'
    ]:
      try:
        value = _get_raw(path, timeout=2).strip().upper()
        if value in ['TRUE', 'SPOT']:
          return True
      except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
          continue
      except Exception:
        pass

  return bool(environment.get_value('PREEMPTIBLE'))
