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
"""Compute Engine helpers."""

import datetime
import random
import six
import time

from googleapiclient.discovery import build

from base import dates
from base import persistent_cache
from metrics import logs

GCE_INSTANCE_INFO_KEY = 'gce_instance_info'
NUM_RETRIES = 10
OPERATION_TIMEOUT = 15 * 60
POLL_INTERVAL = 30
SLEEP_TIME = 10

# TODO(ochang): Allow batching.


def _add_metadata_key_value(items, key, value):
  """Adds a metadata key/value to the "items" list from an instance's
  metadata."""
  replaced_existing = False
  for item in items:
    if item['key'] == key:
      replaced_existing = True
      item['value'] = value
      break

  if not replaced_existing:
    items.append({'key': key, 'value': value})


def _do_operation_with_retries(operation, project, zone, wait_for_completion):
  """Execute an operation, retrying on any exceptions."""
  response = _execute_api_call_with_retries(operation)
  if response is None:
    return False

  if not wait_for_completion:
    # No need to wait, so we are done.
    return True

  for _ in range(NUM_RETRIES + 1):
    try:
      # This could cause exceptions when the response is not ready.
      _wait_for_operation(response, project, zone)
      return True
    except Exception:
      logs.log_error('Failed to wait for Compute Engine operation. '
                     'Original response is %s.' % str(response))
      time.sleep(SLEEP_TIME)
      continue

  return False


def _do_instance_operation(operation, instance_name, project, zone,
                           wait_for_completion):
  """Do a start/reset/stop on the compute engine instance in the given project
  and zone."""
  api = _get_api()
  operation_func = getattr(api.instances(), operation)
  operation = operation_func(instance=instance_name, project=project, zone=zone)

  return _do_operation_with_retries(
      operation, project, zone, wait_for_completion=wait_for_completion)


def _execute_api_call_with_retries(api_func):
  """Execute the given API call, retrying if neccessary. Returns the response if
  successful, or None."""
  last_exception = None
  for i in range(NUM_RETRIES + 1):
    try:
      # Try to execute the operation.
      response = api_func.execute()
      last_exception = None
      break
    except Exception as e:
      # Exponential backoff.
      last_exception = str(e)
      sleep_time = random.uniform(1, SLEEP_TIME * (1 << i))
      time.sleep(sleep_time)
      continue

  if last_exception is not None:
    # Failed, log exception with as much information as we can.
    if hasattr(api_func, 'uri'):
      uri = api_func.uri
    else:
      uri = 'unknown'

    logs.log_error('Compute engine API call "%s" failed with exception:\n%s' %
                   (uri, last_exception))
    return None

  return response


def _get_api():
  """Return the compute engine api object."""
  return build('compute', 'v1', cache_discovery=False)


def _get_instance_info(instance_name, project, zone):
  """Return the instance information for a given instance."""
  api = _get_api()
  instance_info_func = api.instances().get(
      instance=instance_name, project=project, zone=zone)
  return _execute_api_call_with_retries(instance_info_func)


def _get_metadata_and_fingerprint(instance_name, project, zone):
  """Return the metadata values and fingerprint for the given instance."""
  instance_info = _get_instance_info(instance_name, project, zone)
  if not instance_info:
    logs.log_error('Failed to fetch instance metadata')
    return None, None

  fingerprint = instance_info['metadata']['fingerprint']
  metadata_items = instance_info['metadata']['items']
  return metadata_items, fingerprint


def _wait_for_operation(response, project, zone):
  """Wait for the given operation to complete."""
  if 'status' in response and response['status'] == 'DONE':
    return

  if 'kind' not in response or response['kind'] != 'compute#operation':
    logs.log_error('Compute api response not an operation.')
    return

  api = _get_api()
  operation = response['name']
  start_time = datetime.datetime.utcnow()

  while not dates.time_has_expired(start_time, seconds=OPERATION_TIMEOUT):
    operation_func = api.zoneOperations().get(
        operation=operation, project=project, zone=zone)
    response = _execute_api_call_with_retries(operation_func)

    if 'status' not in response:
      logs.log_error('Invalid compute engine operation %s.' % str(operation))
      return

    if response['status'] == 'DONE':
      return

    time.sleep(POLL_INTERVAL)

  logs.log_error('Compute engine operation %s timed out.' % str(operation))


def add_metadata(instance_name, project, zone, key, value, wait_for_completion):
  """Add metadata to an existing instance. Replaces existing metadata values
  with the same key."""
  existing_metadata, fingerprint = _get_metadata_and_fingerprint(
      instance_name, project, zone)
  if not existing_metadata:
    return False

  _add_metadata_key_value(existing_metadata, key, value)

  api = _get_api()
  operation = api.instances().setMetadata(
      body={
          'fingerprint': fingerprint,
          'items': existing_metadata,
      },
      instance=instance_name,
      project=project,
      zone=zone)

  return _do_operation_with_retries(operation, project, zone,
                                    wait_for_completion)


def create_disk(disk_name,
                source_image,
                size_gb,
                project,
                zone,
                wait_for_completion=False):
  """Create a disk."""
  api = _get_api()
  operation = api.disks().insert(
      body={
          'name': disk_name,
          'sizeGb': size_gb,
      },
      sourceImage=source_image,
      project=project,
      zone=zone)

  return _do_operation_with_retries(
      operation, project, zone, wait_for_completion=wait_for_completion)


def delete_disk(disk_name, project, zone, wait_for_completion=False):
  """Delete a disk."""
  api = _get_api()
  operation = api.disks().delete(disk=disk_name, project=project, zone=zone)

  return _do_operation_with_retries(
      operation, project, zone, wait_for_completion=wait_for_completion)


def recreate_instance_with_disks(instance_name,
                                 project,
                                 zone,
                                 additional_metadata=None,
                                 wait_for_completion=False):
  """Recreate an instance and its disk."""
  # Get existing instance information.
  # First, try to get instance info from cache.
  # TODO(ochang): Make this more general in case anything else needs to use
  # this method (e.g. appengine).
  instance_info = persistent_cache.get_value(GCE_INSTANCE_INFO_KEY)
  if instance_info is None:
    instance_info = _get_instance_info(instance_name, project, zone)

  # Bail out if we don't have a valid instance information.
  if (not instance_info or 'disks' not in instance_info or
      not instance_info['disks']):
    logs.log_error(
        'Failed to get disk info from existing instance, bailing on instance '
        'recreation.')
    return False

  # Add any additional metadata required for instance booting.
  if additional_metadata:
    for key, value in six.iteritems(additional_metadata):
      items = instance_info.setdefault('metadata', {}).setdefault('items', [])
      _add_metadata_key_value(items, key, value)

  # Cache the latest instance information.
  persistent_cache.set_value(
      GCE_INSTANCE_INFO_KEY, instance_info, persist_across_reboots=True)

  # Delete the instance.
  if not _do_instance_operation(
      'delete', instance_name, project, zone, wait_for_completion=True):
    logs.log_error('Failed to delete instance.')
    return False

  # Get existing disks information, and recreate.
  api = _get_api()
  disks = instance_info['disks']
  for disk in disks:
    disk_source = disk['source']
    disk_name = disk_source.split('/')[-1]

    disk_info_func = api.disks().get(disk=disk_name, project=project, zone=zone)
    disk_info = _execute_api_call_with_retries(disk_info_func)
    if 'sourceImage' not in disk_info or 'sizeGb' not in disk_info:
      logs.log_error(
          'Failed to get source image and size from existing disk, bailing on '
          'instance recreation.')
      return False

    size_gb = disk_info['sizeGb']
    source_image = disk_info['sourceImage']

    # Recreate the disk.
    if not delete_disk(disk_name, project, zone, wait_for_completion=True):
      logs.log_error('Failed to delete disk.')
      return False

    if not create_disk(
        disk_name,
        source_image,
        size_gb,
        project,
        zone,
        wait_for_completion=True):
      logs.log_error('Failed to recreate disk.')
      return False

  # Recreate the instance with the exact same configurations, but not
  # necessarily the same IPs.
  try:
    del instance_info['networkInterfaces'][0]['accessConfigs'][0]['natIP']
  except:
    # This is not a failure. When a bot is stopped, it has no ip/interface.
    pass
  try:
    del instance_info['networkInterfaces'][0]['networkIP']
  except:
    # This is not a failure. When a bot is stopped, it has no ip/interface.
    pass

  operation = api.instances().insert(
      body=instance_info, project=project, zone=zone)

  return _do_operation_with_retries(
      operation, project, zone, wait_for_completion=wait_for_completion)


def remove_metadata(instance_name, project, zone, key, wait_for_completion):
  """Remove a metadata key/value from an existing instance."""
  existing_metadata, fingerprint = _get_metadata_and_fingerprint(
      instance_name, project, zone)
  if not existing_metadata:
    return False

  filtered_metadata = []
  for item in existing_metadata:
    if item['key'] != key:
      filtered_metadata.append(item)

  if len(filtered_metadata) == len(existing_metadata):
    # Nothing to do.
    return True

  api = _get_api()
  operation = api.instances().setMetadata(
      body={
          'fingerprint': fingerprint,
          'items': filtered_metadata,
      },
      instance=instance_name,
      project=project,
      zone=zone)

  return _do_operation_with_retries(operation, project, zone,
                                    wait_for_completion)


def reset_instance(instance_name, project, zone, wait_for_completion=False):
  """Reset an instance."""
  return _do_instance_operation('reset', instance_name, project, zone,
                                wait_for_completion)
