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
"""Lock functions."""
# NOTE: Deprecated. Avoid using.

import datetime
import random
import time

from google.cloud import ndb
from google.cloud.ndb import exceptions

from config import db_config
from datastore import data_types
from metrics import logs
from system import environment

DEFAULT_MAX_HOLD_SECONDS = 60 * 10

LOCK_CHECK_SLEEP_MULTIPLIER = 10
LOCK_CHECK_TIMEOUT = 60 * 60

MAX_WAIT_EXPONENT = 6
NUM_STATISTICS_SHARDS = 50

TRANSACTION_RETRIES = 0


def _get_current_lock_zone():
  """Get the current zone for locking purposes."""
  if environment.get_value('LOCAL_DEVELOPMENT', False):
    return 'local'

  platform = environment.get_platform_group().lower()
  platform_group_mappings = db_config.get_value('platform_group_mappings')
  for mapping in platform_group_mappings.splitlines():
    if ';' not in mapping:
      continue

    platform_group, zone = mapping.split(';')
    if platform_group.strip() == platform:
      return zone

  # Default to per-platform seperation.
  logs.log_warn('Platform group mapping not set in admin configuration, '
                'using default platform - %s.' % platform)
  return platform


def _get_key_name_with_lock_zone(key_name):
  """Return the lock key name with the current lock zone."""
  current_zone = _get_current_lock_zone()
  if not current_zone:
    logs.log_error('Could not find zone.')
    return None

  return current_zone + ';' + key_name


def _try_acquire_lock(key_name, expiration_time, holder):
  """Actual lock acquire that runs in a transaction."""
  lock_entity = ndb.Key(data_types.Lock, key_name).get()

  if lock_entity is None:
    # Lock wasn't held, try to acquire.
    lock_entity = data_types.Lock(
        id=key_name, expiration_time=expiration_time, holder=holder)
    lock_entity.put()
    return lock_entity

  if lock_entity.expiration_time <= datetime.datetime.utcnow():
    # Lock was expired, try to take over the lock.
    lock_entity.expiration_time = expiration_time
    lock_entity.holder = holder
    lock_entity.put()

  return lock_entity


def acquire_lock(key_name,
                 max_hold_seconds=DEFAULT_MAX_HOLD_SECONDS,
                 retries=None,
                 by_zone=True):
  """Acquire a lock for the given key name. Returns the expiration time if
  succeeded, otherwise None. The lock holder is responsible for making sure it
  doesn't assume the lock is still held after the expiration time."""
  logs.log('Acquiring lock for %s.' % key_name)
  failed_acquires = 0
  total_wait = 0
  wait_exponent = 1

  if by_zone:
    key_name_with_zone = _get_key_name_with_lock_zone(key_name)
    if key_name_with_zone is None:
      logs.log_error('Failed to get zone while trying to lock %s.' % key_name)
      return None

    key_name = key_name_with_zone

  bot_name = environment.get_value('BOT_NAME')
  expiration_delta = datetime.timedelta(seconds=max_hold_seconds)
  while total_wait < LOCK_CHECK_TIMEOUT:
    try:
      lock_entity = ndb.transaction(
          lambda: _try_acquire_lock(key_name,
                                    expiration_time=datetime.datetime.utcnow() +
                                    expiration_delta, holder=bot_name),
          retries=TRANSACTION_RETRIES)

      if lock_entity.holder == bot_name:
        logs.log('Got the lock.')
        return lock_entity.expiration_time
    except exceptions.Error:
      pass

    failed_acquires += 1
    if retries and retries >= failed_acquires:
      logs.log('Failed to acquire lock, exceeded max retries.')
      return None

    logs.log('Failed to acquire lock, waiting...')

    # Exponential backoff.
    max_sleep = (1 << wait_exponent) * LOCK_CHECK_SLEEP_MULTIPLIER
    sleep_time = random.uniform(1.0, max_sleep)
    time.sleep(sleep_time)

    total_wait += sleep_time
    wait_exponent = min(wait_exponent + 1, MAX_WAIT_EXPONENT)

  logs.log('Timeout exceeded while trying to acquire lock, bailing.')
  return None


def release_lock(key_name, force_release=False, by_zone=True):
  """Release a lock for the given key name."""
  logs.log('Releasing lock for %s.' % key_name)
  bot_name = environment.get_value('BOT_NAME')

  if by_zone:
    key_name_with_zone = _get_key_name_with_lock_zone(key_name)
    if key_name_with_zone is None:
      logs.log_error('Failed to get zone while releasing %s.' % key_name)
      return

    key_name = key_name_with_zone

  lock_entity = ndb.Key(data_types.Lock, key_name).get()
  if lock_entity and (force_release or lock_entity.holder == bot_name):
    lock_entity.key.delete()
