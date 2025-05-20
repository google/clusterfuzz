# Copyright 2025 Google LLC
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
"""Interface for dealing with Redis."""

import threading

from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system.environment import if_redis_available
from clusterfuzz._internal.system.environment import local_noop

# Thead local globals.
_local = threading.local()

_DEFAULT_REDIS_HOST = '10.5.219.187'
_DEFAULT_REDIS_PORT = 6379


@local_noop
@if_redis_available
def get(key):
  return client().get(key)


def client():
  """Get the redis client."""
  import redis

  if hasattr(_local, 'redis'):
    return _local.redis

  host = environment.get_value('REDIS_HOST', _DEFAULT_REDIS_HOST)
  port = environment.get_value('REDIS_PORT', _DEFAULT_REDIS_PORT)

  _local.redis = redis.Redis(host=host, port=port)
  return _local.redis
