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
"""Request specific caching.."""

from builtins import str
import collections

from base import memoize
from libs import auth
from metrics import logs


class _FifoRequestCache(memoize.FifoInMemory):
  """In memory caching engine scoped to a request."""

  def __init__(self, cache_key, capacity):
    super(_FifoRequestCache, self).__init__(capacity)
    self._cache_key = str(cache_key)

  @property
  def cache(self):
    """Get the cache backing."""
    request = auth.get_current_request()
    if not request:
      # Not a request (e.g. in a unit test). Should not happen in production.
      logs.log_error('No request found for cache.')
      return None

    key = '__cache:' + self._cache_key

    cache_backing = auth.get_cache_backing()
    backing = getattr(cache_backing, key, None)
    if backing is None:
      backing = collections.OrderedDict()
      setattr(cache_backing, key, backing)

    return backing


def wrap(capacity):
  """Wraps a function to use the per request cache."""

  def decorator(func):
    """Decorator function."""
    engine = _FifoRequestCache(id(func), capacity)
    return memoize.wrap(engine)(func)

  return decorator
