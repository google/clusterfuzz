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

import collections
from typing import Any
from typing import Callable
from typing import Optional
from typing import ParamSpec
from typing import TypeVar

import flask

from clusterfuzz._internal.base import memoize
from clusterfuzz._internal.metrics import logs

_P = ParamSpec('_P')
_R = TypeVar('_R')


def get_current_request() -> Any:
  """Get the current request."""
  return flask.request


def get_cache_backing() -> Any:
  """Get the cache backing for saving current context data."""
  return flask.g


class _FifoRequestCache(memoize.FifoInMemory):
  """In memory caching engine scoped to a request."""

  def __init__(self, cache_key: Any, capacity: int) -> None:
    super().__init__(capacity)
    self._cache_key = str(cache_key)

  @property
  def cache(self) -> Optional[collections.OrderedDict[Any, Any]]:
    """Get the cache backing."""
    cache_backing = get_cache_backing()
    if not cache_backing:
      # Not a cache (e.g. in a unit test). Should not happen in production.
      logs.error('No container found for cache.')
      return None

    key = '__cache:' + self._cache_key

    backing = getattr(cache_backing, key, None)
    if backing is None:
      backing = collections.OrderedDict()
      setattr(cache_backing, key, backing)

    return backing


def wrap(capacity: int) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
  """Wraps a function to use the per request cache."""

  def decorator(func: Callable[_P, _R]) -> Callable[_P, _R]:
    """Decorator function."""
    engine = _FifoRequestCache(id(func), capacity)
    return memoize.wrap(engine)(func)

  return decorator
