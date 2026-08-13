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
"""Helpers for untrusted runner."""

from collections.abc import Callable
import functools
from typing import Any
from typing import overload
from typing import ParamSpec
from typing import TypeVar

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.system import environment

_P = ParamSpec('_P')
_R = TypeVar('_R')
_T = TypeVar('_T')


class HostError(SystemExit):
  """Unrecoverable Exception."""


@overload
def untrusted_noop() -> Callable[[Callable[_P, _T]], Callable[_P, _T | None]]:
  ...


@overload
def untrusted_noop(return_value: _R,
                  ) -> Callable[[Callable[_P, _T]], Callable[_P, _T | _R]]:
  ...


def untrusted_noop(return_value: Any = None,
                  ) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
  """Return a decorator that turns functions into no-ops if the bot is
  untrusted."""

  def decorator(func: Callable[_P, Any]) -> Callable[_P, Any]:
    """Decorator function."""

    @functools.wraps(func)
    def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> Any:
      if environment.is_untrusted_worker():
        return return_value

      return func(*args, **kwargs)

    return wrapped

  return decorator


def internal_network_domain() -> str:
  """Return the internal network domain."""
  return '.c.%s.internal' % utils.get_application_id()


def platform_name(project: str, platform: str) -> str:
  """"Get the untrusted platform name."""
  return project.upper() + '_' + platform.upper()


def queue_name(project: str, platform: str) -> str:
  """Get the untrusted queue name for the project and platform."""
  return tasks.queue_for_platform(platform_name(project, platform))
