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

import functools

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.system import environment


class HostException(SystemExit):
  """Unrecoverable Exception."""


def untrusted_noop(return_value=None):
  """Return a decorator that turns functions into no-ops if the bot is
  untrusted."""

  def decorator(func):
    """Decorator function."""

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
      if environment.is_untrusted_worker():
        return return_value

      return func(*args, **kwargs)

    return wrapped

  return decorator


def internal_network_domain():
  """Return the internal network domain."""
  return '.c.%s.internal' % utils.get_application_id()


def platform_name(project, platform):
  """"Get the untrusted platform name."""
  return project.upper() + '_' + platform.upper()


def queue_name(project, platform):
  """Get the untrusted queue name for the project and platform."""
  return tasks.queue_for_platform(platform_name(project, platform))
