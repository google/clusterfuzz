# Copyright 2024 Google LLC
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
"""Module providing utilities for utask users. This module should not depend on
any other module in tasks to prevent circular imports and issues with
appengine."""

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.system import environment


def get_command_from_module(full_module_name: str) -> str:
  module_name = full_module_name.split('.')[-1]
  if not module_name.endswith('_task'):
    raise ValueError(f'{full_module_name} is not a real command')
  return module_name[:-len('_task')]


def is_remotely_executing_utasks(task=None) -> bool:
  """Returns True if the utask_main portions of utasks are being remotely
  executed on Google cloud batch."""
  if bool(environment.is_production() and
          environment.get_value('REMOTE_UTASK_EXECUTION')):
    return True
  if task is None:
    return False
  return bool(is_task_opted_into_uworker_execution(task))


def get_opted_in_tasks():
  return local_config.ProjectConfig().get('uworker_tasks', [])


def is_task_opted_into_uworker_execution(task: str) -> bool:
  # TODO(metzman): Remove this after OSS-Fuzz and Chrome are at parity.
  uworker_tasks = get_opted_in_tasks()
  return task in uworker_tasks


class UworkerMsgParseError(RuntimeError):
  """Error for parsing UworkerMsgs."""
