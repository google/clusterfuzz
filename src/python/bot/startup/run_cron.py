# Copyright 2023 Google LLC
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
"""Starts the cron scripts."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

import importlib
import sys

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

CRON_TASKS = ['backup']


def main():
  """Runs the cron jobs"""
  logs.configure('run_cron')

  root_directory = environment.get_value('ROOT_DIR')
  local_config.ProjectConfig().set_environment()

  if not root_directory:
    print('Please set ROOT_DIR environment variable to the root of the source '
          'checkout before running. Exiting.')
    print('For an example, check init.bash in the local directory.')
    return 1

  task = sys.argv[1]
  if task not in CRON_TASKS:
    print('Invalid task name. '
          f'Please enter one of the following tasks: {CRON_TASKS}')
    return 1

  task_module_name = f'clusterfuzz._internal.bot.tasks.cron.{task}'
  task_module = importlib.import_module(task_module_name)
  return 0 if task_module.main() else 1


if __name__ == '__main__':
  with ndb_init.context():
    sys.exit(main())
