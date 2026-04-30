# Copyright 2026 Google LLC
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
"""uworker_preprocess.py runs the preprocess step of a fuzz task locally."""

import os
import sys

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.metrics import logs


def execute(args):
  """Executes the uworker_preprocess command."""
  sys.path.insert(0, os.path.abspath(os.path.join('src', 'appengine')))
  sys.path.insert(
      0, os.path.abspath(os.path.join('src', 'appengine', 'third_party')))
  
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(os.path.expanduser(args.config_dir))
  local_config.ProjectConfig().set_environment()
  
  # We want to act as a tworker, so we configure logs accordingly.
  logs.configure('run_bot')
  
  print(f'Running preprocess for fuzzer: {args.fuzzer}, job: {args.job}')
  
  with ndb_init.context():
    uworker_env = {}
    
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('JOB_NAME', args.job)
    
    # tworker_preprocess expects: (module, task_argument, job_type, uworker_env)
    # For fuzz task, task_argument is fuzzer_name.
    result = utasks.tworker_preprocess(fuzz_task, args.fuzzer, args.job, uworker_env)
    
    if result:
      download_url, _ = result
      print(f'\nPreprocess successful!')
      print(f'Input Download URL: {download_url}')
    else:
      print('\nPreprocess failed or returned no result.')
