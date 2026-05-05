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
"""preprocess.py runs the preprocess step of a fuzz task locally."""

import os
import sys
import uuid

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def _get_job_environment(job_name):
  """Fetches the job entity and returns its environment variables."""
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if job:
    return job.get_environment()
  raise RuntimeError(f'Error: Job {job_name} not found in Datastore.')


def _get_fuzzer_environment(fuzzer_name, job_name):
  """Fetches fuzzer entity and returns its additional environment variables."""
  if environment.is_engine_fuzzer_job(job_name):
    return {}

  fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
  if not fuzzer:
    raise RuntimeError(f'Error: Fuzzer {fuzzer_name} not found in Datastore.')

  additional_default_variables = ''
  additional_variables_for_job = ''

  if hasattr(
      fuzzer,
      'additional_environment_string') and fuzzer.additional_environment_string:
    for line in fuzzer.additional_environment_string.splitlines():
      if '=' in line and ':' in line.split('=', 1)[0]:
        fuzzer_job_name, environment_definition = line.split(':', 1)
        if fuzzer_job_name == job_name:
          additional_variables_for_job += '\n%s' % environment_definition
        continue
      additional_default_variables += '\n%s' % line

  env_string = additional_default_variables + additional_variables_for_job
  return environment.parse_environment_definition(env_string)


def _get_uworker_env(args):
  """Prepares the complete environment variables for the payload."""
  uworker_env = _get_job_environment(args.job)
  uworker_env.update(_get_fuzzer_environment(args.fuzzer, args.job))

  # Replicate what process_command_impl does in a real tworker
  uworker_env['TASK_NAME'] = 'fuzz'
  uworker_env['TASK_ARGUMENT'] = args.fuzzer
  uworker_env['JOB_NAME'] = args.job

  # Add logging metadata to be carried over to uworker_main
  uworker_env['CF_TASK_NAME'] = 'fuzz'
  uworker_env['CF_TASK_JOB_NAME'] = args.job
  uworker_env['CF_TASK_ARGUMENT'] = args.fuzzer
  uworker_env['CF_TASK_ID'] = str(uuid.uuid4())

  return uworker_env


def _early_setup(args):
  """Early setup needed for config and logs."""
  sys.path.insert(0, os.path.abspath(os.path.join('src', 'appengine')))
  sys.path.insert(
      0, os.path.abspath(os.path.join('src', 'appengine', 'third_party')))

  environment.set_value('CONFIG_DIR_OVERRIDE',
                        os.path.abspath(os.path.expanduser(args.config_dir)))
  environment.set_value('LOG_TO_CONSOLE', True)
  local_config.ProjectConfig().set_environment()
  logs.configure('run_bot')


def execute(args):
  """Executes the preprocess command."""
  _early_setup(args)

  print(f'Running preprocess for fuzzer: {args.fuzzer}, job: {args.job}')

  with ndb_init.context():
    uworker_env = _get_uworker_env(args)

    # tworker_preprocess expects: (module, task_argument, job_type, uworker_env)
    # For fuzz task, task_argument is fuzzer_name.
    result = utasks.tworker_preprocess(fuzz_task, args.fuzzer, args.job,
                                       uworker_env)

    if result:
      download_url, _ = result
      print('\nPreprocess successful!')
      print(f'Input Download URL: {download_url}')
    else:
      print('\nPreprocess failed or returned no result.')
