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

import uuid

from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.datastore import data_types
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


def _get_uworker_env(fuzzer, job):
  """Prepares the complete environment variables for the payload."""
  uworker_env = _get_job_environment(job)
  uworker_env.update(_get_fuzzer_environment(fuzzer, job))

  # Replicate what process_command_impl does in a real tworker
  uworker_env['TASK_NAME'] = 'fuzz'
  uworker_env['TASK_ARGUMENT'] = fuzzer
  uworker_env['JOB_NAME'] = job

  # Add logging metadata to be carried over to uworker_main
  uworker_env['CF_TASK_NAME'] = 'fuzz'
  uworker_env['CF_TASK_JOB_NAME'] = job
  uworker_env['CF_TASK_ARGUMENT'] = fuzzer
  uworker_env['CF_TASK_ID'] = str(uuid.uuid4())

  return uworker_env


def execute(args):
  """Executes the preprocess command."""
  if not args.script_args or len(args.script_args) < 2:
    print('Usage: python butler.py run preprocess <fuzzer> <job>')
    return

  fuzzer = args.script_args[0]
  job = args.script_args[1]

  environment.set_value('LOG_TO_CONSOLE', True)
  logs.configure('run_bot')

  print(f'Running preprocess for fuzzer: {fuzzer}, job: {job}')

  uworker_env = _get_uworker_env(fuzzer, job)

  # tworker_preprocess expects: (module, task_argument, job_type, uworker_env)
  # For fuzz task, task_argument is fuzzer_name.
  result = utasks.tworker_preprocess(fuzz_task, fuzzer, job, uworker_env)

  if result:
    download_url, _ = result
    print('\nPreprocess successful!')
    print(f'Input Download URL: {download_url}')
  else:
    print('\nPreprocess failed or returned no result.')
