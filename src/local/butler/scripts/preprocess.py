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
"""preprocess.py runs the preprocess step of a utask locally, as a tworker
would, and prints the signed URL of the input its uworker_main needs.

Requires the given idenity to have the `roles/secretmanager.secretAccessor`
role in the target ClusterFuzz instance.

Usage:
  butler.py run preprocess -c <config_dir> --non-dry-run --script_args \
      --task <task> --argument <fuzzer|fuzz target|testcase id> [--job <job>]
"""

import argparse
import dataclasses
import uuid

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.common import testcase_utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


class PreprocessError(Exception):
  """A task is missing something it needs to be preprocessed."""


@dataclasses.dataclass
class TaskRequisites:
  """Datastore entities a task is preprocessed with: its job and the entity
  its argument identifies."""
  job: data_types.Job
  fuzzer: data_types.Fuzzer | None = None
  fuzz_target: data_types.FuzzTarget | None = None
  testcase: data_types.Testcase | None = None


def get_preprocess_tasks() -> list[str]:
  """Returns the names of the tasks that have a preprocess step."""
  return sorted(name for name, task in commands.COMMAND_MAP.items()
                if isinstance(task, task_types.BaseUTask))


def _parse_args(script_args: list[str] | None) -> argparse.Namespace:
  """Parses the script arguments."""
  parser = argparse.ArgumentParser(
      prog='butler.py run preprocess -c <config_dir> --script_args',
      description='Runs the preprocess step of a task locally.')
  parser.add_argument(
      '--task',
      required=True,
      choices=get_preprocess_tasks(),
      help='Name of the task to run the preprocess step of.')
  parser.add_argument(
      '--argument',
      required=True,
      help='Task argument: a fuzzer (fuzz), a fuzz target (corpus_pruning) or '
      'a testcase id (any other task).')
  parser.add_argument(
      '--job',
      help='Job to run the task with. Required for fuzz and corpus_pruning; '
      'defaults to the testcase job for other tasks.')
  return parser.parse_args(script_args or [])


def get_task_requisites(task_name: str,
                        task_argument: str,
                        job_name: str | None = None) -> TaskRequisites:
  """Retrieves what a task needs to be preprocessed.

  Every task needs a job. On top of it, fuzz needs a fuzzer, corpus_pruning
  needs a fuzz target, and any other task needs a testcase, which for analyze
  must be one a user uploaded.

  Args:
    task_name: The task's command (e.g. fuzz).
    task_argument: The fuzzer name, fuzz target name or testcase id.
    job_name: The job to run the task with. Testcase tasks default to the job
      of the testcase.

  Returns:
    The job and the fuzzer, fuzz target or testcase the argument identifies.

  Raises:
    errors.InvalidTestcaseError: If the testcase does not exist.
    PreprocessError: If anything else the task needs is missing.
  """
  fuzzer = fuzz_target = testcase = None
  if task_utils.is_testcase_based_task(task_name):
    testcase = data_handler.get_testcase_by_id(task_argument)
    job_name = job_name or testcase.job_type
  elif task_name == 'fuzz':
    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == task_argument).get()
    if not fuzzer:
      raise PreprocessError('Fuzzer %s not found.' % task_argument)
  else:
    fuzz_target = data_handler.get_fuzz_target(task_argument)
    if not fuzz_target:
      raise PreprocessError('Fuzz target %s not found.' % task_argument)

  if not job_name:
    raise PreprocessError('Task %s needs a job.' % task_name)
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job:
    raise PreprocessError('Job %s not found.' % job_name)

  # Analyze preprocess deletes testcases that have no upload metadata.
  if (task_name == 'analyze' and
      not testcase_utils.get_testcase_upload_metadata(task_argument)):
    raise PreprocessError(
        'Testcase %s was not uploaded by a user, analyze would delete it.' %
        task_argument)

  return TaskRequisites(
      job=job, fuzzer=fuzzer, fuzz_target=fuzz_target, testcase=testcase)


def _set_up_task_environment(task_name: str, task_argument: str,
                             requisites: TaskRequisites) -> dict:
  """Sets the environment like a tworker that picked up the task.

  Returns:
    The uworker environment, whose JOB_NAME is the job to run the task with.
  """
  environment.set_bot_environment()
  environment.set_value('TWORKER', True)
  environment.set_value('REMOTE_UTASK_EXECUTION', True)
  environment.set_value('TASK_LEASE_SECONDS',
                        tasks.get_task_duration(task_name))
  return commands.update_environment_for_task(task_name, task_argument,
                                              requisites.job,
                                              requisites.testcase, uuid.uuid4())


@commands.set_task_payload
def preprocess_task(task_name: str, task_argument: str, job_name: str,
                    requisites: TaskRequisites) -> tuple[str, str] | None:
  """Sets up the tworker environment and runs preprocess for a task.

  Args:
    task_name: The task's command (e.g. fuzz).
    task_argument: The task's raw argument.
    job_name: The job the task was scheduled for.
    requisites: Datastore entities needed to set up the task environment.

  Returns:
    The (input_download_url, output_download_url) tuple from tworker_preprocess,
    or None if preprocessing failed.
  """
  uworker_env = _set_up_task_environment(task_name, task_argument, requisites)
  effective_job_name = uworker_env['JOB_NAME']

  print('Running %s preprocess for argument: %s, job: %s' %
        (task_name, task_argument, effective_job_name))
  return utasks.tworker_preprocess(commands.COMMAND_MAP[task_name].module,
                                   task_argument, effective_job_name,
                                   uworker_env)


def execute(args):
  """Preprocesses a task and prints the signed URL of its uworker input."""
  script_args = _parse_args(args.script_args)
  task_name = script_args.task
  task_argument = script_args.argument

  environment.set_value('LOG_TO_CONSOLE', True)
  logs.configure('run_bot')

  requisites = get_task_requisites(task_name, task_argument, script_args.job)
  if not args.non_dry_run:
    print('Dry-run mode: would preprocess %s for argument: %s, job: %s. '
          'Re-run with --non-dry-run to execute.' % (task_name, task_argument,
                                                     requisites.job.name))
    return

  result = preprocess_task(task_name, task_argument, requisites.job.name,
                           requisites)

  if result:
    download_url, _ = result
    print('\nPreprocess successful!')
    print('Input Download URL: %s' % download_url)
  else:
    print('\nPreprocess failed or returned no result.')
