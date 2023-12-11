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
"""Common functions for task creation for test cases."""

import dataclasses
from typing import List
from typing import Optional

from clusterfuzz._internal.base import bisection
from clusterfuzz._internal.base import tasks as taskslib
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import batch
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


@dataclasses.dataclass
class Task:
  """Representing a Task."""
  name: str
  argument: str
  job: str
  queue_for_platform: Optional[str] = None
  uworker_input = None

  def __init__(self,
               name: str,
               arg: str,
               job: str,
               queue_for_platform: Optional[str] = None):
    self.name = name
    self.argument = arg
    self.job = job
    self.queue_for_platform = queue_for_platform
    self.uworker_input = None


def mark_unreproducible_if_flaky(testcase, task_name,
                                 potentially_flaky) -> None:
  """Check to see if a test case appears to be flaky."""

  # If this run does not suggest that we are flaky, clear the flag and assume
  # that we are reproducible.
  if not potentially_flaky:
    testcase.set_metadata('potentially_flaky', False)
    return

  # If we have not been marked as potentially flaky in the past, don't mark
  # mark the test case as unreproducible yet. It is now potentially flaky.
  if not testcase.get_metadata('potentially_flaky'):
    testcase.set_metadata('potentially_flaky', True)

    # In this case, the current task will usually be in a state where it cannot
    # be completed. Recreate it.
    taskslib.add_task(task_name, testcase.key.id(), testcase.job_type)
    return

  # At this point, this test case has been flagged as potentially flaky twice.
  # It should be marked as unreproducible. Mark it as unreproducible, and set
  # fields that cannot be populated accordingly.
  if task_name == 'minimize' and not testcase.minimized_keys:
    testcase.minimized_keys = 'NA'
  if task_name in ['minimize', 'impact']:
    testcase.set_impacts_as_na()
  if task_name in ['minimize', 'regression']:
    testcase.regression = 'NA'
  if task_name in ['minimize', 'progression']:
    testcase.fixed = 'NA'

  testcase.one_time_crasher_flag = True
  data_handler.update_testcase_comment(testcase, data_types.TaskState.ERROR,
                                       'Testcase appears to be flaky')

  # Issue update to flip reproducibility label is done in App Engine cleanup
  # cron. This avoids calling the issue tracker apis from GCE.

  # For unreproducible testcases, it is still beneficial to get component
  # information from blame task.
  schedule_tasks([create_blame_task_if_needed(testcase)])

  # Let bisection service know about flakiness.
  bisection.request_bisection(testcase)


def create_blame_task_if_needed(testcase) -> Optional[Task]:
  """Creates a blame task if needed."""
  # Blame doesn't work for non-chromium projects.
  if not utils.is_chromium():
    return None

  # Blame is only applicable to chromium project, otherwise bail out.
  if testcase.is_chromium():
    return None

  # We cannot run blame job for custom binaries since we don't have any context
  # on the crash revision and regression range.
  if build_manager.is_custom_binary():
    return None

  # Don't send duplicate issues to Predator. This causes issues with metrics
  # tracking and wastes cycles.
  if testcase.status == 'Duplicate':
    return None

  create_task = False
  if testcase.one_time_crasher_flag:
    # For unreproducible testcases, it is still beneficial to get component
    # information from blame task.
    create_task = True
  else:
    # Reproducible testcase.
    # Step 1: Check if the regression task finished. If not, bail out.
    if not testcase.regression:
      return None

    # Step 2: Check if the symbolize task is applicable and finished. If not,
    # bail out.
    if build_manager.has_symbolized_builds() and not testcase.symbolized:
      return None

    create_task = True

  if create_task:
    return Task('blame', testcase.key.id(), testcase.job_type)
  return None


def create_impact_task_if_needed(testcase) -> Optional[Task]:
  """Creates an impact task if needed."""
  # Impact doesn't make sense for non-chromium projects.
  if not utils.is_chromium():
    return None

  # Impact is only applicable to chromium project, otherwise bail out.
  if testcase.project_name != 'chromium':
    return None

  # We cannot run impact job for custom binaries since we don't have any
  # archived production builds for these.
  if build_manager.is_custom_binary():
    return None

  return Task('impact', testcase.key.id(), testcase.job_type)


def create_minimize_task_if_needed(testcase) -> Task:
  """Creates a minimize task if needed."""
  return Task('minimize', testcase.key.id(), testcase.job_type)


def create_regression_task_if_needed(testcase) -> Optional[Task]:
  """Creates a regression task if needed."""
  # We cannot run regression job for custom binaries since we don't have any
  # archived builds for previous revisions. We only track the last uploaded
  # custom build.
  if build_manager.is_custom_binary():
    return None

  return Task('regression', testcase.key.id(), testcase.job_type)


def create_variant_tasks_if_needed(testcase) -> List[Task]:
  """Creates a variant task if needed."""
  tasks = []
  if testcase.duplicate_of:
    # If another testcase exists with same params, no need to spend cycles on
    # calculating variants again.
    return []

  testcase_id = testcase.key.id()
  project = data_handler.get_project_name(testcase.job_type)
  jobs = data_types.Job.query(data_types.Job.project == project)
  testcase_job_is_engine = environment.is_engine_fuzzer_job(testcase.job_type)
  testcase_job_app_name = None
  if not testcase_job_is_engine:
    testcase_job = (
        data_types.Job.query(data_types.Job.name == testcase.job_type).get())
    testcase_job_environment = testcase_job.get_environment()
    testcase_job_app_name = testcase_job_environment.get('APP_NAME')
  num_variant_tasks = 0
  for job in jobs:
    # The variant needs to be tested in a different job type than us.
    job_type = job.name
    if testcase.job_type == job_type:
      continue

    # Don't try to reproduce engine fuzzer testcase with blackbox fuzzer
    # testcases and vice versa.
    if testcase_job_is_engine != environment.is_engine_fuzzer_job(job_type):
      continue

    # Skip experimental jobs.
    job_environment = job.get_environment()
    if utils.string_is_true(job_environment.get('EXPERIMENTAL')):
      continue

    # Skip jobs for which variant tasks are disabled.
    if utils.string_is_true(job_environment.get('DISABLE_VARIANT')):
      continue

    if (not testcase_job_is_engine and
        job_environment.get('APP_NAME') != testcase_job_app_name):
      continue
    queue = taskslib.queue_for_platform(job.platform)
    tasks.append(Task('variant', testcase_id, job_type, queue))

    variant = data_handler.get_or_create_testcase_variant(testcase_id, job_type)
    variant.status = data_types.TestcaseVariantStatus.PENDING
    variant.put()
    num_variant_tasks += 1
  logs.log(f'Number of variant tasks: {num_variant_tasks}.')
  return tasks


def create_symbolize_task_if_needed(testcase) -> Optional[Task]:
  """Creates a symbolize task if needed."""
  # We cannot run symbolize job for custom binaries since we don't have any
  # archived symbolized builds.
  if build_manager.is_custom_binary():
    return None

  # Make sure we have atleast one symbolized url pattern defined in job type.
  if not build_manager.has_symbolized_builds():
    return None

  return Task('symbolize', testcase.key.id(), testcase.job_type)


def create_tasks(testcase):
  """Create tasks like minimization, regression, impact, progression, stack
  stack for a newly generated testcase."""
  # No need to create progression task. It is automatically created by the cron
  # handler for reproducible testcases.

  # For a non reproducible crash.
  if testcase.one_time_crasher_flag:
    # For unreproducible testcases, it is still beneficial to get component
    # information from blame task.
    schedule_tasks([create_blame_task_if_needed(testcase)])
    return

  # For a fully reproducible crash.

  # MIN environment variable defined in a job definition indicates if
  # we want to do the heavy weight tasks like minimization, regression,
  # impact, etc on this testcase. These are usually skipped when we have
  # a large timeout and we can't afford to waste more than a couple of hours
  # on these jobs.
  testcase_id = testcase.key.id()
  if environment.get_value('MIN') == 'No':
    testcase = data_handler.get_testcase_by_id(testcase_id)
    testcase.minimized_keys = 'NA'
    testcase.regression = 'NA'
    testcase.set_impacts_as_na()
    testcase.put()
    return

  # Just create the minimize task for now. Once minimization is complete, it
  # automatically created the rest of the needed tasks.
  schedule_tasks([create_minimize_task_if_needed(testcase)])


def create_postminimize_tasks(testcase):
  """Create assorted tasks needed after minimize task completes."""
  tasks = []
  tasks.append(create_impact_task_if_needed(testcase))
  tasks.append(create_regression_task_if_needed(testcase))
  tasks.append(create_symbolize_task_if_needed(testcase))
  tasks.extend(create_variant_tasks_if_needed(testcase))
  schedule_tasks(tasks)


def is_remote_utask(task: Task) -> bool:
  """Returns True if |task| is supposed to be executed remotely (i.e. preprocess
  utask_main and postprocess on different machines."""
  command = task.name
  return task_types.COMMAND_TYPES[command].is_execution_remote()


def _preprocess(task: Task) -> None:
  """Runs preprocess portion of task and saves the uworker_input to task."""
  import commands
  task.uworker_input = commands.process_command_impl(task.name, task.argument,
                                                     task.job)


def start_utask_mains(tasks: List[Task]) -> None:
  """Start utask_main of multiple tasks as batch tasks on batch."""
  batch_tasks = [
      batch.BatchTask(task.name, task.job, task.uworker_input) for task in tasks
  ]
  batch.create_uworker_main_batch_jobs(batch_tasks)


def schedule_tasks(tasks: List[Task]):
  """Starts tasks as defined by task objects. If the tasks are not executed
  remotely, then they are put on the queue. If they are executed remotely, then
  the utask_mains are scheduled on batch, since preprocess has already been done
  in this module on this bot."""
  # uworker_tasks = []
  tasks = [task for task in tasks if task is not None]
  for task in tasks:
    # if not task_types.is_remote_utask(task.name):
    taskslib.add_task(task.name, task.argument, task.job,
                      task.queue_for_platform)
  #   continue
  # TODO(metzman): Reenable utask_mains after us-west2 is tested.
  #   _preprocess(task)
  #   uworker_tasks.append(task)

  # start_utask_mains(uworker_tasks)
