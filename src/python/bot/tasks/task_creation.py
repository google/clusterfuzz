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

from base import tasks
from base import utils
from build_management import build_manager
from datastore import data_handler
from datastore import data_types
from system import environment


def mark_unreproducible_if_flaky(testcase, potentially_flaky):
  """Check to see if a test case appears to be flaky."""
  task_name = environment.get_value('TASK_NAME')

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
    tasks.add_task(task_name, testcase.key.id(), testcase.job_type)
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

  # For unreproducible testcases, it is still beneficial to get second stack
  # information from stack task and component information from blame task.
  create_blame_task_if_needed(testcase)
  create_stack_task_if_needed(testcase)


def create_blame_task_if_needed(testcase):
  """Creates a blame task if needed."""
  # Blame doesn't work for non-chromium projects.
  if not utils.is_chromium():
    return

  # Blame is only applicable to chromium project, otherwise bail out.
  if testcase.project_name != 'chromium':
    return

  # We cannot run blame job for custom binaries since we don't have any context
  # on the crash revision and regression range.
  if build_manager.is_custom_binary():
    return

  # Don't send duplicate issues to Predator. This causes issues with metrics
  # tracking and wastes cycles.
  if testcase.status == 'Duplicate':
    return

  create_task = False
  if testcase.one_time_crasher_flag:
    # For unreproducible testcases, it is still beneficial to get component
    # information from blame task.
    create_task = True
  else:
    # Reproducible testcase.
    # Step 1: Check if the regression task finished. If not, bail out.
    if not testcase.regression:
      return

    # Step 2: Check if the symbolize task is applicable and finished. If not,
    # bail out.
    if build_manager.has_symbolized_builds() and not testcase.symbolized:
      return

    create_task = True

  if create_task:
    tasks.add_task('blame', testcase.key.id(), testcase.job_type)


def create_impact_task_if_needed(testcase):
  """Creates an impact task if needed."""
  # Impact doesn't make sense for non-chromium projects.
  if not utils.is_chromium():
    return

  # Impact is only applicable to chromium project, otherwise bail out.
  if testcase.project_name != 'chromium':
    return

  # We cannot run impact job for custom binaries since we don't have any
  # archived production builds for these.
  if build_manager.is_custom_binary():
    return

  tasks.add_task('impact', testcase.key.id(), testcase.job_type)


def create_minimize_task_if_needed(testcase):
  """Creates a minimize task if needed."""
  tasks.add_task('minimize', testcase.key.id(), testcase.job_type)


def create_regression_task_if_needed(testcase):
  """Creates a regression task if needed."""
  # We cannot run regression job for custom binaries since we don't have any
  # archived builds for previous revisions. We only track the last uploaded
  # custom build.
  if build_manager.is_custom_binary():
    return

  tasks.add_task('regression', testcase.key.id(), testcase.job_type)


def create_stack_task_if_needed(testcase):
  """Creates a stack task if needed."""
  second_stack_job_type = environment.get_value('SECOND_STACK_JOB_TYPE')
  if not second_stack_job_type:
    return

  tasks.add_task('stack', testcase.key.id(), second_stack_job_type)


def create_symbolize_task_if_needed(testcase):
  """Creates a symbolize task if needed."""
  # We cannot run symbolize job for custom binaries since we don't have any
  # archived symbolized builds.
  if build_manager.is_custom_binary():
    return

  # Make sure we have atleast one symbolized url pattern defined in job type.
  if not build_manager.has_symbolized_builds():
    return

  tasks.add_task('symbolize', testcase.key.id(), testcase.job_type)


def create_tasks(testcase):
  """Create tasks like minimization, regression, impact, progression, stack
  stack for a newly generated testcase."""
  # No need to create progression task. It is automatically created by the cron
  # handler for reproducible testcases.

  # For a non reproducible crash.
  if testcase.one_time_crasher_flag:
    # For unreproducible testcases, it is still beneficial to get second stack
    # information from stack task and component information from blame task.
    create_blame_task_if_needed(testcase)
    create_stack_task_if_needed(testcase)
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
  create_minimize_task_if_needed(testcase)
