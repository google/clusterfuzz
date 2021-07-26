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
"""Run command based on the current task."""

import functools
import sys
import time

import six

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.tasks import analyze_task
from clusterfuzz._internal.bot.tasks import blame_task
from clusterfuzz._internal.bot.tasks import corpus_pruning_task
from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.bot.tasks import impact_task
from clusterfuzz._internal.bot.tasks import minimize_task
from clusterfuzz._internal.bot.tasks import progression_task
from clusterfuzz._internal.bot.tasks import regression_task
from clusterfuzz._internal.bot.tasks import symbolize_task
from clusterfuzz._internal.bot.tasks import train_rnn_generator_task
from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.bot.tasks import upload_reports_task
from clusterfuzz._internal.bot.tasks import variant_task
from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell

COMMAND_MAP = {
    'analyze': analyze_task,
    'blame': blame_task,
    'corpus_pruning': corpus_pruning_task,
    'fuzz': fuzz_task,
    'impact': impact_task,
    'minimize': minimize_task,
    'train_rnn_generator': train_rnn_generator_task,
    'progression': progression_task,
    'regression': regression_task,
    'symbolize': symbolize_task,
    'unpack': unpack_task,
    'upload_reports': upload_reports_task,
    'variant': variant_task,
}

TASK_RETRY_WAIT_LIMIT = 5 * 60  # 5 minutes.


class Error(Exception):
  """Base commands exceptions."""


class AlreadyRunningError(Error):
  """Exception raised for a task that is already running on another bot."""


def cleanup_task_state():
  """Cleans state before and after a task is executed."""
  # Cleanup stale processes.
  process_handler.cleanup_stale_processes()

  # Clear build urls, temp and testcase directories.
  shell.clear_build_urls_directory()
  shell.clear_crash_stacktraces_directory()
  shell.clear_testcase_directories()
  shell.clear_temp_directory()
  shell.clear_system_temp_directory()
  shell.clear_device_temp_directories()

  # Reset memory tool environment variables.
  environment.reset_current_memory_tool_options()

  # Call python's garbage collector.
  utils.python_gc()


def is_supported_cpu_arch_for_job():
  """Return true if the current cpu architecture can run this job."""
  cpu_arch = environment.get_cpu_arch()
  if not cpu_arch:
    # No cpu architecture check is defined for this platform, bail out.
    return True

  supported_cpu_arch = environment.get_value('CPU_ARCH')
  if not supported_cpu_arch:
    # No specific cpu architecture requirement specified in job, bail out.
    return True

  # Convert to list just in case anyone specifies value as a single string.
  supported_cpu_arch_list = list(supported_cpu_arch)

  return cpu_arch in supported_cpu_arch_list


def update_environment_for_job(environment_string):
  """Process the environment variable string included with a job."""
  # Now parse the job's environment definition.
  environment_values = (
      environment.parse_environment_definition(environment_string))

  for key, value in six.iteritems(environment_values):
    environment.set_value(key, value)

  # If we share the build with another job type, force us to be a custom binary
  # job type.
  if environment.get_value('SHARE_BUILD_WITH_JOB_TYPE'):
    environment.set_value('CUSTOM_BINARY', True)

  # Allow the default FUZZ_TEST_TIMEOUT and MAX_TESTCASES to be overridden on
  # machines that are preempted more often.
  fuzz_test_timeout_override = environment.get_value(
      'FUZZ_TEST_TIMEOUT_OVERRIDE')
  if fuzz_test_timeout_override:
    environment.set_value('FUZZ_TEST_TIMEOUT', fuzz_test_timeout_override)

  max_testcases_override = environment.get_value('MAX_TESTCASES_OVERRIDE')
  if max_testcases_override:
    environment.set_value('MAX_TESTCASES', max_testcases_override)

  if environment.is_trusted_host():
    environment_values['JOB_NAME'] = environment.get_value('JOB_NAME')
    from clusterfuzz._internal.bot.untrusted_runner import \
        environment as worker_environment
    worker_environment.update_environment(environment_values)


def set_task_payload(func):
  """Set TASK_PAYLOAD and unset TASK_PAYLOAD."""

  @functools.wraps(func)
  def wrapper(task):
    """Wrapper."""
    environment.set_value('TASK_PAYLOAD', task.payload())
    try:
      return func(task)
    except:  # Truly catch *all* exceptions.
      e = sys.exc_info()[1]
      e.extras = {'task_payload': environment.get_value('TASK_PAYLOAD')}
      raise
    finally:
      environment.remove_key('TASK_PAYLOAD')

  return wrapper


def should_update_task_status(task_name):
  """Whether the task status should be automatically handled."""
  return task_name not in [
      # Multiple fuzz tasks are expected to run in parallel.
      'fuzz',

      # The task payload can't be used as-is for de-duplication purposes as it
      # includes revision. corpus_pruning_task calls update_task_status itself
      # to handle this.
      # TODO(ochang): This will be cleaned up as part of migration to Pub/Sub.
      'corpus_pruning',
  ]


def start_web_server_if_needed():
  """Start web server for blackbox fuzzer jobs (non-engine fuzzer jobs)."""
  if environment.is_engine_fuzzer_job():
    return

  try:
    http_server.start()
  except Exception:
    logs.log_error('Failed to start web server, skipping.')


def run_command(task_name, task_argument, job_name):
  """Run the command."""
  if task_name not in COMMAND_MAP:
    logs.log_error("Unknown command '%s'" % task_name)
    return

  task_module = COMMAND_MAP[task_name]

  # If applicable, ensure this is the only instance of the task running.
  task_state_name = ' '.join([task_name, task_argument, job_name])
  if should_update_task_status(task_name):
    if not data_handler.update_task_status(task_state_name,
                                           data_types.TaskState.STARTED):
      logs.log('Another instance of "{}" already '
               'running, exiting.'.format(task_state_name))
      raise AlreadyRunningError

  try:
    task_module.execute_task(task_argument, job_name)
  except errors.InvalidTestcaseError:
    # It is difficult to try to handle the case where a test case is deleted
    # during processing. Rather than trying to catch by checking every point
    # where a test case is reloaded from the datastore, just abort the task.
    logs.log_warn('Test case %s no longer exists.' % task_argument)
  except BaseException:
    # On any other exceptions, update state to reflect error and re-raise.
    if should_update_task_status(task_name):
      data_handler.update_task_status(task_state_name,
                                      data_types.TaskState.ERROR)

    raise

  # Task completed successfully.
  if should_update_task_status(task_name):
    data_handler.update_task_status(task_state_name,
                                    data_types.TaskState.FINISHED)


# pylint: disable=too-many-nested-blocks
# TODO(mbarbella): Rewrite this function to avoid nesting issues.
@set_task_payload
def process_command(task):
  """Figures out what to do with the given task and executes the command."""
  logs.log("Executing command '%s'" % task.payload())
  if not task.payload().strip():
    logs.log_error('Empty task received.')
    return

  # Parse task payload.
  task_name = task.command
  task_argument = task.argument
  job_name = task.job

  environment.set_value('TASK_NAME', task_name)
  environment.set_value('TASK_ARGUMENT', task_argument)
  environment.set_value('JOB_NAME', job_name)
  if job_name != 'none':
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    # Job might be removed. In that case, we don't want an exception
    # raised and causing this task to be retried by another bot.
    if not job:
      logs.log_error("Job '%s' not found." % job_name)
      return

    if not job.platform:
      error_string = "No platform set for job '%s'" % job_name
      logs.log_error(error_string)
      raise errors.BadStateError(error_string)

    # A misconfiguration led to this point. Clean up the job if necessary.
    job_queue_suffix = tasks.queue_suffix_for_platform(job.platform)
    bot_queue_suffix = tasks.default_queue_suffix()

    if job_queue_suffix != bot_queue_suffix:
      # This happens rarely, store this as a hard exception.
      logs.log_error(
          'Wrong platform for job %s: job queue [%s], bot queue [%s].' %
          (job_name, job_queue_suffix, bot_queue_suffix))

      # Try to recreate the job in the correct task queue.
      new_queue = (
          tasks.high_end_queue() if task.high_end else tasks.regular_queue())
      new_queue += job_queue_suffix

      # Command override is continuously run by a bot. If we keep failing
      # and recreating the task, it will just DoS the entire task queue.
      # So, we don't create any new tasks in that case since it needs
      # manual intervention to fix the override anyway.
      if not task.is_command_override:
        try:
          tasks.add_task(task_name, task_argument, job_name, new_queue)
        except Exception:
          # This can happen on trying to publish on a non-existent topic, e.g.
          # a topic for a high-end bot on another platform. In this case, just
          # give up.
          logs.log_error('Failed to fix platform and re-add task.')

      # Add a wait interval to avoid overflowing task creation.
      failure_wait_interval = environment.get_value('FAIL_WAIT')
      time.sleep(failure_wait_interval)
      return

    if task_name != 'fuzz':
      # Make sure that our platform id matches that of the testcase (for
      # non-fuzz tasks).
      testcase = data_handler.get_entity_by_type_and_id(data_types.Testcase,
                                                        task_argument)
      if testcase:
        current_platform_id = environment.get_platform_id()
        testcase_platform_id = testcase.platform_id

        # This indicates we are trying to run this job on the wrong platform.
        # This can happen when you have different type of devices (e.g
        # android) on the same platform group. In this case, we just recreate
        # the task.
        if (task_name != 'variant' and testcase_platform_id and
            not utils.fields_match(testcase_platform_id, current_platform_id)):
          logs.log(
              'Testcase %d platform (%s) does not match with ours (%s), exiting'
              % (testcase.key.id(), testcase_platform_id, current_platform_id))
          tasks.add_task(
              task_name,
              task_argument,
              job_name,
              wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
          return

    # Some fuzzers contain additional environment variables that should be
    # set for them. Append these for tests generated by these fuzzers and for
    # the fuzz command itself.
    fuzzer_name = None
    if task_name == 'fuzz':
      fuzzer_name = task_argument
    elif testcase:
      fuzzer_name = testcase.fuzzer_name

    # Get job's environment string.
    environment_string = job.get_environment_string()

    if task_name == 'minimize':
      # Let jobs specify a different job and fuzzer to minimize with.
      job_environment = job.get_environment()
      minimize_job_override = job_environment.get('MINIMIZE_JOB_OVERRIDE')
      if minimize_job_override:
        minimize_job = data_types.Job.query(
            data_types.Job.name == minimize_job_override).get()
        if minimize_job:
          environment.set_value('JOB_NAME', minimize_job_override)
          environment_string = minimize_job.get_environment_string()
          environment_string += '\nORIGINAL_JOB_NAME = %s\n' % job_name
          job_name = minimize_job_override
        else:
          logs.log_error(
              'Job for minimization not found: %s.' % minimize_job_override)
          # Fallback to using own job for minimization.

      minimize_fuzzer_override = job_environment.get('MINIMIZE_FUZZER_OVERRIDE')
      fuzzer_name = minimize_fuzzer_override or fuzzer_name

    if fuzzer_name and not environment.is_engine_fuzzer_job(job_name):
      fuzzer = data_types.Fuzzer.query(
          data_types.Fuzzer.name == fuzzer_name).get()
      additional_default_variables = ''
      additional_variables_for_job = ''
      if (fuzzer and hasattr(fuzzer, 'additional_environment_string') and
          fuzzer.additional_environment_string):
        for line in fuzzer.additional_environment_string.splitlines():
          # Job specific values may be defined in fuzzer additional
          # environment variable name strings in the form
          # job_name:VAR_NAME = VALUE.
          if '=' in line and ':' in line.split('=', 1)[0]:
            fuzzer_job_name, environment_definition = line.split(':', 1)
            if fuzzer_job_name == job_name:
              additional_variables_for_job += '\n%s' % environment_definition
            continue

          additional_default_variables += '\n%s' % line

      environment_string += additional_default_variables
      environment_string += additional_variables_for_job

    # Update environment for the job.
    update_environment_for_job(environment_string)

  # Match the cpu architecture with the ones required in the job definition.
  # If they don't match, then bail out and recreate task.
  if not is_supported_cpu_arch_for_job():
    logs.log(
        'Unsupported cpu architecture specified in job definition, exiting.')
    tasks.add_task(
        task_name,
        task_argument,
        job_name,
        wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
    return

  # Initial cleanup.
  cleanup_task_state()

  start_web_server_if_needed()

  try:
    run_command(task_name, task_argument, job_name)
  finally:
    # Final clean up.
    cleanup_task_state()
