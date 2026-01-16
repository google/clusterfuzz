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
import os
import sys
import time
import uuid

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_rate_limiting
from clusterfuzz._internal.bot.tasks import blame_task
from clusterfuzz._internal.bot.tasks import impact_task
from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.bot.tasks import unpack_task
from clusterfuzz._internal.bot.tasks.utasks import analyze_task
from clusterfuzz._internal.bot.tasks.utasks import corpus_pruning_task
from clusterfuzz._internal.bot.tasks.utasks import fuzz_task
from clusterfuzz._internal.bot.tasks.utasks import minimize_task
from clusterfuzz._internal.bot.tasks.utasks import progression_task
from clusterfuzz._internal.bot.tasks.utasks import regression_task
from clusterfuzz._internal.bot.tasks.utasks import symbolize_task
from clusterfuzz._internal.bot.tasks.utasks import variant_task
from clusterfuzz._internal.bot.webserver import http_server
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell

TASK_RETRY_WAIT_LIMIT = 5 * 60  # 5 minutes.

_COMMAND_MODULE_MAP = {
    'analyze': analyze_task,
    'blame': blame_task,
    'corpus_pruning': corpus_pruning_task,
    'fuzz': fuzz_task,
    'impact': impact_task,
    'minimize': minimize_task,
    'progression': progression_task,
    'regression': regression_task,
    'symbolize': symbolize_task,
    'unpack': unpack_task,
    'postprocess': None,
    'uworker_main': None,
    'variant': variant_task,
}

assert set(_COMMAND_MODULE_MAP.keys()) == set(task_types.COMMAND_TYPES.keys())
COMMAND_MAP = {
    command: task_cls(_COMMAND_MODULE_MAP[command])
    for command, task_cls in task_types.COMMAND_TYPES.items()
}


class Error(Exception):
  """Base commands exceptions."""


class AlreadyRunningError(Error):
  """Exception raised for a task that is already running on another bot."""


def cleanup_task_state():
  """Cleans state before and after a task is executed."""
  # Cleanup stale processes.
  if environment.is_tworker():
    return
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
  env = environment.parse_environment_definition(environment_string)
  uworker_env = env.copy()
  for key, value in env.items():
    environment.set_value(key, value)

  # Allow the default FUZZ_TEST_TIMEOUT and MAX_TESTCASES to be overridden on
  # machines that are preempted more often.
  fuzz_test_timeout_override = environment.get_value(
      'FUZZ_TEST_TIMEOUT_OVERRIDE')
  if fuzz_test_timeout_override:
    environment.set_value('FUZZ_TEST_TIMEOUT', fuzz_test_timeout_override)
    uworker_env['FUZZ_TEST_TIMEOUT'] = fuzz_test_timeout_override

  max_testcases_override = environment.get_value('MAX_TESTCASES_OVERRIDE')
  if max_testcases_override:
    environment.set_value('MAX_TESTCASES', max_testcases_override)
    uworker_env['MAX_TESTCASES'] = max_testcases_override

  uworker_env['JOB_NAME'] = environment.get_value('JOB_NAME')
  if environment.is_trusted_host():
    env['JOB_NAME'] = environment.get_value('JOB_NAME')
    from clusterfuzz._internal.bot.untrusted_runner import \
        environment as worker_environment
    worker_environment.update_environment(env)
  return uworker_env


def set_task_payload(func):
  """Set TASK_PAYLOAD and unset TASK_PAYLOAD."""

  @functools.wraps(func)
  def wrapper(task_name, task_argument, job_name, *args, **kwargs):
    """Wrapper."""
    payload = tasks.construct_payload(task_name, task_argument, job_name)
    environment.set_value('TASK_PAYLOAD', payload)
    try:
      return func(task_name, task_argument, job_name, *args, **kwargs)
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
    logs.error('Failed to start web server, skipping.')


def get_command_object(task_name):
  """Returns the command object that execute can be called on."""
  task = COMMAND_MAP.get(task_name)
  if not environment.is_tworker():
    return task

  if task_name in {'postprocess', 'uworker_main'}:
    return task

  if isinstance(task, task_types.TrustedTask):
    # We don't need to execute this remotely.
    return task

  # Force remote execution.
  return task_types.UTask(_COMMAND_MODULE_MAP[task_name])


def run_command(task_name, task_argument, job_name, uworker_env):
  """Runs the command."""
  task = get_command_object(task_name)
  if not task:
    logs.error(f'Unknown command "{task_name}"')
    return None

  # If applicable, ensure this is the only instance of the task running.
  task_state_name = ' '.join([task_name, task_argument, job_name])
  if should_update_task_status(task_name):
    if not data_handler.update_task_status(task_state_name,
                                           data_types.TaskState.STARTED):
      logs.info(f'Another instance of "{task_state_name}" already running, '
                'exiting.')
      raise AlreadyRunningError

  result = None
  rate_limiter = task_rate_limiting.TaskRateLimiter(task_name, task_argument,
                                                    job_name)
  if rate_limiter.is_rate_limited():
    monitoring_metrics.TASK_RATE_LIMIT_COUNT.increment(labels={
        'job': job_name,
        'task': task_name,
        'argument': task_argument,
    })
    logs.error(f'Rate limited task: {task_name} {task_argument} {job_name}')
    if task_name == 'fuzz' and not environment.is_tworker():
      # TODO(b/377885331): Get rid of this when oss-fuzz is migrated.
      # Wait 10 seconds. We don't want to try again immediately because if we
      # tried to run a fuzz task then there is no other task to run.
      time.sleep(environment.get_value('FAIL_WAIT'))
    return None
  try:
    result = task.execute(task_argument, job_name, uworker_env)
  except errors.InvalidTestcaseError:
    # It is difficult to try to handle the case where a test case is deleted
    # during processing. Rather than trying to catch by checking every point
    # where a test case is reloaded from the datastore, just abort the task.
    logs.warning('Test case %s no longer exists.' % task_argument)
    rate_limiter.record_task(success=False)
  except BaseException:
    # On any other exceptions, update state to reflect error and re-raise.
    rate_limiter.record_task(success=False)
    if should_update_task_status(task_name):
      data_handler.update_task_status(task_state_name,
                                      data_types.TaskState.ERROR)
    raise
  else:
    rate_limiter.record_task(success=True)

  # Task completed successfully.
  if should_update_task_status(task_name):
    data_handler.update_task_status(task_state_name,
                                    data_types.TaskState.FINISHED)
  return result


def process_command(task):
  """Figures out what to do with the given task and executes the command."""
  logs.info(f'Executing command "{task.payload()}"')
  if not task.payload().strip():
    logs.error('Empty task received.')
    return None

  return process_command_impl(task.command, task.argument, task.job,
                              task.high_end, task.is_command_override,
                              task.queue)


# pylint: disable=too-many-nested-blocks
# TODO(mbarbella): Rewrite this function to avoid nesting issues.
@set_task_payload
def process_command_impl(task_name,
                         task_argument,
                         job_name,
                         high_end,
                         is_command_override,
                         queue=None):
  """Implementation of process_command."""
  uworker_env = None
  environment.set_value('TASK_NAME', task_name)
  environment.set_value('TASK_ARGUMENT', task_argument)
  environment.set_value('JOB_NAME', job_name)
  if task_name in {'uworker_main', 'postprocess'}:
    # We want the id of the task we are processing, not "uworker_main", or
    # "postprocess".
    task_id = None
  else:
    task_id = uuid.uuid4()
  environment.set_value('CF_TASK_ID', task_id)
  environment.set_value('CF_TASK_NAME', task_name)
  environment.set_value('CF_TASK_ARGUMENT', task_argument)
  environment.set_value('CF_TASK_JOB_NAME', job_name)
  if job_name != 'none':
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    # Job might be removed. In that case, we don't want an exception
    # raised and causing this task to be retried by another bot.
    if not job:
      logs.error("Job '%s' not found." % job_name)
      return None

    if not job.platform:
      error_string = "No platform set for job '%s'" % job_name
      logs.error(error_string)
      raise errors.BadStateError(error_string)

    job_base_queue_suffix = tasks.queue_suffix_for_platform(
        environment.base_platform(job.platform))
    bot_platform = environment.platform().lower()
    bot_base_queue_suffix = tasks.queue_suffix_for_platform(
        environment.base_platform(bot_platform))

    # A misconfiguration led to this point. Clean up the job if necessary.
    # TODO(ochang): Remove the first part of this check once we migrate off the
    # old untrusted worker architecture.
    # If the job base quque is '-android', which is the default Android queue
    # ignore the mismatch since with subqueues, it is expected
    if (not environment.get_value('DEBUG_TASK') and
        not environment.is_tworker() and
        not environment.is_trusted_host(ensure_connected=False) and
        job_base_queue_suffix != bot_base_queue_suffix and
        job_base_queue_suffix != '-android'):
      # This happens rarely, store this as a hard exception.
      logs.error('Wrong platform for job %s: job queue [%s], bot queue [%s].' %
                 (job_name, job_base_queue_suffix, bot_base_queue_suffix))

      # Try to recreate the job in the correct task queue.
      new_queue = (
          tasks.high_end_queue() if high_end else tasks.regular_queue())
      new_queue += job_base_queue_suffix

      # Command override is continuously run by a bot. If we keep failing
      # and recreating the task, it will just DoS the entire task queue.
      # So, we don't create any new tasks in that case since it needs
      # manual intervention to fix the override anyway.
      if not is_command_override:
        try:
          tasks.add_task(task_name, task_argument, job_name, new_queue)
        except Exception:
          # This can happen on trying to publish on a non-existent topic, e.g.
          # a topic for a high-end bot on another platform. In this case, just
          # give up.
          logs.error('Failed to fix platform and re-add task.')

      # Add a wait interval to avoid overflowing task creation.
      time.sleep(environment.get_value('FAIL_WAIT'))
      return None

    if task_name != 'fuzz':
      # Make sure that our platform id matches that of the testcase (for
      # non-fuzz tasks).
      testcase = data_handler.get_entity_by_type_and_id(data_types.Testcase,
                                                        task_argument)
      if testcase:
        current_platform_id = environment.get_platform_id()
        testcase_platform_id = testcase.platform_id
        testcase_id = testcase.key.id()

        # This indicates we are trying to run this job on the wrong platform
        # and potentially blocks fuzzing. See the 'subqueues' feature for
        # more details: https://github.com/google/clusterfuzz/issues/3347
        if (task_name != 'variant' and testcase_platform_id and
            not utils.fields_match(testcase_platform_id, current_platform_id)):

          logs.info(
              f'Testcase {testcase_id} platform {testcase_platform_id} '
              f'does not match with ours {current_platform_id}, checking.')

          # Check if the device or branch is deprecated.
          # If it is deprecated, try to execute on an updated platform.
          if not (environment.is_testcase_deprecated(testcase_platform_id) and
                  environment.can_testcase_run_on_platform(
                      testcase_platform_id, current_platform_id)):
            logs.info(f'Testcase {testcase.key.id()} platform '
                      f'({testcase_platform_id}) does not match with ours '
                      f'({current_platform_id}), exiting.')
            logs.info(f'Adding testcase {testcase.key.id()} to {queue}.')
            tasks.add_task(
                task_name,
                task_argument,
                job_name,
                queue,
                wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
            return None

          logs.info(f'Testcase {testcase_id} platform {testcase_platform_id} '
                    f'can run on current platform {current_platform_id}.')

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
          logs.error(
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
    uworker_env = update_environment_for_job(environment_string)
    uworker_env['TASK_NAME'] = task_name
    uworker_env['TASK_ARGUMENT'] = task_argument
    uworker_env['JOB_NAME'] = job_name
    uworker_env['CF_TASK_ID'] = task_id
    uworker_env['CF_TASK_NAME'] = task_name
    uworker_env['CF_TASK_ARGUMENT'] = task_argument
    uworker_env['CF_TASK_JOB_NAME'] = job_name

  # Match the cpu architecture with the ones required in the job definition.
  # If they don't match, then bail out and recreate task.
  if not is_supported_cpu_arch_for_job():
    logs.info(
        'Unsupported cpu architecture specified in job definition, exiting.')
    tasks.add_task(
        task_name,
        task_argument,
        job_name,
        wait_time=utils.random_number(1, TASK_RETRY_WAIT_LIMIT))
    return None

  # Initial cleanup.
  cleanup_task_state()

  start_web_server_if_needed()

  try:
    return run_command(task_name, task_argument, job_name, uworker_env)
  finally:
    # Final clean up.
    cleanup_task_state()
    tear_down_envs = [
        'CF_TASK_ID', 'CF_TASK_NAME', 'CF_TASK_ARGUMENT', 'CF_TASK_JOB_NAME'
    ]
    for env_key in tear_down_envs:
      if env_key in os.environ:
        del os.environ[env_key]
