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
"""Bot startup script."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from clusterfuzz._internal.base import modules

modules.fix_module_search_paths()

import contextlib
import multiprocessing
import os
import sys
import time
import traceback

from clusterfuzz._internal.base import dates
from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import untrusted
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.base.tasks import task_utils
from clusterfuzz._internal.bot.fuzzers import init as fuzzers_init
from clusterfuzz._internal.bot.tasks import update_task
from clusterfuzz._internal.bot.tasks import utasks
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.metrics import monitor
from clusterfuzz._internal.metrics import monitoring_metrics
from clusterfuzz._internal.metrics import profiler
from clusterfuzz._internal.system import environment


class _Monitor:
  """Monitor one task."""

  def __init__(self, task, time_module=time):
    self.task = task
    self.time_module = time_module
    self.start_time = None

  def __enter__(self):
    monitoring_metrics.TASK_COUNT.increment({
        'task': self.task.command or '',
        'job': self.task.job or '',
    })
    self.start_time = self.time_module.time()

  def __exit__(self, exc_type, value, trackback):
    if not environment.get_value('LOG_TASK_TIMES'):
      return
    duration = self.time_module.time() - self.start_time
    monitoring_metrics.TASK_TOTAL_RUN_TIME.increment_by(
        int(duration), {
            'task': self.task.command or '',
            'job': self.task.job or '',
        })


@contextlib.contextmanager
def lease_all_tasks(task_list):
  """Creates a context manager that leases every task in tasks_list."""
  with contextlib.ExitStack() as exit_stack:
    for task in task_list:
      monitoring_metrics.TASK_COUNT.increment({
          'task': task.command or '',
          'job': task.job or '',
      })
      exit_stack.enter_context(task.lease())
    yield


def schedule_utask_mains():
  """Schedules utask_mains from preprocessed utasks on Google Cloud Batch."""
  from clusterfuzz._internal.google_cloud_utils import batch

  logs.info('Attempting to combine batch tasks.')
  utask_mains = tasks.get_utask_mains()
  if not utask_mains:
    logs.info('No utask mains.')
    return

  logs.info(f'Combining {len(utask_mains)} batch tasks.')

  with lease_all_tasks(utask_mains):
    batch_tasks = [
        batch.BatchTask(task.command, task.job, task.argument)
        for task in utask_mains
    ]
    batch.create_uworker_main_batch_jobs(batch_tasks)


def task_loop():
  """Executes tasks indefinitely."""
  # Defer heavy task imports to prevent issues with multiprocessing.Process
  from clusterfuzz._internal.bot.tasks import commands

  clean_exit = False
  while True:
    stacktrace = ''
    exception_occurred = False
    task = None
    # This caches the current environment on first run. Don't move this.
    environment.reset_environment()
    try:
      # Run regular updates.
      # TODO(metzman): Move this after utask_main execution so that utasks can't
      # be updated on subsequent attempts.
      update_task.run()
      update_task.track_revision()
      if environment.is_uworker():
        # Batch/Swarming tasks only run one at a time.
        sys.exit(utasks.uworker_bot_main())

      if environment.get_value('SCHEDULE_UTASK_MAINS'):
        # If the bot is configured to schedule utask_mains, don't run any other
        # tasks because scheduling these tasks is more important than executing
        # any one other task.

        # TODO(metzman): Convert this to a k8s cron.
        schedule_utask_mains()
        continue

      if environment.is_tworker():
        task = tasks.tworker_get_task()
      else:
        task = tasks.get_task()

      if not task:
        continue

      with _Monitor(task):
        with task.lease():
          # Execute the command and delete the task.
          commands.process_command(task)
    except SystemExit as e:
      exception_occurred = True
      clean_exit = e.code == 0
      if not clean_exit and not isinstance(e, untrusted.HostError):
        logs.error('SystemExit occurred while working on task.')

      stacktrace = traceback.format_exc()
    except commands.AlreadyRunningError:
      exception_occurred = False
    except task_utils.UworkerMsgParseError:
      logs.error('Task cannot be retried because of utask parse error.')
      task.dont_retry()
      exception_occurred = True
      stacktrace = traceback.format_exc()
    except Exception:
      logs.error('Error occurred while working on task.')
      exception_occurred = True
      stacktrace = traceback.format_exc()

    if exception_occurred:
      # Prevent looping too quickly. See: crbug.com/644830
      failure_wait_interval = environment.get_value('FAIL_WAIT')
      time.sleep(utils.random_number(1, failure_wait_interval))
      break

  task_payload = task.payload() if task else None
  return stacktrace, clean_exit, task_payload


def main():
  """Prepare the configuration options and start requesting tasks."""
  logs.configure('run_bot')

  root_directory = environment.get_value('ROOT_DIR')
  if not root_directory:
    print('Please set ROOT_DIR environment variable to the root of the source '
          'checkout before running. Exiting.')
    print('For an example, check init.bash in the local directory.')
    return

  dates.initialize_timezone_from_environment()
  environment.set_bot_environment()

  if not profiler.start_if_needed('python_profiler_bot'):
    sys.exit(-1)

  fuzzers_init.run()
  if environment.is_trusted_host(ensure_connected=False):
    from clusterfuzz._internal.bot.untrusted_runner import host
    host.init()

  if environment.is_untrusted_worker():
    # Track revision since we won't go into the task_loop.
    update_task.track_revision()

    from clusterfuzz._internal.bot.untrusted_runner import \
        untrusted as untrusted_worker
    untrusted_worker.start_server()
    assert False, 'Unreachable code'

  while True:
    # task_loop should be an infinite loop,
    # unless we run into an exception.
    error_stacktrace, clean_exit, task_payload = task_loop()

    # Print the error trace to the console.
    if not clean_exit:
      print('Exception occurred while running "%s".' % task_payload)
      print('-' * 80)
      print(error_stacktrace)
      print('-' * 80)

    should_terminate = (
        clean_exit or errors.error_in_list(error_stacktrace,
                                           errors.BOT_ERROR_TERMINATION_LIST))
    if should_terminate:
      logs.info('Not retrying.')
      return

    logs.error(
        'Task exited with exception (payload="%s").' % task_payload,
        error_stacktrace=error_stacktrace)

    should_hang = errors.error_in_list(error_stacktrace,
                                       errors.BOT_ERROR_HANG_LIST)
    if should_hang:
      logs.info('Start hanging forever.')
      while True:
        # Sleep to avoid consuming 100% of CPU.
        time.sleep(60)

    # See if our run timed out, if yes bail out.
    if data_handler.bot_run_timed_out():
      return


if __name__ == '__main__':
  multiprocessing.set_start_method('spawn')

  try:
    with monitor.wrap_with_monitoring(), ndb_init.context():
      main()
    exit_code = 0
  except Exception:
    traceback.print_exc()
    sys.stdout.flush()
    sys.stderr.flush()
    exit_code = 1

  # Prevent python GIL deadlocks on shutdown. See https://crbug.com/744680.
  os._exit(exit_code)  # pylint: disable=protected-access
