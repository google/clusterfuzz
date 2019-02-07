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

from __future__ import print_function

# We want to use utf-8 encoding everywhere throughout the application
# instead of the default 'ascii' encoding. This must happen before any
# other imports.
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

# Before other modules import os, we patch path-related methods, so they are
# compatible with windows.
from system import path_patcher
path_patcher.patch()

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from python.base import modules
modules.fix_module_search_paths()

import os
import time
import traceback

from base import dates
from base import errors
from base import tasks
from base import untrusted
from base import utils
from bot.tasks import commands
from bot.tasks import update_task
from datastore import data_handler
from metrics import logs
from metrics import monitor
from metrics import monitoring_metrics
from system import environment


class _Monitor(object):
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
    duration = self.time_module.time() - self.start_time
    has_error = bool(value)
    monitoring_metrics.TASK_TIME.add(
        duration, {
            'task': self.task.command or '',
            'job': self.task.job or '',
            'error': has_error
        })


def task_loop():
  """Executes tasks indefinitely."""
  clean_exit = False
  while True:
    exception_occurred = False
    task = None
    # This caches the current environment on first run. Don't move this.
    environment.reset_environment()
    try:
      # Run regular updates.
      update_task.run()
      update_task.track_revision()

      task = tasks.get_task()
      if not task:
        continue

      with _Monitor(task):
        with task.lease():
          # Execute the command and delete the task.
          commands.process_command(task)
    except SystemExit as e:
      exception_occurred = True
      clean_exit = (e.code == 0)
      if not clean_exit and not isinstance(e, untrusted.HostException):
        logs.log_error('SystemExit occurred while working on task.')
    except commands.AlreadyRunningError:
      exception_occurred = False
    except Exception:
      logs.log_error('Error occurred while working on task.')
      exception_occurred = True

    if exception_occurred:
      # Prevent looping too quickly. See: crbug.com/644830
      failure_wait_interval = environment.get_value('FAIL_WAIT')
      time.sleep(utils.random_number(1, failure_wait_interval))
      break

  task_payload = task.payload() if task else None
  return traceback.format_exc(), clean_exit, task_payload


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
  monitor.initialize()

  if environment.is_trusted_host(ensure_connected=False):
    from bot.untrusted_runner import host
    host.init()

  if environment.is_untrusted_worker():
    # Track revision since we won't go into the task_loop.
    update_task.track_revision()

    from bot.untrusted_runner import untrusted as untrusted_worker
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
      return

    logs.log_error(
        'Task exited with exception.',
        error_stacktrace=error_stacktrace,
        task_payload=task_payload)

    should_hang = errors.error_in_list(error_stacktrace,
                                       errors.BOT_ERROR_HANG_LIST)
    if should_hang:
      logs.log('Start hanging forever.')
      while True:
        # Sleep to avoid consuming 100% of CPU.
        time.sleep(60)

    # See if our run timed out, if yes bail out.
    if data_handler.bot_run_timed_out():
      return

    # Clear the current exception.
    sys.exc_clear()


if __name__ == '__main__':
  try:
    main()
    exit_code = 0
  except Exception:
    traceback.print_exc()
    exit_code = 1

  monitor.stop()

  # Prevent python GIL deadlocks on shutdown. See https://crbug.com/744680.
  os._exit(exit_code)  # pylint: disable=protected-access
