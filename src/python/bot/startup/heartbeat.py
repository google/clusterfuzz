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
"""Heartbeat script that monitors
   whether the bot is still running or not."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from python.base import modules
modules.fix_module_search_paths()

import os
import sys
import time

from base import dates
from base import tasks
from datastore import data_handler
from datastore import data_types
from datastore import ndb_init
from metrics import logs
from system import environment
from system import process_handler
from system import shell

try:
  import psutil
except ImportError:
  psutil = None


def beat(previous_state, log_filename):
  """Run a cycle of heartbeat checks to ensure bot is running."""
  # Handle case when run_bot.py script is stuck. If yes, kill its process.
  task_end_time = tasks.get_task_end_time()
  if psutil and task_end_time and dates.time_has_expired(
      task_end_time, seconds=tasks.TASK_COMPLETION_BUFFER):

    # Get absolute path to |run_bot| script. We use this to identify unique
    # instances of bot running on a particular host.
    startup_scripts_directory = environment.get_startup_scripts_directory()
    bot_file_path = os.path.join(startup_scripts_directory, 'run_bot')

    for process in psutil.process_iter():
      try:
        command_line = ' '.join(process.cmdline())
      except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        continue

      # Find the process running the main bot script.
      if bot_file_path not in command_line:
        continue

      process_id = process.pid
      logs.log(
          'Killing stale bot (pid %d) which seems to have stuck.' % process_id)
      try:
        process_handler.terminate_root_and_child_processes(process_id)
      except Exception:
        logs.log_error('Failed to terminate stale bot processes.')

    # Minor cleanup to avoid disk space issues on bot restart.
    process_handler.terminate_stale_application_instances()
    shell.clear_temp_directory()
    shell.clear_testcase_directories()

    # Concerned stale processes should be killed. Now, delete the stale task.
    tasks.track_task_end()

  # Figure out when the log file was last modified.
  try:
    current_state = str(os.path.getmtime(log_filename))
  except Exception:
    current_state = None

  # Only update the heartbeat if the log file was modified.
  if current_state and current_state != previous_state:
    # Try updating the heartbeat. If an error occurs, just
    # wait and return None.
    if not data_handler.update_heartbeat():
      return None
    # Heartbeat is successfully updated.

  return current_state


def main():
  logs.configure('heartbeat')
  dates.initialize_timezone_from_environment()
  environment.set_bot_environment()

  if sys.argv[1] == 'None':
    previous_state = None
  else:
    previous_state = sys.argv[1]

  log_filename = sys.argv[2]

  try:
    sys.stdout.write(str(beat(previous_state, log_filename)))
  except Exception:
    logs.log_error('Failed to beat.')

  time.sleep(data_types.HEARTBEAT_WAIT_INTERVAL)


if __name__ == '__main__':
  with ndb_init.context():
    main()
