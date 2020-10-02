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
"""Start the bot and heartbeat scripts."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from python.base import modules
modules.fix_module_search_paths()

import atexit
import os
import subprocess
import time

from base import persistent_cache
from base.untrusted import untrusted_noop
from bot.tasks import update_task
from datastore import data_handler
from datastore import ndb_init
from metrics import logs
from system import environment
from system import shell

BOT_SCRIPT = 'run_bot.py'
HEARTBEAT_SCRIPT = 'run_heartbeat.py'
HEARTBEAT_START_WAIT_TIME = 60
LOOP_SLEEP_INTERVAL = 3
MAX_SUBPROCESS_TIMEOUT = 2**31 // 1000  # https://bugs.python.org/issue20493

_heartbeat_handle = None


def start_bot(bot_command):
  """Start the bot process."""
  command = shell.get_command(bot_command)

  # Wait until the process terminates or until run timed out.
  run_timeout = environment.get_value('RUN_TIMEOUT')
  if run_timeout and run_timeout > MAX_SUBPROCESS_TIMEOUT:
    logs.log_error(
        'Capping RUN_TIMEOUT to max allowed value: %d' % MAX_SUBPROCESS_TIMEOUT)
    run_timeout = MAX_SUBPROCESS_TIMEOUT

  try:
    result = subprocess.run(
        command,
        timeout=run_timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False)
    exit_code = result.returncode
    output = result.stdout
  except subprocess.TimeoutExpired as e:
    exit_code = 0
    output = e.stdout
  except Exception:
    logs.log_error('Unable to start bot process (%s).' % bot_command)
    return 1

  output = output.decode('utf-8', errors='ignore')
  log_message = f'Command: {command} (exit={exit_code})\n{output}'

  if exit_code == 0:
    logs.log(log_message)
  elif exit_code == 1:
    # Anecdotally, exit=1 means there's a fatal Python exception.
    logs.log_error(log_message)
  else:
    logs.log_warn(log_message)

  return exit_code


def sleep(seconds):
  """time.sleep wrapper for mocking."""
  time.sleep(seconds)


@untrusted_noop()
def start_heartbeat(heartbeat_command):
  """Start the heartbeat (in another process)."""
  global _heartbeat_handle
  if _heartbeat_handle:
    # If heartbeat is already started, no work to do. Bail out.
    return

  try:
    command = shell.get_command(heartbeat_command)
    process_handle = subprocess.Popen(command)
  except Exception:
    logs.log_error(
        'Unable to start heartbeat process (%s).' % heartbeat_command)
    return

  # If heartbeat is successfully started, set its handle now.
  _heartbeat_handle = process_handle

  # Artificial delay to let heartbeat's start time update first.
  sleep(HEARTBEAT_START_WAIT_TIME)


@untrusted_noop()
def stop_heartbeat():
  """Stop the heartbeat process."""
  global _heartbeat_handle
  if not _heartbeat_handle:
    # If there is no heartbeat started yet, no work to do. Bail out.
    return

  try:
    _heartbeat_handle.kill()
  except Exception:
    pass

  _heartbeat_handle = None


def update_source_code_if_needed():
  """Update source code if needed."""
  try:
    # Update the bot source, if there's a newer version.
    newer_source_revision = update_task.get_newer_source_revision()
    if newer_source_revision is not None:
      # If source code needs update, stop the heartbeat first. As otherwise,
      # we can run into exceptions if source code changed from underneath
      # a running process.
      stop_heartbeat()

      update_task.update_source_code()
  except Exception:
    logs.log_error('Failed to update source.')


def run_loop(bot_command, heartbeat_command):
  """Run infinite loop with bot's command."""
  atexit.register(stop_heartbeat)

  while True:
    update_source_code_if_needed()
    start_heartbeat(heartbeat_command)
    start_bot(bot_command)

    # See if our run timed out, if yes bail out.
    try:
      if data_handler.bot_run_timed_out():
        break
    except Exception:
      logs.log_error('Failed to check for bot run timeout.')

    sleep(LOOP_SLEEP_INTERVAL)


def main():
  root_directory = environment.get_value('ROOT_DIR')
  if not root_directory:
    print('Please set ROOT_DIR environment variable to the root of the source '
          'checkout before running. Exiting.')
    print('For an example, check init.bash in the local directory.')
    return

  environment.set_bot_environment()
  persistent_cache.initialize()
  logs.configure('run')

  # Create command strings to launch bot and heartbeat.
  base_directory = environment.get_startup_scripts_directory()
  log_directory = environment.get_value('LOG_DIR')
  bot_log = os.path.join(log_directory, 'bot.log')

  bot_script_path = os.path.join(base_directory, BOT_SCRIPT)
  bot_interpreter = shell.get_interpreter(bot_script_path)
  assert bot_interpreter
  bot_command = '%s %s' % (bot_interpreter, bot_script_path)

  heartbeat_script_path = os.path.join(base_directory, HEARTBEAT_SCRIPT)
  heartbeat_interpreter = shell.get_interpreter(heartbeat_script_path)
  assert heartbeat_interpreter
  heartbeat_command = '%s %s %s' % (heartbeat_interpreter,
                                    heartbeat_script_path, bot_log)

  run_loop(bot_command, heartbeat_command)

  logs.log('Exit run.py')


if __name__ == '__main__':
  with ndb_init.context():
    main()
