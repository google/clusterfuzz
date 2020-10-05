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
"""Heartbeat script wrapper."""

# Before any other imports, we must fix the path. Some libraries might expect
# to be able to import dependencies directly, but we must store these in
# subdirectories of common so that they are shared with App Engine.
from python.base import modules
modules.fix_module_search_paths()

import os
import subprocess
import sys

from datastore import data_handler
from datastore import ndb_init
from metrics import logs
from system import environment
from system import shell

BEAT_SCRIPT = 'heartbeat.py'


def main():
  """Update the heartbeat if there is bot activity."""
  if len(sys.argv) < 2:
    print('Usage: %s <log file>' % sys.argv[0])
    return

  environment.set_bot_environment()
  logs.configure('run_heartbeat')

  log_filename = sys.argv[1]
  previous_state = None

  # Get absolute path to heartbeat script and interpreter needed to execute it.
  startup_scripts_directory = environment.get_startup_scripts_directory()
  beat_script_path = os.path.join(startup_scripts_directory, BEAT_SCRIPT)
  beat_interpreter = shell.get_interpreter(beat_script_path)
  assert beat_interpreter

  while True:
    beat_command = [
        beat_interpreter, beat_script_path,
        str(previous_state), log_filename
    ]

    try:
      previous_state = subprocess.check_output(
          beat_command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      logs.log_error('Failed to beat.', output=e.output)
    except Exception:
      logs.log_error('Failed to beat.')

    # See if our run timed out, if yes bail out.
    if data_handler.bot_run_timed_out():
      break


if __name__ == '__main__':
  with ndb_init.context():
    main()
