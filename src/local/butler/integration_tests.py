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
"""py_unittest.py runs tests under src/appengine and butler/tests"""
import time
import urllib.error
import urllib.request

from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler import common
from local.butler import constants

RUN_SERVER_TIMEOUT = 120


def execute(_):
  """Run integration tests."""
  command = 'run_server'
  indicator = b'Booting worker'

  try:
    lines = []
    server = common.execute_async(
        'python -u butler.py {} --skip-install-deps'.format(command))
    test_utils.wait_for_emulator_ready(
        server,
        command,
        indicator,
        timeout=RUN_SERVER_TIMEOUT,
        output_lines=lines)

    # Sleep a small amount of time to ensure the server is definitely ready.
    time.sleep(1)

    # Call setup ourselves instead of passing --bootstrap since we have no idea
    # when that finishes.
    # TODO(ochang): Make bootstrap a separate butler command and just call that.
    common.execute(
        ('python butler.py run setup '
         '--non-dry-run --local --config-dir={config_dir}'
        ).format(config_dir=constants.TEST_CONFIG_DIR),
        exit_on_error=False)

    request = urllib.request.urlopen('http://' + constants.DEV_APPSERVER_HOST)
    request.read()  # Raises exception on error
  except Exception:
    print('Error occurred:')
    print(b''.join(lines))
    raise
  finally:
    server.terminate()

  # TODO(ochang): Test that bot runs, and do a basic fuzzing session to ensure
  # things work end to end.
  print('All end-to-end integration tests passed.')
