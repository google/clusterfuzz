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
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import urllib.error
import urllib.request

from local.butler import common
from local.butler import constants
from python.tests.test_libs import test_utils

RUN_SERVER_TIMEOUT = 30


def execute(_):
  """Run integration tests."""
  try:
    server = common.execute_async(
        'python -u butler.py run_server --skip-install-deps')
    test_utils.wait_for_emulator_ready(
        server,
        'run_server',
        'Starting module "default" running at:',
        timeout=RUN_SERVER_TIMEOUT)

    request = urllib.request.urlopen('http://' + constants.DEV_APPSERVER_HOST)
    request.read()  # Raises exception on error
  finally:
    server.terminate()

  # TODO(ochang): Test that bot runs, and do a basic fuzzing session to ensure
  # things work end to end.
  print('All end-to-end integration tests passed.')
