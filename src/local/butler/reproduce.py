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
"""reproduce.py reproduces test cases locally."""

from __future__ import print_function
from builtins import object

import httplib2
import json
import os
import shutil
import tempfile
import urllib
import webbrowser

from src.python.base import utils
from src.python.bot.tasks import commands
from src.python.fuzzing import testcase_manager
from src.python.system import environment
from src.python.system import shell

AUTHORIZATION_CACHE_FILE = os.path.join(
    os.path.expanduser('~'), '.config', 'clusterfuzz', 'authorization-cache')

# TODO(mbarbella): Don't use the old clusterfuzz-tools client id.
OAUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth?%s' % (
    urllib.urlencode({
        'scope':
            'email profile',
        'client_id': ('602540103821-lccrsee9e5hbe3lpdsghin0'
                      '8ket97hhl.apps.googleusercontent.com'),
        'response_type':
            'code',
        'redirect_uri':
            'urn:ietf:wg:oauth:2.0:oob'
    }))

# TODO(mbarbella): This value should come from the configuration.
TESTCASE_URL = 'https://clusterfuzz.com/reproduce-tool/testcase-info'


class SerializedTestcase(object):
  """Minimal representation of a test case."""

  def __init__(self, testcase_map):
    self._testcase_map = testcase_map

  def __getattr__(self, item):
    return self._testcase_map[item]


class SuppressOutput(object):
  """Suppress stdout and stderr.

  We need this to suppress webbrowser's stdout and stderr."""

  def __enter__(self):
    self.stdout = os.dup(1)
    self.stderr = os.dup(2)
    os.close(1)
    os.close(2)
    os.open(os.devnull, os.O_RDWR)

  def __exit__(self, *_):
    os.dup2(self.stdout, 1)
    os.dup2(self.stderr, 2)
    return True


def _get_authorization(force_reauthorization):
  """Get the value for an oauth authorization header."""
  # Try to read from cache unless we need to reauthorize.
  if not force_reauthorization:
    cached_authorization = utils.read_data_from_file(
        AUTHORIZATION_CACHE_FILE, eval_data=False)
    if cached_authorization:
      return cached_authorization

  # Prompt the user for a code if we don't have one or need a new one.
  with SuppressOutput():
    webbrowser.open(OAUTH_URL, new=1, autoraise=True)
  verification_code = raw_input('Enter verification code: ')
  return 'VerificationCode {code}'.format(code=verification_code)


def _post(url, body, force_reauthorization=False):
  """Make a POST request to the specified URL."""
  authorization = _get_authorization(force_reauthorization)
  headers = {
      'User-Agent': 'clusterfuzz-reproduce',
      'Authorization': authorization
  }

  http = httplib2.Http()
  response, content = http.request(
      url, method='POST', headers=headers, body=json.dumps(body))

  # If the server returns 401 we may need to reauthenticate. Try the request
  # a second time if this happens.
  if response.status == 401 and not force_reauthorization:
    return _post(url, body, force_reauthorization=True)

  if 'x-clusterfuzz-authorization' in response:
    shell.create_directory(
        os.path.dirname(AUTHORIZATION_CACHE_FILE), create_intermediates=True)
    utils.write_data_to_file(response['x-clusterfuzz-authorization'],
                             AUTHORIZATION_CACHE_FILE)

  return response, content


def _get_testcase(testcase_id):
  """Retrieve the json representation of the test case with the given id."""
  response, content = _post(TESTCASE_URL, body={'testcaseId': testcase_id})

  # TODO(mbarbella): Handle this gracefully.
  if response.status != 200:
    raise Exception('Failed to get test case information.')

  testcase_map = json.loads(content)
  return SerializedTestcase(testcase_map)


def _download_testcase(_):
  """Download the test case and return its path."""
  # TODO(mbarbella): Implement this.
  return '/tmp/blah'


def _copy_root_subdirectory(root_dir, temp_root_dir, subdirectory):
  """Copy a single directory to the temporary root directory."""
  shutil.copytree(
      os.path.join(root_dir, subdirectory),
      os.path.join(temp_root_dir, subdirectory))


def _prepare_initial_environment(build_directory):
  """Prepare common environment variables that don't depend on the job."""
  # Create a temporary directory to use as ROOT_DIR with a copy of the default
  # bot and configuration directories nested under it.
  root_dir = environment.get_value('ROOT_DIR')
  temp_root_dir = tempfile.mkdtemp()
  environment.set_value('ROOT_DIR', temp_root_dir)

  _copy_root_subdirectory(root_dir, temp_root_dir, 'bot')
  _copy_root_subdirectory(root_dir, temp_root_dir, 'configs')
  _copy_root_subdirectory(root_dir, temp_root_dir, 'resources')

  environment.set_value('CONFIG_DIR_OVERRIDE',
                        os.path.join(temp_root_dir, 'configs', 'test'))

  environment.set_bot_environment()

  # Overrides that should not be set to the default values.
  environment.set_value('APP_DIR', build_directory)
  environment.set_value('BUILDS_DIR', build_directory)


def _update_environment_for_job(testcase, build_directory):
  commands.update_environment_for_job(testcase.job_definition)

  # Update APP_PATH now that we know the application name.
  app_path = os.path.join(build_directory, environment.get_value('APP_NAME'))
  environment.set_value('APP_PATH', app_path)


def _reproduce_crash(testcase_id, build_directory):
  """Reproduce a crash."""
  _prepare_initial_environment(build_directory)
  testcase = _get_testcase(testcase_id)
  testcase_path = _download_testcase(testcase_id)
  _update_environment_for_job(testcase, build_directory)

  timeout = environment.get_value('TEST_TIMEOUT')
  result = testcase_manager.test_for_crash_with_retries(testcase, testcase_path,
                                                        timeout)

  # Clean up the temporary root directory created in prepare environment.
  shell.remove_directory(environment.get_value('ROOT_DIR'))

  return result


def execute(args):
  """Attempt to reproduce a crash then report on the result."""
  result = _reproduce_crash(args.testcase, args.build_dir)

  # TODO(mbarbella): Report success/failure based on result.
  print(result.output)
