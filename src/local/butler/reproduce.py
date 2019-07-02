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

from python.base import modules
modules.fix_module_search_paths()

import httplib2
import os
import tempfile
import urllib
import webbrowser

from base import json_utils
from base import utils
from bot.tasks import commands
from bot.tasks import setup
from build_management import build_manager
from datastore import data_types
from fuzzing import testcase_manager
from local.butler import appengine
from local.butler import common
from system import archive
from system import environment
from system import shell

AUTHORIZATION_CACHE_FILE = os.path.join(
    os.path.expanduser('~'), '.config', 'clusterfuzz', 'authorization-cache')

# TODO(mbarbella): Client ID and domain should be configurable.
OAUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth?%s' % (
    urllib.urlencode({
        'scope':
            'email profile',
        'client_id': ('981641712411-sj50drhontt4m3gjc3hordj'
                      'mpc7bn50f.apps.googleusercontent.com'),
        'response_type':
            'code',
        'redirect_uri':
            'urn:ietf:wg:oauth:2.0:oob'
    }))
TESTCASE_DOWNLOAD_URL = ('https://clusterfuzz.com/testcase-detail/'
                         'download-testcase?id={testcase_id}')
TESTCASE_INFO_URL = 'https://clusterfuzz.com/reproduce-tool/testcase-info'

_GET_METHOD = 'GET'
_POST_METHOD = 'POST'


class ReproduceToolException(Exception):
  """Base class for reproduce tool exceptions."""
  pass


class SerializedTestcase(object):
  """Minimal representation of a test case."""

  def __init__(self, testcase_map):
    self._testcase_map = testcase_map

  def __getattr__(self, item):
    return self._testcase_map[item]

  def get_metadata(self, key=None, default=None):
    """Emulate Testcase's get_metadata function."""
    metadata = json_utils.loads(self.additional_metadata)
    if not key:
      return metadata

    try:
      return self.metadata[key]
    except KeyError:
      return default


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


def _http_request(url,
                  body=None,
                  method=_POST_METHOD,
                  force_reauthorization=False):
  """Make a POST request to the specified URL."""
  authorization = _get_authorization(force_reauthorization)
  headers = {
      'User-Agent': 'clusterfuzz-reproduce',
      'Authorization': authorization
  }

  http = httplib2.Http()
  request_body = json_utils.dumps(body) if body else ''
  response, content = http.request(
      url, method=method, headers=headers, body=request_body)

  # If the server returns 401 we may need to reauthenticate. Try the request
  # a second time if this happens.
  if response.status == 401 and not force_reauthorization:
    return _http_request(url, body, method=method, force_reauthorization=True)

  if 'x-clusterfuzz-authorization' in response:
    shell.create_directory(
        os.path.dirname(AUTHORIZATION_CACHE_FILE), create_intermediates=True)
    utils.write_data_to_file(response['x-clusterfuzz-authorization'],
                             AUTHORIZATION_CACHE_FILE)

  return response, content


def _get_testcase(testcase_id):
  """Retrieve the json representation of the test case with the given id."""
  response, content = _http_request(
      TESTCASE_INFO_URL, body={'testcaseId': testcase_id})

  if response.status != 200:
    raise ReproduceToolException('Unable to fetch test case information.')

  testcase_map = json_utils.loads(content)
  return SerializedTestcase(testcase_map)


def _download_testcase(testcase_id, testcase):
  """Download the test case and return its path."""
  response, content = _http_request(
      TESTCASE_DOWNLOAD_URL.format(testcase_id=testcase_id), method=_GET_METHOD)

  if response.status != 200:
    raise ReproduceToolException('Unable to download test case.')

  # Create a temporary directory where we can store the test case.
  bot_absolute_filename = response['x-goog-meta-filename']
  testcase_directory = os.path.join(
      environment.get_value('ROOT_DIR'), 'current-testcase')
  shell.create_directory(testcase_directory)
  testcase_path = os.path.join(testcase_directory,
                               os.path.basename(bot_absolute_filename))

  utils.write_data_to_file(content, testcase_path)

  # Unpack the test case if it's archived.
  # TODO(mbarbella): Rewrite setup.unpack_testcase and share this code.
  if testcase.minimized_keys and testcase.minimized_keys != 'NA':
    mask = data_types.ArchiveStatus.MINIMIZED
  else:
    mask = data_types.ArchiveStatus.FUZZED

  if testcase.archive_state & mask:
    archive.unpack(testcase_path, testcase_directory)
    file_list = archive.get_file_list(testcase_path)

    testcase_path = None
    for file_name in file_list:
      if testcase.absolute_path.endswith(file_name):
        testcase_path = os.path.join(testcase_directory, file_name)
        break

    if not testcase_path:
      raise ReproduceToolException('Test case file was not found in archive.\n'
                                   'Original filename: {absolute_path}.\n'
                                   'Archive contents: {file_list}'.format(
                                       absolute_path=testcase.absolute_path,
                                       file_list=file_list))

  return testcase_path


def _prepare_initial_environment(build_directory):
  """Prepare common environment variables that don't depend on the job."""
  # Create a temporary directory to use as ROOT_DIR with a copy of the default
  # bot and configuration directories nested under it.
  root_dir = environment.get_value('ROOT_DIR')
  temp_root_dir = tempfile.mkdtemp()
  environment.set_value('ROOT_DIR', temp_root_dir)

  common.update_dir(
      os.path.join(root_dir, 'bot'), os.path.join(temp_root_dir, 'bot'))
  common.update_dir(
      os.path.join(root_dir, 'configs'), os.path.join(temp_root_dir, 'configs'))
  common.update_dir(
      os.path.join(root_dir, 'resources'),
      os.path.join(temp_root_dir, 'resources'))
  common.update_dir(
      os.path.join(root_dir, 'src'), os.path.join(temp_root_dir, 'src'))

  environment.set_value('CONFIG_DIR_OVERRIDE',
                        os.path.join(temp_root_dir, 'configs', 'test'))
  environment.set_value(
      'PYTHONPATH',
      os.pathsep.join(
          [os.path.join(temp_root_dir, 'src'),
           appengine.find_sdk_path()]))

  environment.set_bot_environment()

  # Overrides that should not be set to the default values.
  environment.set_value('APP_DIR', build_directory)
  environment.set_value('BUILD_DIR', build_directory)
  environment.set_value('BUILDS_DIR', build_directory)


def _update_environment_for_testcase(testcase, build_directory):
  """Update environment variables that depend on the test case."""
  commands.update_environment_for_job(testcase.job_definition)
  environment.set_value('JOB_NAME', testcase.job_type)

  # Update APP_PATH now that we know the application name.
  app_path = os.path.join(build_directory, environment.get_value('APP_NAME'))
  environment.set_value('APP_PATH', app_path)

  fuzzer_directory = setup.get_fuzzer_directory(testcase.fuzzer_name)
  environment.set_value('FUZZER_DIR', fuzzer_directory)

  setup.prepare_environment_for_testcase(testcase)

  build_manager.set_environment_vars(
      [environment.get_value('FUZZER_DIR'), build_directory])


def _reproduce_crash(testcase_id, build_directory):
  """Reproduce a crash."""
  _prepare_initial_environment(build_directory)
  testcase = _get_testcase(testcase_id)
  testcase_path = _download_testcase(testcase_id, testcase)
  _update_environment_for_testcase(testcase, build_directory)

  timeout = environment.get_value('TEST_TIMEOUT')
  result = testcase_manager.test_for_crash_with_retries(testcase, testcase_path,
                                                        timeout)

  # Clean up the temporary root directory created in prepare environment.
  shell.remove_directory(environment.get_value('ROOT_DIR'))

  return result


def execute(args):
  """Attempt to reproduce a crash then report on the result."""
  try:
    result = _reproduce_crash(args.testcase, args.build_dir)
  except ReproduceToolException as exception:
    print(exception)
    return

  if result.is_crash():
    status_message = 'Test case reproduced successfully.'
  else:
    status_message = 'Unable to reproduce desired crash.'

  print('{status_message} Output:\n\n{output}'.format(
      status_message=status_message, output=result.get_stacktrace()))
