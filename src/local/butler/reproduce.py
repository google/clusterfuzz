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
from future import standard_library
standard_library.install_aliases()

from python.base import modules
modules.fix_module_search_paths()

import os
import tempfile

from urllib import parse

from base import json_utils
from base import utils
from bot.tasks import commands
from bot.tasks import setup
from build_management import build_manager
from datastore import data_types
from fuzzing import testcase_manager
from local.butler import appengine
from local.butler import common
from local.butler.reproduce_tool import config
from local.butler.reproduce_tool import errors
from local.butler.reproduce_tool import http_utils
from system import archive
from system import environment
from system import shell


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


def _get_testcase(testcase_id, configuration):
  """Retrieve the json representation of the test case with the given id."""
  response, content = http_utils.request(
      configuration.get('testcase_info_url'),
      body={'testcaseId': testcase_id},
      configuration=configuration)

  if response.status != 200:
    raise errors.ReproduceToolUnrecoverableError(
        'Unable to fetch test case information.')

  testcase_map = json_utils.loads(content)
  return SerializedTestcase(testcase_map)


def _download_testcase(testcase_id, testcase, configuration):
  """Download the test case and return its path."""
  testcase_download_url = '{url}?id={id}'.format(
      url=configuration.get('testcase_download_url'), id=testcase_id)
  response, content = http_utils.request(
      testcase_download_url,
      method=http_utils.GET_METHOD,
      configuration=configuration)

  if response.status != 200:
    raise errors.ReproduceToolUnrecoverableError(
        'Unable to download test case.')

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
      raise errors.ReproduceToolUnrecoverableError(
          'Test case file was not found in archive.\n'
          'Original filename: {absolute_path}.\n'
          'Archive contents: {file_list}'.format(
              absolute_path=testcase.absolute_path, file_list=file_list))

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

  # Avoid kililng the application we're testing as developers may have it
  # running on the side.
  environment.set_value('KILL_PROCESSES_MATCHING_APP_NAME', 'False')


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


def _get_testcase_id_from_url(testcase_url):
  """Convert a testcase URL to a testcase ID."""
  url_parts = parse.urlparse(testcase_url)
  # Testcase urls have paths like "/testcase-detail/1234567890", where the
  # number is the testcase ID.
  path_parts = url_parts.path.split('/')

  try:
    testcase_id = int(path_parts[-1])
  except (ValueError, IndexError):
    testcase_id = 0

  # Validate that the URL is correct.
  if (len(path_parts) != 3 or path_parts[0] or
      path_parts[1] != 'testcase-detail' or not testcase_id):
    raise errors.ReproduceToolUnrecoverableError(
        'Invalid testcase URL {url}. Expected format: '
        'https://clusterfuzz-deployment/testcase-detail/1234567890'.format(
            url=testcase_url))

  return testcase_id


def _reproduce_crash(testcase_url, build_directory):
  """Reproduce a crash."""
  _prepare_initial_environment(build_directory)

  # Validate the test case URL and fetch the tool's configuration.
  testcase_id = _get_testcase_id_from_url(testcase_url)
  configuration = config.ReproduceToolConfiguration(testcase_url)

  testcase = _get_testcase(testcase_id, configuration)
  testcase_path = _download_testcase(testcase_id, testcase, configuration)
  _update_environment_for_testcase(testcase, build_directory)

  timeout = environment.get_value('TEST_TIMEOUT')
  result = testcase_manager.test_for_crash_with_retries(testcase, testcase_path,
                                                        timeout)

  # Get the return code and symbolized stacktrace before cleaning up.
  return_value = (result.is_crash(), result.get_stacktrace())

  # Clean up the temporary root directory created in prepare environment.
  shell.remove_directory(environment.get_value('ROOT_DIR'))

  return return_value


def execute(args):
  """Attempt to reproduce a crash then report on the result."""
  try:
    is_crash, stacktrace = _reproduce_crash(args.testcase, args.build_dir)
  except errors.ReproduceToolUnrecoverableError as exception:
    print(exception)
    return

  if is_crash:
    status_message = 'Test case reproduced successfully.'
  else:
    status_message = 'Unable to reproduce desired crash.'

  print('{status_message} Output:\n\n{output}'.format(
      status_message=status_message, output=stacktrace))
