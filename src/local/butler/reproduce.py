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
import shutil
import tempfile
import time

from urllib import parse

from base import json_utils
from base import utils
from bot import testcase_manager
from bot.tasks import commands
from bot.tasks import setup
from build_management import build_manager
from datastore import data_types
from local.butler import appengine
from local.butler.reproduce_tool import config
from local.butler.reproduce_tool import errors
from local.butler.reproduce_tool import http_utils
from local.butler.reproduce_tool import prompts
from platforms.android import device
from system import archive
from system import environment
from system import new_process
from system import shell

CONFIG_DIRECTORY = os.path.join(
    os.path.expanduser('~'), '.config', 'clusterfuzz')
DISPLAY = ':99'
PROCESS_START_WAIT_SECONDS = 2
SUPPORTED_PLATFORMS = ['android', 'linux', 'mac']


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

  def actual_fuzzer_name(self):
    """Actual fuzzer name, uses one from overridden attribute if available."""
    return self.overridden_fuzzer_name or self.fuzzer_name


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
  print('Downloading testcase...')
  testcase_download_url = '{url}?id={id}'.format(
      url=configuration.get('testcase_download_url'), id=testcase_id)
  response, content = http_utils.request(
      testcase_download_url,
      method=http_utils.GET_METHOD,
      configuration=configuration)

  if response.status != 200:
    raise errors.ReproduceToolUnrecoverableError(
        'Unable to download test case.')

  bot_absolute_filename = response['x-goog-meta-filename']
  # Store the test case in the config directory for debuggability.
  testcase_directory = os.path.join(CONFIG_DIRECTORY, 'current-testcase')
  shell.remove_directory(testcase_directory, recreate=True)
  environment.set_value('FUZZ_INPUTS', testcase_directory)
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
      if os.path.basename(file_name) == os.path.basename(
          testcase.absolute_path):
        testcase_path = os.path.join(testcase_directory, file_name)
        break

    if not testcase_path:
      raise errors.ReproduceToolUnrecoverableError(
          'Test case file was not found in archive.\n'
          'Original filename: {absolute_path}.\n'
          'Archive contents: {file_list}'.format(
              absolute_path=testcase.absolute_path, file_list=file_list))

  return testcase_path


def _setup_x():
  """Start Xvfb and blackbox before running the test application."""
  if environment.platform() != 'LINUX':
    return []

  if environment.is_engine_fuzzer_job():
    # For engine fuzzer jobs like AFL, libFuzzer, Xvfb is not needed as the
    # those fuzz targets do not needed a UI.
    return []

  environment.set_value('DISPLAY', DISPLAY)

  print('Starting Xvfb...')
  xvfb_runner = new_process.ProcessRunner('/usr/bin/Xvfb')
  xvfb_process = xvfb_runner.run(additional_args=[
      DISPLAY, '-screen', '0', '1280x1024x24', '-ac', '-nolisten', 'tcp'
  ])
  time.sleep(PROCESS_START_WAIT_SECONDS)

  print('Starting blackbox...')
  blackbox_runner = new_process.ProcessRunner('/usr/bin/blackbox')
  blackbox_process = blackbox_runner.run()
  time.sleep(PROCESS_START_WAIT_SECONDS)

  # Return all handles we create so they can be terminated properly at exit.
  return [xvfb_process, blackbox_process]


def _prepare_initial_environment(build_directory, iterations):
  """Prepare common environment variables that don't depend on the job."""
  # Create a temporary directory to use as ROOT_DIR with a copy of the default
  # bot and configuration directories nested under it.
  root_dir = environment.get_value('ROOT_DIR')
  temp_root_dir = tempfile.mkdtemp()
  environment.set_value('ROOT_DIR', temp_root_dir)

  def _update_directory(directory_name, ignore_paths=None):
    """Copy a subdirectory from a checkout to a temp directory."""
    if not ignore_paths:
      ignore_paths = []

    shutil.copytree(
        os.path.join(root_dir, directory_name),
        os.path.join(temp_root_dir, directory_name),
        ignore=lambda directory, contents:
        contents if directory in ignore_paths else [])

  _update_directory('bot')
  _update_directory('configs')
  _update_directory('resources')
  _update_directory(
      'src',
      ignore_paths=[
          os.path.join(root_dir, 'src', 'appengine'),
          os.path.join(root_dir, 'src', 'bazel-bin'),
          os.path.join(root_dir, 'src', 'bazel-genfiles'),
          os.path.join(root_dir, 'src', 'bazel-out'),
          os.path.join(root_dir, 'src', 'bazel-src'),
          os.path.join(root_dir, 'src', 'python', 'tests'),
      ])

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

  # Some functionality must be disabled when running the tool.
  environment.set_value('REPRODUCE_TOOL', 'True')

  # Force logging to console for this process and child processes.
  environment.set_value('LOG_TO_CONSOLE', 'True')

  if iterations:
    environment.set_value('CRASH_RETRIES', iterations)


def _verify_target_exists(build_directory):
  """Ensure that we can find the test target before running it.

  Separated into its own function to simplify test behavior."""
  app_path = environment.get_value('APP_PATH')
  if not app_path or not os.path.exists(app_path):
    raise errors.ReproduceToolUnrecoverableError(
        'Unable to locate app binary in {build_directory}.'.format(
            build_directory=build_directory))


def _update_environment_for_testcase(testcase, build_directory):
  """Update environment variables that depend on the test case."""
  commands.update_environment_for_job(testcase.job_definition)
  environment.set_value('JOB_NAME', testcase.job_type)

  fuzzer_directory = setup.get_fuzzer_directory(testcase.fuzzer_name)
  environment.set_value('FUZZER_DIR', fuzzer_directory)

  setup.prepare_environment_for_testcase(testcase)

  build_manager.set_environment_vars(
      [environment.get_value('FUZZER_DIR'), build_directory])

  _verify_target_exists(build_directory)


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
        'https://clusterfuzz-domain/testcase-detail/1234567890'.format(
            url=testcase_url))

  return testcase_id


def _prepare_environment_for_android():
  """Additional environment overrides needed to run on an Android device."""
  environment.set_value('OS_OVERRIDE', 'ANDROID')

  # Bail out if we don't have an Android device connected.
  serial = environment.get_value('ANDROID_SERIAL')
  if not serial:
    # TODO(mbarbella): Handle the one-device case gracefully.
    raise errors.ReproduceToolUnrecoverableError('Please set ANDROID_SERIAL.')

  willing_to_continue = prompts.get_boolean(
      'Warning: this tool will make changes to settings on the connected '
      'android device with serial {serial} that could result in data loss. Are '
      'you sure you want to continue?'.format(serial=serial))
  if not willing_to_continue:
    raise errors.ReproduceToolUnrecoverableError(
        'Bailing out to avoid changing settings on the connected device.')

  # Push the test case and build APK to the device.
  apk_path = environment.get_value('APP_PATH')
  device.update_build(apk_path)

  device.push_testcases_to_device()


def _reproduce_crash(testcase_url, build_directory, iterations, disable_xvfb):
  """Reproduce a crash."""
  _prepare_initial_environment(build_directory, iterations)

  # Validate the test case URL and fetch the tool's configuration.
  testcase_id = _get_testcase_id_from_url(testcase_url)
  configuration = config.ReproduceToolConfiguration(testcase_url)

  testcase = _get_testcase(testcase_id, configuration)

  # Ensure that we support this test case.
  if testcase.platform not in SUPPORTED_PLATFORMS:
    raise errors.ReproduceToolUnrecoverableError(
        'The reproduce tool is not yet supported on {platform}.'.format(
            platform=testcase.platform))

  testcase_path = _download_testcase(testcase_id, testcase, configuration)
  _update_environment_for_testcase(testcase, build_directory)

  # Validate that we're running on the right platform for this test case.
  platform = environment.platform().lower()
  if testcase.platform == 'android' and platform == 'linux':
    _prepare_environment_for_android()
  elif testcase.platform == 'android' and platform != 'linux':
    raise errors.ReproduceToolUnrecoverableError(
        'The ClusterFuzz environment only supports running Android test cases '
        'on Linux host machines. Unable to reproduce the test case on '
        '{current_platform}.'.format(current_platform=platform))
  elif testcase.platform != platform:
    raise errors.ReproduceToolUnrecoverableError(
        'The specified test case was discovered on {testcase_platform}. '
        'Unable to attempt to reproduce it on {current_platform}.'.format(
            testcase_platform=testcase.platform, current_platform=platform))

  x_processes = []
  if not disable_xvfb:
    _setup_x()
  timeout = environment.get_value('TEST_TIMEOUT')

  print('Running testcase...')
  result = testcase_manager.test_for_crash_with_retries(testcase, testcase_path,
                                                        timeout)

  # Terminate Xvfb and blackbox.
  for process in x_processes:
    process.terminate()

  return result


def _cleanup():
  """Clean up after running the tool."""
  temp_directory = environment.get_value('ROOT_DIR')
  assert 'tmp' in temp_directory
  shell.remove_directory(temp_directory)


def execute(args):
  """Attempt to reproduce a crash then report on the result."""
  # The current working directory may change while we're running.
  absolute_build_dir = os.path.abspath(args.build_dir)
  try:
    result = _reproduce_crash(args.testcase, absolute_build_dir,
                              args.iterations, args.disable_xvfb)
  except errors.ReproduceToolUnrecoverableError as exception:
    print(exception)
    return

  print('Output:\n{output}'.format(output=result.get_stacktrace()))

  if result.is_crash():
    status_message = 'Test case reproduced successfully.'
  else:
    status_message = 'Unable to reproduce desired crash.'
  print(status_message)

  _cleanup()
