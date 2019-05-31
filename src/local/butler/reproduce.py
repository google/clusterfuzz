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

import os
import six

from src.python.fuzzing import tests
from src.python.system import environment


class _SimplifiedTestcase(object):
  """Minimal representation of a test case."""

  def __init__(self, testcase_json):
    self.crash_state = testcase_json['crash_state']
    self.security_flag = testcase_json['security_flag']
    self.gestures = testcase_json['gestures']
    self.flaky_stack = testcase_json['flaky_stack']

    # Custom field not included in real test cases. Used in environment setup.
    self.job_definition = testcase_json['job_definition']


def _get_testcase(_):
  """Retrieve the json representation of the test case with the given id."""
  # TODO(mbarbella): Actually fetch the test case info from the server.
  testcase_json = {
      'crash_state': '',
      'security_flag': False,
      'gestures': [],
      'flaky_stack': False,
      'job_definition': 'APP_NAME = echo\nAPP_ARGS = -n\n',
  }

  return _SimplifiedTestcase(testcase_json)


def _download_testcase(_):
  """Download the test case and return its path."""
  # TODO(mbarbella): Implement this.
  return '/tmp/blah'


def _prepare_environment(testcase, build_directory):
  """Prepare environment variables based on the test case and build path."""
  environment.set_default_vars()

  # Environment variables used by the tool.
  environment.set_value('APP_DIR', build_directory)
  environment.set_value('BUILDS_DIR', build_directory)
  environment.set_value('INPUT_DIR', '/tmp/fixme')

  # Directories not needed by the reproduce tool but which require values.
  environment.set_value('BOT_TMPDIR', '/tmp/unused')
  environment.set_value('CRASH_STACKTRACES_DIR', '/tmp/unused')
  environment.set_value('FUZZER_DIR', '/tmp/unused')
  environment.set_value('USER_PROFILE_ROOT_DIR', '/tmp/unused')

  environment_values = (
      environment.parse_environment_definition(testcase.job_definition))
  for key, value in six.iteritems(environment_values):
    environment.set_value(key, value)

  # Fix app path once name is known.
  app_path = os.path.join(build_directory, environment.get_value('APP_NAME'))
  environment.set_value('APP_PATH', app_path)


def _reproduce_crash(testcase_id, build_dir):
  """Reproduce a crash."""
  testcase = _get_testcase(testcase_id)
  testcase_path = _download_testcase(testcase_id)
  _prepare_environment(testcase, build_dir)

  timeout = environment.get_value('TEST_TIMEOUT')
  result = tests.test_for_crash_with_retries(testcase, testcase_path, timeout)
  return result


def execute(args):
  """Attempt to reproduce a crash then report on the result."""
  result = _reproduce_crash(args.testcase, args.build_dir)

  # TODO(mbarbella): Report success/failure based on result.
  print(result.output)
