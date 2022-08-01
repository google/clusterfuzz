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
"""Fuzzer related helper functions for testcases."""

import os
import random

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.metrics import logs

# FIXME: Importing data_handler module is heavyweight and
# runs into exception with |oauth2client|. Skip and initialize
# constant directly.
LOCK_FILENAME = '.lock'


def create_testcase_list_file(testcase_file_paths, input_directory):
  """Store list of fuzzed testcases from fuzzer in a bot specific
  testcase list file."""
  if not testcase_file_paths:
    logs.log_error('No testcases found, skipping list file.')
    return

  bot_testcases_file_path = utils.get_bot_testcases_file_path(input_directory)
  with open(bot_testcases_file_path, 'wb') as bot_testcases_file_handle:
    bot_testcases_file_handle.write('\n'.join(testcase_file_paths))


def is_valid_testcase_file(file_path,
                           check_if_exists=True,
                           size_limit=None,
                           allowed_extensions=None):
  """Return true if the file looks like a testcase file."""
  return utils.is_valid_testcase_file(file_path, check_if_exists, size_limit,
                                      allowed_extensions)


def is_locked(input_directory):
  """Returns true if the data bundle is locked and unavailable for use."""
  lock_file_path = os.path.join(input_directory, LOCK_FILENAME)
  return os.path.exists(lock_file_path)


def get_random_testcases(input_directory, max_testcases):
  """Returns list of |max_testcases| testcases."""
  testcases_list = get_testcases(input_directory)
  return random.SystemRandom().sample(testcases_list, max_testcases)


def get_testcases(input_directory):
  """Returns list of testcase files."""
  testcase_list_file_path = os.path.join(
      input_directory, testcase_manager.TESTCASE_LIST_FILENAME)
  if not os.path.exists(testcase_list_file_path):
    return []

  with open(testcase_list_file_path, 'rb') as testcase_list_file_handle:
    testcase_relative_file_paths = testcase_list_file_handle.read().splitlines()

  testcase_file_paths = []
  for testcase_relative_file_path in testcase_relative_file_paths:
    # Discard junk paths.
    if not testcase_relative_file_path.strip():
      continue

    testcase_file_path = os.path.join(
        input_directory, testcase_relative_file_path.replace('/', os.sep))
    testcase_file_paths.append(testcase_file_path)

  return testcase_file_paths
