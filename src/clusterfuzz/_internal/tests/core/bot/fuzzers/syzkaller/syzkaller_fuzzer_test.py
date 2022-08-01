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
"""Tests for syzkaller engine."""
# pylint: disable=unused-argument

import os
import shutil
import unittest

from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(TEST_PATH, 'test_data')
TEMP_DIR = os.path.join(TEST_PATH, 'temp')


def clear_temp_dir():
  """Clear temp directory."""
  if os.path.exists(TEMP_DIR):
    shutil.rmtree(TEMP_DIR)

  os.mkdir(TEMP_DIR)


@test_utils.integration
class IntegrationTest(unittest.TestCase):
  """Integration tests."""

  def setUp(self):
    test_helpers.patch_environ(self)

    os.environ['BUILD_DIR'] = DATA_DIR
