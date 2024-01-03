# Copyright 2023 Google LLC
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
"""Tests for blame task."""
import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.tests.test_libs import helpers


class UTaskCombinedTest(unittest.TestCase):

  def setUp(self):
    helpers.patch_environ(self)

  def test_is_remote(self):
    with mock.patch(
        'clusterfuzz._internal.bot.tasks.task_types.is_remotely_executing_utasks',
        return_value=True):
      self.assertTrue(task_types.UTaskCombined.is_execution_remote())
