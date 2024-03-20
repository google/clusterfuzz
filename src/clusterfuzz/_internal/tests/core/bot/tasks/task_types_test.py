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
"""Tests for task_types."""
import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks import task_types
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class IsRemoteUtaskTest(unittest.TestCase):
  """Tests for is_remote_utask."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_mac(self):
    job_name = 'libfuzzer_mac_asan'

    with mock.patch(
        'clusterfuzz._internal.base.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='MAC').put()
      self.assertFalse(task_types.is_remote_utask('variant', job_name))

  @unittest.skip('No remote utasks')
  def test_linux(self):
    job_name = 'libfuzzer_linux_asan'

    with mock.patch(
        'clusterfuzz._internal.base.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='LINUX').put()
      self.assertTrue(task_types.is_remote_utask('progression', job_name))

  def test_trusted(self):
    job_name = 'libfuzzer_linux_asan'

    with mock.patch(
        'clusterfuzz._internal.base.task_utils.is_remotely_executing_utasks',
        return_value=True):
      data_types.Job(name=job_name, platform='LINUX').put()
      self.assertFalse(task_types.is_remote_utask('impact', job_name))
