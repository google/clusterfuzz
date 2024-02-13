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
"""Tests for Google Cloud Profiler integration."""

import time
import unittest

from clusterfuzz._internal.metrics import profiler
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers


class ProfilerTest(unittest.TestCase):
  """Test Google Cloud Profiler."""

  def setUp(self):
    helpers.patch_environ(self)
    environment.set_value('USE_PYTHON_PROFILER', True)

    self.fake_profile = {
        'profileType': 'type',
        'deployment': 'deployment',
        'duration': 123,
    }

    helpers.patch(self, [
        'googlecloudprofiler.backoff.Backoff.next_backoff',
        'googlecloudprofiler.client.Client.setup_auth',
        'googlecloudprofiler.client.Client._build_service',
        'googlecloudprofiler.client.Client._create_profile',
        'googlecloudprofiler.client.Client._collect_and_upload_profile',
    ])

    # Time in seconds used in a sleep call inside profiler loop.
    self.mock.next_backoff.return_value = 0.005
    self.mock.setup_auth.return_value = 'project_id'
    self.mock._build_service.return_value = None  # pylint: disable=protected-access
    self.mock._create_profile.return_value = self.fake_profile  # pylint: disable=protected-access

  def test_profiler(self):
    """Test profiler."""
    profiler.start_if_needed('python_profiler_unit_test_service')

    # A dummy code to spend a few moments on.
    counter = 12345
    for _ in range(5):
      time.sleep(0.01)
      counter *= counter

    self.assertLess(0,
                    len(self.mock._collect_and_upload_profile.call_args_list))  # pylint: disable=protected-access
    self.assertEqual((self.fake_profile,),
                     self.mock._collect_and_upload_profile.call_args[0][1:])  # pylint: disable=protected-access
