# Copyright 2024 Google LLC
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
"""Swarming config error tests."""
import unittest
from unittest import mock

from clusterfuzz._internal import swarming
from clusterfuzz._internal.base.errors import BadConfigError
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class SwarmingConfigErrorTest(unittest.TestCase):
  """Tests for swarming utils when config is missing."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.swarming.FeatureFlags',
        'clusterfuzz._internal.google_cloud_utils.compute_metadata.get',
    ])
    helpers.patch_environ(self)
    self.mock.FeatureFlags.SWARMING_REMOTE_EXECUTION.enabled = True
    self.mock.get.return_value = None

  def test_is_swarming_task_bad_config(self):
    """Tests that is_swarming_task returns False when there's a BadConfigError."""
    with mock.patch('clusterfuzz._internal.config.local_config.SwarmingConfig'
                   ) as mock_config:
      mock_config.side_effect = BadConfigError('test')
      job = data_types.Job(
          name='libfuzzer_chrome_asan',
          platform='LINUX',
          environment_string='IS_SWARMING_JOB = True')
      job.put()
      self.assertFalse(swarming.is_swarming_task(job.name))

  def test_create_new_task_request_bad_config(self):
    """Tests that create_new_task_request returns None when there's a BadConfigError."""
    with mock.patch('clusterfuzz._internal.config.local_config.SwarmingConfig'
                   ) as mock_config:
      mock_config.side_effect = BadConfigError('test')
      job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
      job.put()
      spec = swarming.create_new_task_request('fuzz', job.name,
                                              'https://download_url')
      self.assertIsNone(spec)
