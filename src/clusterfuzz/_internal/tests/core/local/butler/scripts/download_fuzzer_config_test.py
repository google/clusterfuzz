# Copyright 2026 Google LLC
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
"""Tests for download_fuzzer_config."""

import json
import os
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler.scripts import download_fuzzer_config


class Args:

  def __init__(self, script_args, non_dry_run=True):
    self.script_args = script_args
    self.non_dry_run = non_dry_run


@test_utils.with_cloud_emulators('datastore')
class DownloadFuzzerConfigTest(unittest.TestCase):
  """Tests for download_fuzzer_config."""

  def setUp(self):
    helpers.patch(
        self,
        [
            'sys.exit',
        ],
    )

    self.fuzzer1 = data_types.Fuzzer(
        name='fuzzer1',
        jobs=['job1'],
        data_bundle_name='data_bundle1',
        timeout=10,
        max_testcases=100,
        external_contribution=True,
        additional_environment_string='A=1',
        executable_path='path/to/exec1',
        launcher_script='path/to/launcher1',
    )
    self.fuzzer1.put()

    self.fuzzer2 = data_types.Fuzzer(
        name='fuzzer2',
        jobs=[],
        data_bundle_name='data_bundle2',
        timeout=20,
        max_testcases=200,
        external_contribution=False,
        additional_environment_string='B=2',
        executable_path='path/to/exec2',
        launcher_script='path/to/launcher2',
    )
    self.fuzzer2.put()

  def tearDown(self):
    if os.path.exists('fuzzer1_config.json'):
      os.remove('fuzzer1_config.json')
    if os.path.exists('fuzzer2_config.json'):
      os.remove('fuzzer2_config.json')

  def test_execute_success(self):
    """Test successful download."""
    args = Args(['fuzzer1', 'fuzzer2'])
    download_fuzzer_config.execute(args)

    with open('fuzzer1_config.json') as f:
      config1 = json.load(f)
      self.assertEqual(['job1'], config1['jobs'])
      self.assertEqual('data_bundle1', config1['data_bundle_name'])
      self.assertEqual(10, config1['timeout'])

    with open('fuzzer2_config.json') as f:
      config2 = json.load(f)
      self.assertEqual([], config2['jobs'])
      self.assertEqual('data_bundle2', config2['data_bundle_name'])
      self.assertEqual(20, config2['timeout'])

  def test_execute_not_found(self):
    """Test fuzzer not found."""
    args = Args(['fuzzer1', 'fuzzer_missing'])
    download_fuzzer_config.execute(args)

    self.assertTrue(os.path.exists('fuzzer1_config.json'))
    self.assertFalse(os.path.exists('fuzzer_missing_config.json'))
