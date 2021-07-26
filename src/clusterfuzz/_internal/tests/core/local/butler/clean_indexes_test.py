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
"""clean_indexes test."""
from collections import namedtuple
import os
import unittest

import mock

Args = namedtuple('Args', 'config_dir')

from clusterfuzz._internal.tests.test_libs import helpers
from local.butler import clean_indexes


class ExecuteTest(unittest.TestCase):
  """Execute tests."""

  def setUp(self):
    helpers.patch(self, ['local.butler.common.execute'])
    self.mock.execute.return_value = (0, 'ok')

  def test_invalid_config_dir(self):
    """Tests execute with invalid config dir."""
    args = Args(config_dir='')
    with self.assertRaises(SystemExit):
      clean_indexes.execute(args)

  def test_valid_config_dir(self):
    """Tests execute with valid config dir."""
    args = Args(config_dir=os.getenv('CONFIG_DIR_OVERRIDE'))
    clean_indexes.execute(args)

    self.mock.execute.assert_has_calls([
        mock.call('gcloud datastore indexes cleanup --quiet '
                  '--project test-clusterfuzz src/appengine/index.yaml'),
    ])
