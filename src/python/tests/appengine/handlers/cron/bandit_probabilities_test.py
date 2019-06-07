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
"""Tests for bandit_probabilities cron job."""

import json
import os
import unittest

from datastore import data_types
from handlers.cron import bandit_probabilities
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'bandit_probabilities_data')


@test_utils.with_cloud_emulators('datastore')
class TestUpdateBanditProbabilities(unittest.TestCase):
  """Test with patch for query. Tests whether the program properly
  stores calculated banidt weights in datastore"""

  def setUp(self):
    """set up method for bandit probability tests"""
    test_helpers.patch_environ(self)
    test_helpers.patch(
        self, ['handlers.cron.bandit_probabilities.query_libfuzzer_stats'])
    self.mock.query_libfuzzer_stats.return_value = json.load(
        open(os.path.join(DATA_DIRECTORY, 'bandit_query.json')))

  def test_bandit_probs(self):
    """unit tests for bandit weight updates"""
    bandit_probabilities.upload_bandit_weights(None)
    row1 = data_types.BanditProbabilities.query(
        data_types.BanditProbabilities.strategy_name == 'ml rnn,fork,').get()
    self.assertEqual(row1.strategy_bandit_probability, 0.008620604590128514)
    row2 = data_types.BanditProbabilities.query(
        data_types.BanditProbabilities.strategy_name ==
        'ml rnn,fork,subset,').get()
    self.assertEqual(row2.strategy_bandit_probability, 0.008052209440792676)
    row3 = data_types.BanditProbabilities.query(
        data_types.BanditProbabilities.strategy_name ==
        'max len,ml rnn,dict,').get()
    self.assertEqual(row3.strategy_bandit_probability, 0.01854100900807415)
