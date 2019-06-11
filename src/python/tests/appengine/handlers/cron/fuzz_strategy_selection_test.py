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
"""Tests for fuzz_strategy_selection cron job."""
# pylint: disable=protected-access

import json
import os
import unittest

from datastore import data_types
from handlers.cron import fuzz_strategy_selection
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'fuzz_strategy_selection_data')


@test_utils.with_cloud_emulators('datastore')
class TestFuzzStrategySelection(unittest.TestCase):
  """Tests whether the program properly
  stores calculated banidt weights in datastore."""

  def setUp(self):
    """Set up method strategy distribution calculation tests."""
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'handlers.cron.fuzz_strategy_selection._query_multi_armed_bandit_probs'
    ])
    self.mock._query_multi_armed_bandit_probs.return_value = json.load(
        open(os.path.join(DATA_DIRECTORY, 'multi_armed_bandit_query.json')))

  def test_strategy_probs(self):
    """Ensure that the expected weights are being set for
    various methods."""
    fuzz_strategy_selection._upload_fuzz_strategy_weights(None)
    row1 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'ml rnn,fork,').get()
    self.assertEqual(row1.probability, 0.008499377133881613)
    row2 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'ml rnn,fork,subset,').get()
    self.assertEqual(row2.probability, 0.008034989621423334)
    row3 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'max len,ml rnn,dict,').get()
    self.assertEqual(row3.probability, 0.03471989092623837)

  def test_delete_from_table(self):
    """Ensures that ndb datastore table is properly being
    cleared before being updated."""
    fuzz_strategy_selection._upload_fuzz_strategy_weights(None)
    count1 = data_types.FuzzStrategyProbability.query().count()
    fuzz_strategy_selection._upload_fuzz_strategy_weights(None)
    count2 = data_types.FuzzStrategyProbability.query().count()
    self.assertEqual(count1, count2)
