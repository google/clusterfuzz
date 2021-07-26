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

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import fuzz_strategy_selection

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'fuzz_strategy_selection_data')


@test_utils.with_cloud_emulators('datastore')
class TestFuzzStrategySelection(unittest.TestCase):
  """Tests whether the program properly stores
  calculated multi-armed bandit probabilities in datastore."""

  def setUp(self):
    """Set up method strategy distribution calculation tests."""
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'handlers.cron.fuzz_strategy_selection.'
        '_query_multi_armed_bandit_probabilities',
        'handlers.cron.fuzz_strategy_selection.'
        '_store_probabilities_in_bigquery'
    ])
    self.mock._query_multi_armed_bandit_probabilities.return_value = json.load(
        open(os.path.join(DATA_DIRECTORY, 'multi_armed_bandit_query.json')))

  def test_strategy_probabilities(self):
    """Ensure that the expected probabilities are being set for
    various methods."""

    # We pass an empty list as the query is patched out.
    fuzz_strategy_selection._query_and_upload_strategy_probabilities(
        fuzz_strategy_selection.LIBFUZZER_ENGINE)
    row1 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'corpus_mutations_ml_rnn,fork,').get()
    self.assertEqual(row1.probability, 0.0061753988734031835)
    self.assertEqual(row1.engine, 'libFuzzer')
    row2 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'corpus_mutations_ml_rnn,fork,corpus_subset,').get()
    self.assertEqual(row2.probability, 0.005077124089195762)
    self.assertEqual(row2.engine, 'libFuzzer')
    row3 = data_types.FuzzStrategyProbability.query(
        data_types.FuzzStrategyProbability.strategy_name ==
        'random_max_len,corpus_mutations_ml_rnn,recommended_dict,').get()
    self.assertEqual(row3.probability, 0.011855451527667878)
    self.assertEqual(row3.engine, 'libFuzzer')

  def test_delete_from_table(self):
    """Ensures that ndb datastore table is properly being
    cleared before being updated."""

    # We pass an empty list as the query is patched out.
    fuzz_strategy_selection._query_and_upload_strategy_probabilities(
        fuzz_strategy_selection.LIBFUZZER_ENGINE)
    count1 = data_types.FuzzStrategyProbability.query().count()
    fuzz_strategy_selection._query_and_upload_strategy_probabilities(
        fuzz_strategy_selection.LIBFUZZER_ENGINE)
    count2 = data_types.FuzzStrategyProbability.query().count()
    self.assertEqual(count1, count2)
