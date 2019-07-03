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
"""Fuzzing strategy selection cron job.

Runs multi-armed bandit experiments for fuzzing strategy selection.
In particular, this is a Boltzman Exploration (softmax) implementaion
of multi-armed bandit experiments. Queries from bigquery to update
multi-armed bandit probability values based on the new edges for various
combined strategies. In the upload_bandit_weights function, we can change
metric to be for edges, crash, features, or units. Currently based on new
edges."""

from datastore import data_types
from datastore import ndb
from datastore import ndb_utils
from google_cloud_utils import big_query
from handlers import base_handler
from libs import handler

# BigQuery query for calculating multi-armed bandit probabilities for
# various strategies using a Boltzman Exploration (softmax) model.

# Averages standardized new_edges feature over each strategy for expected
# new_edges metric for each strategy.
# See https://www.cs.mcgill.ca/~vkules/bandits.pdf for formula.

BANDIT_PROBABILITY_QUERY = """
SELECT
  /* Calculate bandit weights from calculated exponential values. */
  strategy,
  strategy_exp / exp_sum AS bandit_weight,
  run_count
FROM
  (SELECT
    EXP(strategy_avg_edges / temperature) AS strategy_exp,
    SUM(EXP(strategy_avg_edges / temperature)) OVER() AS exp_sum,
    strategy,
    run_count
  FROM
    (SELECT
      /* Standardize the new edges data and take averages per strategy. */
      AVG((new_edges - overall_avg_new_edges) / overall_stddev_new_edges) AS strategy_avg_edges,
      strategy,
      /* Change temperature parameter here. */
      .5 as temperature,
      COUNT(*) AS run_count
    FROM
      (SELECT
        fuzzer,
        CONCAT(s_radamsa, s_max_len, s_ml_rnn, s_vp, s_fork, s_subset, s_recommended_dict) AS strategy,
        fuzzer_stddev,
        AVG(new_edges) OVER() AS overall_avg_new_edges,
        STDDEV(new_edges) OVER() AS overall_stddev_new_edges,
        new_edges
      FROM
        (SELECT
          fuzzer,
          IF(strategy_corpus_mutations_radamsa > 0, "corpus_mutations_radamsa,", "") AS s_radamsa,
          IF(strategy_random_max_len > 0, "random_max_len,", "") AS s_max_len,
          IF(strategy_corpus_mutations_ml_rnn > 0,"corpus_mutations_ml_rnn,", "") AS s_ml_rnn, 
          IF(strategy_value_profile > 0, "value_profile,", "") AS s_vp, 
          IF(strategy_fork > 0, "fork,", "") AS s_fork,
          IF(strategy_corpus_subset > 0, "corpus_subset,", "") AS s_subset,
          IF(strategy_recommended_dict > 0, "recommended_dict,", "") AS s_recommended_dict,
          STDDEV(new_edges) OVER(PARTITION by fuzzer) AS fuzzer_stddev,
          new_edges
        FROM 
          libFuzzer_stats.TestcaseRun
        WHERE
          ((strategy_mutator_plugin = 0) OR (strategy_mutator_plugin IS NULL)) AND
          /* Query results from the past 30 days. Change as needed. */
          DATE_DIFF(cast(current_timestamp() AS DATE), cast(_PARTITIONTIME AS DATE), DAY) < 31
        )
      WHERE
        /* Filter for unstable targets. */
        fuzzer_stddev < 150)
    GROUP BY
      strategy))
ORDER BY
  bandit_weight DESC
"""


def _query_multi_armed_bandit_probabilities():
  """Get query results.

  Queries above BANDIT_PROBABILITY_QUERY and yields results
  from bigquery. This query is sorted by strategies implemented."""
  client = big_query.Client()
  return client.query(query=BANDIT_PROBABILITY_QUERY).rows


def _store_probabilities_in_bigquery(data):
  """Update a bigquery table containing the daily updated
  probability distribution over strategies."""
  bigquery_data = []

  for row in data:
    bigquery_row = {
        'strategy_name': row['strategy'],
        'probability': row['bandit_weight'],
        'run_count': row['run_count']
    }
    bigquery_data.append(big_query.Insert(row=bigquery_row, insert_id=None))

  client = big_query.Client(
      dataset_id='main', table_id='fuzz_strategy_probability')
  client.insert(bigquery_data)


def _query_and_upload_strategy_probabilities():
  """Uploads queried data into datastore.

  Calls query functions and uploads query results
  to datastore to use as new probabilities. Probabilities
  are based on new_edges feature."""
  strategy_data = []
  data = _query_multi_armed_bandit_probabilities()

  for row in data:
    curr_strategy = data_types.FuzzStrategyProbability()
    curr_strategy.strategy_name = str(row['strategy'])
    curr_strategy.probability = float(row['bandit_weight'])
    strategy_data.append(curr_strategy)

  ndb.delete_multi([
      entity.key for entity in ndb_utils.get_all_from_model(
          data_types.FuzzStrategyProbability)
  ])
  ndb.put_multi(strategy_data)
  _store_probabilities_in_bigquery(data)


class Handler(base_handler.Handler):
  """Cron job handler for fuzz strategy selection.

  Handler to periodically update fuzz strategy bandit probabilities
  based on a performance metric (currently based on new_edges)."""

  @handler.check_cron()
  def get(self):
    """Process all fuzz targets and update FuzzStrategy weights."""
    _query_and_upload_strategy_probabilities()
