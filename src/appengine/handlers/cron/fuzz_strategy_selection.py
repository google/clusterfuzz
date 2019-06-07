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
  metric to be for edges, crash, features, or units. Currently based on new edges."""

from datastore import data_types
from datastore import ndb
from google_cloud_utils import big_query
from handlers import base_handler
from libs import handler




"""BigQuery query for calculating multi-armed bandit probabilities for
various strategies using a Boltzman Exploration (softmax) model.

See https://www.cs.mcgill.ca/~vkules/bandits.pdf
"""
MULTI_ARMED_BANDIT_PROB = """
SELECT
  EXP(standardized_avg_ne / temp_p) / (SUM(EXP(standardized_avg_ne / temp_p)) OVER()) AS edges_bandit,
  EXP(standardized_avg_cc / temp_p) / (SUM(EXP(standardized_avg_cc / temp_p)) OVER()) AS crash_bandit,
  EXP(standardized_avg_nf / temp_p) / (SUM(EXP(standardized_avg_nf / temp_p)) OVER()) AS features_bandit,
  EXP(standardized_avg_nu / temp_p) / (SUM(EXP(standardized_avg_nu / temp_p)) OVER()) AS units_bandit,
  strategy,
  strategy_count
FROM (
  SELECT
    CONCAT(s_radamsa, s_max_len, s_ml_rnn, s_vp, s_corpus, s_fork, s_subset, s_recommended_dict) AS strategy,
    AVG((crash_count - avg_cc) / stddev_cc) AS standardized_avg_cc,
    AVG((new_edges - avg_ne) / stddev_ne) AS standardized_avg_ne,
    AVG((new_features - avg_nf) / stddev_nf) AS standardized_avg_nf,
    AVG((new_units_added - avg_nu) / stddev_nu) AS standardized_avg_nu,
    COUNT(*) AS strategy_count,
    "any" AS matcher,
    /* Change temperature parameter here. */ .2 AS temp_p
  FROM (
    SELECT
    IF
      (strategy_corpus_mutations_radamsa > 0,
        "radamsa,",
        "") AS s_radamsa,
    IF
      (strategy_random_max_len>0,
        "max len,",
        "") AS s_max_len,
    IF
      (strategy_corpus_mutations_ml_rnn>0,
        "ml rnn,",
        "") AS s_ml_rnn,
    IF
      (strategy_value_profile > 0,
        "value profile,",
        "") AS s_vp,
    IF
      (strategy_corpus_mutations > 0,
        "corpus,",
        "") AS s_corpus,
    IF
      (strategy_fork > 0,
        "fork,",
        "") AS s_fork,
    IF
      (strategy_corpus_subset > 0,
        "subset,",
        "") AS s_subset,
    IF
      (strategy_recommended_dict > 0,
        "dict,",
        "") AS s_recommended_dict,
      AVG(crash_count) OVER() AS avg_cc,
      AVG(new_edges) OVER() AS avg_ne,
      AVG(new_features) OVER() AS avg_nf,
      AVG(new_units_added) OVER() AS avg_nu,
      STDDEV(crash_count) OVER() AS stddev_cc,
      STDDEV(new_edges) OVER() AS stddev_ne,
      STDDEV(new_features) OVER() AS stddev_nf,
      STDDEV(new_units_added) OVER() AS stddev_nu,
      crash_count,
      new_edges,
      new_features,
      new_units_added
    FROM
      libFuzzer_stats.TestcaseRun
    WHERE
      ((strategy_mutator_plugin = 0)
        OR (strategy_mutator_plugin IS NULL))
      AND DATE_DIFF(CAST(CURRENT_TIMESTAMP() AS DATE), CAST(_PARTITIONTIME AS DATE), DAY) < 31
      AND ((strategy_corpus_mutations = 0)
        OR (strategy_corpus_mutations IS NULL))
      AND ((strategy_handle_unstable = 0)
        OR (strategy_handle_unstable IS NULL))
      AND ((strategy_weighted_mutations = 0)
        OR (strategy_weighted_mutations IS NULL)))
  GROUP BY
    strategy)
"""


def _query_multi_armed_bandit_probs(client):
  """Get query results.

  Queries above query (MULTI_ARMED_BANDIT_PROB) and yields results
  from bigquery. This query is sorted by strategies implemented."""
  return client.query(query=MULTI_ARMED_BANDIT_PROB)


def _upload_fuzz_strategy_weights(client):
  """Uploads queried data into datastore.

  Upload query results to datastore to use as new probabilities
  currently using edges as bandit metric, can change below by selecting
  a bandit field for one of the other metrics (features, units, crash)"""
  strategy_data = []
  data = _query_multi_armed_bandit_probs(client)
  
  for row in data:
    curr_strategy = data_types.FuzzStrategyProbability()
    curr_strategy.strategy_name = str(row['strategy'])
    curr_strategy.strategy_count = int(row['strategy_count'])
    curr_strategy.strategy_probability = float(row['edges_bandit'])
    strategy_data.append(curr_strategy)
  ndb.put_multi(strategy_data)


class Handler(base_handler.Handler):
  """Cron job handler for fuzz strategy selection.

  Handler to periodically update fuzz strategy bandit probabilities
   based on a performance metric (currently based on new_edges)."""

  @handler.check_cron()
  def get(self):
    """Process all fuzz targets and update FuzzStrategy weights."""
    client = big_query.Client()
    _upload_fuzz_strategy_weights(client)
