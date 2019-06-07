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
"""Bandit probabilities cron job. Queries from bigquery for updated probability
	values based on new edges for various combined strategies."""

from datastore import data_types
from datastore import ndb
from google_cloud_utils import big_query
from handlers import base_handler
from libs import handler

MULTIPLE_STRATEGY_PROBABILITY_QUERY = """
SELECT 
  EXP(standardized_avg_ne / temp_p) / (SUM(EXP(standardized_avg_ne / temp_p)) OVER()) as edges_bandit,
  EXP(standardized_avg_cc / temp_p) / (SUM(EXP(standardized_avg_cc / temp_p)) OVER()) as crash_bandit,
  EXP(standardized_avg_nf / temp_p) / (SUM(EXP(standardized_avg_nf / temp_p)) OVER()) as features_bandit,
  EXP(standardized_avg_nu / temp_p) / (SUM(EXP(standardized_avg_nu / temp_p)) OVER()) as units_bandit,
  strategy,
  strategy_count 
FROM
  (SELECT
	CONCAT(s_radamsa, s_max_len, s_ml_rnn, s_vp, s_corpus, s_fork, s_subset, s_recommended_dict) AS strategy,
	AVG((crash_count - avg_cc) / stddev_cc) as standardized_avg_cc,
	AVG((new_edges - avg_ne) / stddev_ne) as standardized_avg_ne,
	AVG((new_features - avg_nf) / stddev_nf) as standardized_avg_nf,
	AVG((new_units_added - avg_nu) / stddev_nu) as standardized_avg_nu,
	COUNT(*) as strategy_count,
	"any" as matcher,
	/*CHANGE TEMPERATURE HERE*/
	.2 as temp_p
  FROM
	(SELECT
	  IF(strategy_corpus_mutations_radamsa > 0, "radamsa,", "") AS s_radamsa,
	  IF(strategy_random_max_len>0, "max len,", "") AS s_max_len,
	  IF(strategy_corpus_mutations_ml_rnn>0,"ml rnn,", "") AS s_ml_rnn, 
	  IF(strategy_value_profile > 0, "value profile,", "") AS s_vp, 
	  IF(strategy_corpus_mutations > 0, "corpus,", "") AS s_corpus,
	  IF(strategy_fork > 0, "fork,", "") AS s_fork,
	  /* MIGHT NOT USE SUBSET*/
	  IF(strategy_corpus_subset > 0, "subset,", "") AS s_subset,
	  IF(strategy_recommended_dict > 0, "dict,", "") AS s_recommended_dict,
	  AVG(crash_count) OVER() as avg_cc,
	  AVG(new_edges) OVER() as avg_ne,
	  AVG(new_features) OVER() as avg_nf,
	  AVG(new_units_added) OVER() as avg_nu,
	  STDDEV(crash_count) OVER() as stddev_cc,
	  STDDEV(new_edges) OVER() as stddev_ne,
	  STDDEV(new_features) OVER() as stddev_nf,
	  STDDEV(new_units_added) OVER() as stddev_nu,
	  crash_count, new_edges, new_features, new_units_added
    FROM
	  libFuzzer_stats.TestcaseRun
	WHERE
	  ((strategy_mutator_plugin = 0) OR (strategy_mutator_plugin IS NULL)) AND
	  DATE_DIFF(cast(current_timestamp() AS DATE), cast(_PARTITIONTIME AS DATE), DAY) < 31 AND
	  ((strategy_corpus_mutations = 0) OR (strategy_corpus_mutations IS NULL)) AND
	  ((strategy_handle_unstable = 0) OR (strategy_handle_unstable IS NULL)) AND
	  ((strategy_weighted_mutations = 0) OR (strategy_weighted_mutations IS NULL)))
	GROUP BY
	  strategy)
"""


def query_libfuzzer_stats(client):
  """Get query results"""
  return client.query(query=MULTIPLE_STRATEGY_PROBABILITY_QUERY)


def upload_bandit_weights(client):
  """Upload query results to datastore to use as new probabilities
  currently using edges as bandit metric, can change below by selecting
  a bandit field for one of the other metrics (features, units, crash)"""
  strategy_data = []
  data = query_libfuzzer_stats(client)
  # get query results
  curr_strategy = data_types.BanditProbabilities()
  for row in data:
    curr_strategy.strategy_name = str(row['strategy'])
    curr_strategy.strategy_count = int(row['strategy_count'])
    curr_strategy.strategy_bandit_probability = float(row['edges_bandit'])
    strategy_data.append(curr_strategy)
  ndb.put_multi(strategy_data)


class Handler(base_handler.Handler):
  """Handler to periodically update fuzz strategy bandit probabilities
   based on performance metric (currently based on new_edges)."""

  @handler.check_cron()
  def get(self):
    """Process all fuzz targets and update FuzzTargetJob weights."""
    client = big_query.Client()
    upload_bandit_weights(client)
