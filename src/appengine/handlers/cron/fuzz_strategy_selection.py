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

from bot.fuzzers import strategy
from datastore import data_types
from datastore import ndb
from datastore import ndb_utils
from google_cloud_utils import big_query
from handlers import base_handler
from libs import handler
from metrics import logs

HIGH_TEMPERATURE_PARAMETER = .5
MEDIUM_TEMPERATURE_PARAMETER = .25
LOW_TEMPERATURE_PARAMETER = .15

# A list of tuples of engine names and associated strategies to include in
# query.
ENGINE_LIST = [('libFuzzer', strategy.libfuzzer_query_strategy_list),
               ('afl', strategy.afl_query_strategy_list)]

# BigQuery query for calculating multi-armed bandit probabilities for
# various strategies using a Boltzman Exploration (softmax) model.

# Averages standardized new_edges feature over each strategy for expected
# new_edges metric for each strategy.
# See https://www.cs.mcgill.ca/~vkules/bandits.pdf for formula.

# TODO(mukundv): Change query once we decide on a temperature parameter and
# final implementation.

BANDIT_PROBABILITY_QUERY = """
SELECT
  a.strategy AS strategy,
  bandit_weight_high_temperature,
  bandit_weight_low_temperature,
  bandit_weight_medium_temperature,
  a.run_count + b.run_count + c.run_count as run_count 
FROM {high_temperature_query} a
JOIN {low_temperature_query} b ON a.strategy = b.strategy
JOIN {medium_temperature_query} c ON a.strategy = c.strategy
"""

BANDIT_PROBABILITY_SUBQUERY = """
(SELECT
    /* Calculate bandit weights from calculated exponential values. */
    strategy,
    strategy_exp / exp_sum AS bandit_weight_{temperature_type}_temperature,
    run_count,
    strategy_selection_method
  FROM (
    SELECT
      EXP(strategy_avg_edges / temperature) AS strategy_exp,
      SUM(EXP(strategy_avg_edges / temperature)) OVER() AS exp_sum,
      strategy,
      run_count,
      strategy_selection_method
    FROM (
      SELECT
        /* Standardize the new edges data and take averages per strategy. */
        AVG((new_edges - overall_avg_new_edges) / overall_stddev_new_edges) AS strategy_avg_edges,
        strategy,
        /* Change temperature parameter here. */
        {temperature_value} AS temperature,
        COUNT(*) AS run_count,
        "multi_armed_bandit_{temperature_type}" AS strategy_selection_method
      FROM (
        SELECT
          fuzzer,
          CONCAT({strategies}) AS strategy,
          fuzzer_stddev,
          AVG(new_edges) OVER() AS overall_avg_new_edges,
          STDDEV(new_edges) OVER() AS overall_stddev_new_edges,
          new_edges,
          strategy_selection_method
        FROM (
          SELECT
            fuzzer,
            {strategies_subquery}
            STDDEV(new_edges) OVER(PARTITION BY fuzzer) AS fuzzer_stddev,
            new_edges,
            strategy_selection_method
          FROM
            {engine}_stats.TestcaseRun
          WHERE
            /* Query results from the past 5 days. Change as needed. */
            DATE_DIFF(CAST(CURRENT_TIMESTAMP() AS DATE), CAST(_PARTITIONTIME AS DATE), DAY) < 6 )
        WHERE
          /* Filter for unstable targets. */
          fuzzer_stddev < 50)
      WHERE
        strategy_selection_method = "multi_armed_bandit_{temperature_type}"
      GROUP BY
        strategy)))
"""

STRATEGY_SUBQUERY = """
IF
  (strategy_{strategy_name} > 0,
    "{strategy_name},",
    "") AS strategy_{strategy_name},
"""


def _query_multi_armed_bandit_probabilities(engine_name, strategy_list):
  """Get query results.

  Queries above BANDIT_PROBABILITY_QUERY and yields results
  from bigquery. This query is sorted by strategies implemented."""
  strategy_names_list = [
      strategy_entry.name for strategy_entry in strategy_list
  ]
  strategies_subquery = '\n'.join([
      STRATEGY_SUBQUERY.format(strategy_name=strategy_name)
      for strategy_name in strategy_names_list
  ])
  client = big_query.Client()
  formatted_query = BANDIT_PROBABILITY_QUERY.format(
      high_temperature_query=BANDIT_PROBABILITY_SUBQUERY.format(
          temperature_type='high',
          temperature_value=HIGH_TEMPERATURE_PARAMETER,
          strategies=','.join([
              'strategy_' + strategy_name
              for strategy_name in strategy_names_list
          ]),
          strategies_subquery=strategies_subquery,
          engine=engine_name),
      low_temperature_query=BANDIT_PROBABILITY_SUBQUERY.format(
          temperature_type='low',
          temperature_value=LOW_TEMPERATURE_PARAMETER,
          strategies=','.join([
              'strategy_' + strategy_name
              for strategy_name in strategy_names_list
          ]),
          strategies_subquery=strategies_subquery,
          engine=engine_name),
      medium_temperature_query=BANDIT_PROBABILITY_SUBQUERY.format(
          temperature_type='medium',
          temperature_value=MEDIUM_TEMPERATURE_PARAMETER,
          strategies=','.join([
              'strategy_' + strategy_name
              for strategy_name in strategy_names_list
          ]),
          strategies_subquery=strategies_subquery,
          engine=engine_name))
  return client.query(query=formatted_query).rows


def _store_probabilities_in_bigquery(engine_name, data):
  """Update a bigquery table containing the daily updated
  probability distribution over strategies."""
  bigquery_data = []

  # TODO(mukundv): Update once we choose a temperature parameter for final
  # implementation.
  for row in data:
    bigquery_row = {
        'strategy_name':
            row['strategy'],
        'probability_high_temperature':
            row['bandit_weight_high_temperature'],
        'probability_low_temperature':
            row['bandit_weight_low_temperature'],
        'probability_medium_temperature':
            row['bandit_weight_medium_temperature'],
        'run_count':
            row['run_count'],
        'engine':
            engine_name
    }
    bigquery_data.append(big_query.Insert(row=bigquery_row, insert_id=None))

  if bigquery_data:
    client = big_query.Client(
        dataset_id='main', table_id='fuzz_strategy_experiments')
    client.insert(bigquery_data)
  else:
    logs.log("No fuzz strategy distribution data was found to upload to "
             "BigQuery.")


def _query_and_upload_strategy_probabilities(engine_name, strategy_list):
  """Uploads queried data into datastore.

  Calls query functions and uploads query results
  to datastore to use as new probabilities. Probabilities
  are based on new_edges feature."""
  strategy_data = []
  data = _query_multi_armed_bandit_probabilities(engine_name, strategy_list)

  # TODO(mukundv): Update once we choose a temperature parameter for final
  # implementation.
  for row in data:
    curr_strategy = data_types.FuzzStrategyProbability()
    curr_strategy.strategy_name = str(row['strategy'])
    curr_strategy.probability_high_temperature = float(
        row['bandit_weight_high_temperature'])
    curr_strategy.probability_low_temperature = float(
        row['bandit_weight_low_temperature'])
    curr_strategy.probability_medium_temperature = float(
        row['bandit_weight_medium_temperature'])
    curr_strategy.engine = engine_name
    strategy_data.append(curr_strategy)

  ndb.delete_multi([
      entity.key for entity in ndb_utils.get_all_from_model(
          data_types.FuzzStrategyProbability)
  ])
  ndb.put_multi(strategy_data)
  _store_probabilities_in_bigquery(engine_name, data)


class Handler(base_handler.Handler):
  """Cron job handler for fuzz strategy selection.

  Handler to periodically update fuzz strategy bandit probabilities
  based on a performance metric (currently based on new_edges)."""

  @handler.check_cron()
  def get(self):
    """Process all fuzz targets and update FuzzStrategy weights."""
    for engine_name, strategy_list in ENGINE_LIST:
      _query_and_upload_strategy_probabilities(engine_name, strategy_list)
