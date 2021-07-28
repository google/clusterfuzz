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
In particular, this is a Boltzman Exploration (softmax) implementation
of multi-armed bandit experiments. Queries from bigquery to update
multi-armed bandit probability values based on the new edges for various
combined strategies. In the upload_bandit_weights function, we can change
metric to be for edges, crash, features, or units. Currently based on new
edges."""

from collections import namedtuple

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.google_cloud_utils import big_query
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler

# After experimentation with high, low, and medium temperature parameters, we
# decided on .15.
TEMPERATURE_PARAMETER = .15

# Maintain a list of strategies to include in query for each fuzzing engine.
# Keep this strategy order for strategy combination tracking as strategy
# combinations are tracked as strings.
libfuzzer_query_strategy_list = [
    strategy_tuple for strategy_tuple in strategy.LIBFUZZER_STRATEGY_LIST
    if not strategy_tuple.manually_enable
]

afl_query_strategy_list = [
    strategy_tuple for strategy_tuple in strategy.AFL_STRATEGY_LIST
    if not strategy_tuple.manually_enable
]

# A tuple of engine name and corresponding strategies to include in multi-armed
# bandit query.
Engine = namedtuple('Engine', 'name query_strategy_list performance_metric')

LIBFUZZER_ENGINE = Engine(
    name='libFuzzer',
    query_strategy_list=libfuzzer_query_strategy_list,
    performance_metric='new_edges')

AFL_ENGINE = Engine(
    name='afl',
    query_strategy_list=afl_query_strategy_list,
    performance_metric='new_units_generated')

ENGINE_LIST = [LIBFUZZER_ENGINE, AFL_ENGINE]

# BigQuery query for calculating multi-armed bandit probabilities for
# various strategies using a Boltzman Exploration (softmax) model.

# Averages standardized new_edges feature over each strategy for expected
# new_edges metric for each strategy.
# See https://www.cs.mcgill.ca/~vkules/bandits.pdf for formula.

# TODO(mukundv): Change query once we decide on a temperature parameter and
# final implementation.

BANDIT_PROBABILITY_QUERY_FORMAT = """
(SELECT
    /* Calculate bandit weights from calculated exponential values. */
    strategy,
    strategy_exp / exp_sum AS bandit_weight
  FROM (
    SELECT
      EXP(strategy_avg_{performance_metric} / temperature) AS strategy_exp,
      SUM(EXP(strategy_avg_{performance_metric} / temperature)) OVER() AS exp_sum,
      strategy
    FROM (
      SELECT
        /* Standardize the new edges data and take averages per strategy. */
        AVG(({performance_metric} - overall_avg_{performance_metric}) / overall_stddev_{performance_metric}) AS strategy_avg_{performance_metric},
        strategy,
        /* Change temperature parameter here. */
        {temperature_value} AS temperature
      FROM (
        SELECT
          fuzzer,
          CONCAT({strategies}) AS strategy,
          fuzzer_stddev,
          AVG({performance_metric}) OVER() AS overall_avg_{performance_metric},
          STDDEV({performance_metric}) OVER() AS overall_stddev_{performance_metric},
          {performance_metric},
          strategy_selection_method
        FROM (
          SELECT
            fuzzer,
            {strategies_subquery}
            STDDEV({performance_metric}) OVER(PARTITION BY fuzzer) AS fuzzer_stddev,
            {performance_metric},
            strategy_selection_method
          FROM
            {engine}_stats.TestcaseRun
          WHERE
            /* Query results from the past 5 days. Change as needed. */
            DATE_DIFF(CAST(CURRENT_TIMESTAMP() AS DATE), CAST(_PARTITIONTIME AS DATE), DAY) < 6 )
        WHERE
          /* Filter for unstable targets. */
          fuzzer_stddev < 50)
      GROUP BY
        strategy)))
"""

STRATEGY_SUBQUERY_FORMAT = """
IF
  (strategy_{strategy_name} > 0,
    "{strategy_name},",
    "") AS strategy_{strategy_name},
"""


def _query_multi_armed_bandit_probabilities(engine):
  """Get query results.

  Queries above BANDIT_PROBABILITY_QUERY and yields results
  from bigquery. This query is sorted by strategies implemented."""
  strategy_names_list = [
      strategy_entry.name for strategy_entry in engine.query_strategy_list
  ]
  strategies_subquery = '\n'.join([
      STRATEGY_SUBQUERY_FORMAT.format(strategy_name=strategy_name)
      for strategy_name in strategy_names_list
  ])
  client = big_query.Client()
  strategies = ','.join(
      ['strategy_' + strategy_name for strategy_name in strategy_names_list])
  formatted_query = BANDIT_PROBABILITY_QUERY_FORMAT.format(
      performance_metric=engine.performance_metric,
      temperature_value=TEMPERATURE_PARAMETER,
      strategies=strategies,
      strategies_subquery=strategies_subquery,
      engine=engine.name)
  return client.query(query=formatted_query).rows


def _store_probabilities_in_bigquery(engine, data):
  """Update a bigquery table containing the daily updated
  probability distribution over strategies."""
  bigquery_data = []

  # TODO(mukundv): Update once we choose a temperature parameter for final
  # implementation.
  for row in data:
    bigquery_row = {
        'strategy_name': row['strategy'],
        'probability': row['bandit_weight'],
        'engine': engine.name
    }
    bigquery_data.append(big_query.Insert(row=bigquery_row, insert_id=None))

  if bigquery_data:
    client = big_query.Client(
        dataset_id='main', table_id='fuzz_strategy_probability')
    client.insert(bigquery_data)
  else:
    logs.log('No fuzz strategy distribution data was found to upload to '
             'BigQuery.')


def _query_and_upload_strategy_probabilities(engine):
  """Uploads queried data into datastore.

  Calls query functions and uploads query results
  to datastore to use as new probabilities. Probabilities
  are based on new_edges feature."""
  strategy_data = []
  data = _query_multi_armed_bandit_probabilities(engine)
  logs.log('Queried distribution for {}.'.format(engine.name))

  # TODO(mukundv): Update once we choose a temperature parameter for final
  # implementation.
  for row in data:
    curr_strategy = data_types.FuzzStrategyProbability()
    curr_strategy.strategy_name = str(row['strategy'])
    curr_strategy.probability = float(row['bandit_weight'])
    curr_strategy.engine = engine.name
    strategy_data.append(curr_strategy)

  query = data_types.FuzzStrategyProbability.query(
      data_types.FuzzStrategyProbability.engine == engine.name)
  ndb_utils.delete_multi(
      [entity.key for entity in ndb_utils.get_all_from_query(query)])
  ndb_utils.put_multi(strategy_data)
  logs.log('Uploaded queried distribution to ndb for {}'.format(engine.name))
  _store_probabilities_in_bigquery(engine, data)
  logs.log('Uploaded queried distribution to BigQuery for {}'.format(
      engine.name))


class Handler(base_handler.Handler):
  """Cron job handler for fuzz strategy selection.

  Handler to periodically update fuzz strategy bandit probabilities
  based on a performance metric (currently based on new_edges)."""

  @handler.cron()
  def get(self):
    """Process all fuzz targets and update FuzzStrategy weights."""
    for engine in ENGINE_LIST:
      _query_and_upload_strategy_probabilities(engine)
