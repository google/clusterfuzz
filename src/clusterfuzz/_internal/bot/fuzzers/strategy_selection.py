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
"""Generate strategy pool for launcher based on strategy probabilities.

Decides the set strategies to be considered by the launcher. Note
that because of compatibility issues, the exact set of strategies
generated here may be modified in the launcher before being launched."""

from collections import namedtuple

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.fuzzing import strategy
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

GENERATORS = [
    strategy.CORPUS_MUTATION_RADAMSA_STRATEGY,
    strategy.CORPUS_MUTATION_ML_RNN_STRATEGY,
]

StrategyCombination = namedtuple('StrategyCombination',
                                 'strategy_name probability')


class StrategyPool(object):
  """Object used to keep track of which strategies the launcher should attempt
  to enable."""

  def __init__(self):
    """Empty set representing empty strategy pool."""
    self.strategy_names = set()

  def add_strategy(self, strategy_tuple):
    """Add a strategy into our existing strategy pool unless it is disabled."""
    if strategy_tuple.name not in environment.get_value('DISABLED_STRATEGIES',
                                                        '').split(','):
      self.strategy_names.add(strategy_tuple.name)

  def do_strategy(self, strategy_tuple):
    """Boolean value representing whether or not a strategy is in our strategy
    pool."""
    return strategy_tuple.name in self.strategy_names


def choose_generator(strategy_pool):
  """Chooses whether to use radamsa, ml rnn, or no generator and updates the
  strategy pool."""

  radamsa_prob = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name,
      default=strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.probability)

  ml_rnn_prob = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name,
      default=strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.probability)

  if engine_common.decide_with_probability(radamsa_prob + ml_rnn_prob):
    if engine_common.decide_with_probability(
        radamsa_prob / (radamsa_prob + ml_rnn_prob)):
      strategy_pool.add_strategy(strategy.CORPUS_MUTATION_RADAMSA_STRATEGY)
    else:
      strategy_pool.add_strategy(strategy.CORPUS_MUTATION_ML_RNN_STRATEGY)


def do_strategy(strategy_tuple):
  """Return whether or not to use a given strategy."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(strategy_tuple.name,
                                             strategy_tuple.probability))


def generate_default_strategy_pool(strategy_list, use_generator):
  """Return a strategy pool representing a selection of strategies for launcher
  to consider.

  Select strategies according to default strategy selection method."""
  pool = StrategyPool()

  # If use_generator is enabled, decide whether to include radamsa, ml rnn,
  # or no generator (mutually exclusive).
  if use_generator:
    choose_generator(pool)

  # Decide whether or not to add non-generator strategies according to
  # probability parameters.
  for value in [
      strategy_entry for strategy_entry in strategy_list
      if strategy_entry not in GENERATORS
  ]:
    if do_strategy(value):
      pool.add_strategy(value)

  logs.log('Strategy pool was generated according to default parameters. '
           'Chosen strategies: ' + ', '.join(pool.strategy_names))
  return pool


def generate_weighted_strategy_pool(strategy_list, use_generator, engine_name):
  """Generate a strategy pool based on probability distribution from multi armed
  bandit experimentation."""

  # If weighted strategy selection is enabled, there will be a distribution
  # stored in the environment.
  distribution = environment.get_value('STRATEGY_SELECTION_DISTRIBUTION')
  selection_method = environment.get_value(
      'STRATEGY_SELECTION_METHOD', default_value='default')

  # Otherwise if weighted strategy selection is not enabled (strategy selection
  # method is default) or if we cannot query properly, generate strategy
  # pool according to default parameters. We pass the combined list of
  # multi-armed bandit strategies and manual strategies for consideration in
  # the default strategy selection process.
  if not distribution or selection_method == 'default':
    return generate_default_strategy_pool(strategy_list, use_generator)

  # Change the distribution to a list of named tuples rather than a list of
  # dictionaries so that we can use the random_weighted_choice function. Filter
  # out probability entries from other engines.
  distribution_tuples = [
      StrategyCombination(
          strategy_name=elem['strategy_name'], probability=elem['probability'])
      for elem in distribution
      if elem['engine'] == engine_name
  ]

  if not distribution_tuples:
    logs.log_warn('Tried to generate a weighted strategy pool, but do not have '
                  'strategy probabilities for %s fuzzing engine.' % engine_name)
    return generate_default_strategy_pool(strategy_list, use_generator)

  strategy_selection = utils.random_weighted_choice(distribution_tuples,
                                                    'probability')
  strategy_name = strategy_selection.strategy_name

  chosen_strategies = strategy_name.split(',')
  pool = StrategyPool()

  for strategy_tuple in strategy_list:
    if strategy_tuple.name in chosen_strategies:
      pool.add_strategy(strategy_tuple)

  # We consider certain strategies separately as those are only supported by a
  # small number of fuzz targets and should be used heavily when available.
  for value in [
      strategy_entry for strategy_entry in strategy_list
      if strategy_entry.manually_enable
  ]:
    if do_strategy(value):
      pool.add_strategy(value)

  logs.log('Strategy pool was generated according to weighted distribution. '
           'Chosen strategies: ' + ', '.join(pool.strategy_names))
  return pool
