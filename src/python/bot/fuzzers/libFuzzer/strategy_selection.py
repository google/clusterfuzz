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
that because of compatability issues, the exact set of strategies
generated here may be modified in the launcher before being launched."""

from bot.fuzzers import engine_common
from bot.fuzzers import strategy


def choose_generator():
  """Return whether to use radamsa, ml rnn, or no generator."""

  radamsa_prob = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name,
      default=strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.probability)

  ml_rnn_prob = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name,
      default=strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.probability)

  generators = {}

  if engine_common.decide_with_probability(radamsa_prob + ml_rnn_prob):
    generators[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name] = (
        engine_common.decide_with_probability(
            radamsa_prob / (radamsa_prob + ml_rnn_prob)))
    generators[strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name] = (
        not generators[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name])
  else:
    generators[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY.name] = False
    generators[strategy.CORPUS_MUTATION_ML_RNN_STRATEGY.name] = False
  return generators


def do_strategy(strategy_name, default_probability):
  """Return whether or not to use a given strategy."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy_name, default=default_probability))


def generate_strategy_pool():
  """Return dictionary representing a random selection of strategies
  for launcher to consider."""
  strategy_pool = {}

  # Decide whether or not to include radamsa, ml rnn, or no generator
  strategy_pool.update(choose_generator())

  # Decide whether or not to include remaining strategies
  strategy_pool[
      strategy.CORPUS_SUBSET_STRATEGY.name] = engine_common.do_corpus_subset()
  strategy_pool[strategy.RANDOM_MAX_LENGTH_STRATEGY.name] = do_strategy(
      strategy.RANDOM_MAX_LENGTH_STRATEGY.name,
      strategy.RANDOM_MAX_LENGTH_STRATEGY.probability)
  strategy_pool[strategy.RECOMMENDED_DICTIONARY_STRATEGY.name] = do_strategy(
      strategy.RECOMMENDED_DICTIONARY_STRATEGY.name,
      strategy.RECOMMENDED_DICTIONARY_STRATEGY.probability)
  strategy_pool[strategy.VALUE_PROFILE_STRATEGY.name] = do_strategy(
      strategy.VALUE_PROFILE_STRATEGY.name,
      strategy.VALUE_PROFILE_STRATEGY.probability)
  strategy_pool[strategy.FORK_STRATEGY.name] = do_strategy(
      strategy.FORK_STRATEGY.name, strategy.FORK_STRATEGY.probability)
  strategy_pool[strategy.MUTATOR_PLUGIN_STRATEGY.name] = do_strategy(
      strategy.MUTATOR_PLUGIN_STRATEGY.name,
      strategy.MUTATOR_PLUGIN_STRATEGY.probability)

  return strategy_pool
