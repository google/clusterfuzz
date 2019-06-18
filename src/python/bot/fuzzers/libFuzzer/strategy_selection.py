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

# Probability of using `-max_len` option. Not applicable if already declared in
# .options file.
RANDOM_MAX_LENGTH_PROBABILITY = 0.15

# Probability of doing ML RNN mutations on the corpus in this run.
CORPUS_MUTATION_ML_RNN_PROBABILITY = 0.50

# Probability of doing radamsa mutations on the corpus in this run.
CORPUS_MUTATION_RADAMSA_PROBABILITY = 0.15

# Number of radamsa mutations.
RADAMSA_MUTATIONS = 2000

# Maximum number of seconds to run radamsa for.
RADAMSA_TIMEOUT = 3

# Probability of recommended dictionary usage.
RECOMMENDED_DICTIONARY_PROBABILITY = 0.10

# Probability of using `-use_value_profile=1` option.
VALUE_PROFILE_PROBABILITY = 0.33

FORK_PROBABILITY = 0.50

MUTATOR_PLUGIN_PROBABILITY = 0.50


def do_random_max_length():
  """Return whether or not to do value profile."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.RANDOM_MAX_LENGTH_STRATEGY,
          default=RANDOM_MAX_LENGTH_PROBABILITY))


def use_generator():
  """Return whether to use a generator or not."""
  radamsa_p = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_RADAMSA_STRATEGY,
      default=CORPUS_MUTATION_RADAMSA_PROBABILITY)
  ml_rnn_p = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_ML_RNN_STRATEGY,
      default=CORPUS_MUTATION_ML_RNN_PROBABILITY)
  return engine_common.decide_with_probability(radamsa_p + ml_rnn_p)


def do_radamsa_or_ml_rnn_generator():
  """Return whether to use radamsa or ml rnn generator.

  True for radamsa, false for ml rnn."""
  radamsa_p = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_RADAMSA_STRATEGY,
      default=CORPUS_MUTATION_RADAMSA_PROBABILITY)
  ml_rnn_p = engine_common.get_strategy_probability(
      strategy.CORPUS_MUTATION_ML_RNN_STRATEGY,
      default=CORPUS_MUTATION_ML_RNN_PROBABILITY)
  return engine_common.decide_with_probability(
      radamsa_p / (radamsa_p + ml_rnn_p))


def do_recommended_dictionary():
  """Return whether or not to use the recommended dictionary."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.RECOMMENDED_DICTIONARY_STRATEGY,
          default=RECOMMENDED_DICTIONARY_PROBABILITY))


def do_value_profile():
  """Return whether or not to do value profile."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.VALUE_PROFILE_STRATEGY, default=VALUE_PROFILE_PROBABILITY))


def do_fork():
  """Return whether or not to do fork mode."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.FORK_STRATEGY, default=FORK_PROBABILITY))


def do_mutator_plugin():
  """Return whether or not to use a mutator_plugin."""
  return engine_common.decide_with_probability(
      engine_common.get_strategy_probability(
          strategy.MUTATOR_PLUGIN_STRATEGY, default=MUTATOR_PLUGIN_PROBABILITY))


def generate_strategy_pool():
  """Return dictionary representing a random selection of strategies
  for launcher to consider."""
  strategy_pool = {}

  # Decide whether or not to include radamsa, ml rnn, or no generator
  if use_generator():
    strategy_pool[
        strategy.
        CORPUS_MUTATION_RADAMSA_STRATEGY] = do_radamsa_or_ml_rnn_generator()
    strategy_pool[
        strategy.CORPUS_MUTATION_ML_RNN_STRATEGY] = not \
            strategy_pool[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY]
  else:
    strategy_pool[strategy.CORPUS_MUTATION_RADAMSA_STRATEGY] = False
    strategy_pool[strategy.CORPUS_MUTATION_ML_RNN_STRATEGY] = False

  # Decide whether or not to include remaining strategies
  strategy_pool[
      strategy.CORPUS_SUBSET_STRATEGY] = engine_common.do_corpus_subset()
  strategy_pool[strategy.RANDOM_MAX_LENGTH_STRATEGY] = do_random_max_length()
  strategy_pool[
      strategy.RECOMMENDED_DICTIONARY_STRATEGY] = do_recommended_dictionary()
  strategy_pool[strategy.VALUE_PROFILE_STRATEGY] = do_value_profile()
  strategy_pool[strategy.FORK_STRATEGY] = do_fork()
  strategy_pool[strategy.MUTATOR_PLUGIN_STRATEGY] = do_mutator_plugin()

  return strategy_pool
