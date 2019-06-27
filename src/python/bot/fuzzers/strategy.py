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
"""Fuzzing strategies for fuzzing engines like libFuzzer, AFL, etc."""

# Number of testcases to use for the corpus subset strategy.
# See https://crbug.com/682311 for more information.
# Size 100 has a slightly higher chance as it seems to be the best one so far.
from collections import namedtuple

Strategy = namedtuple('Strategy', 'name probability')
CORPUS_SUBSET_NUM_TESTCASES = [10, 20, 50, 75, 75, 100, 100, 100, 125, 125, 150]

# Supported fuzzing strategies.
CORPUS_MUTATION_RADAMSA_STRATEGY = Strategy(
    name='corpus_mutations_radamsa', probability=0.15)
CORPUS_MUTATION_ML_RNN_STRATEGY = Strategy(
    name='corpus_mutations_ml_rnn', probability=0.50)
DATAFLOW_TRACING_STRATEGY = Strategy(name='dataflow_tracing', probability=0.25)
CORPUS_SUBSET_STRATEGY = Strategy(name='corpus_subset', probability=0.50)
FORK_STRATEGY = Strategy(name='fork', probability=0.50)
MUTATOR_PLUGIN_STRATEGY = Strategy(name='mutator_plugin', probability=0.50)
RANDOM_MAX_LENGTH_STRATEGY = Strategy(name='random_max_len', probability=0.15)
RECOMMENDED_DICTIONARY_STRATEGY = Strategy(
    name='recommended_dict', probability=0.10)
VALUE_PROFILE_STRATEGY = Strategy(name='value_profile', probability=0.33)

strategy_list = [
    CORPUS_MUTATION_RADAMSA_STRATEGY, CORPUS_MUTATION_ML_RNN_STRATEGY,
    DATAFLOW_TRACING_STRATEGY, CORPUS_SUBSET_STRATEGY, FORK_STRATEGY,
    MUTATOR_PLUGIN_STRATEGY, RANDOM_MAX_LENGTH_STRATEGY,
    RECOMMENDED_DICTIONARY_STRATEGY, VALUE_PROFILE_STRATEGY
]

strategies_with_prefix_value = [
    CORPUS_SUBSET_STRATEGY,
    FORK_STRATEGY,
]

strategies_with_boolean_value = [
    CORPUS_MUTATION_RADAMSA_STRATEGY,
    CORPUS_MUTATION_ML_RNN_STRATEGY,
    DATAFLOW_TRACING_STRATEGY,
    MUTATOR_PLUGIN_STRATEGY,
    RANDOM_MAX_LENGTH_STRATEGY,
    RECOMMENDED_DICTIONARY_STRATEGY,
    VALUE_PROFILE_STRATEGY,
]

# To ensure that all strategies present in |strategy_list| are parsed for stats.
assert (set(strategy_list) == set(strategies_with_prefix_value +
                                  strategies_with_boolean_value))
