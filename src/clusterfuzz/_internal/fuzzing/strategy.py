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

from collections import namedtuple

# Named tuple for each strategy. The manually_enable field signifies whether a
# given strategy should be considered separately from the multi-armed bandit
# strategy seleciton process. Strategies with this field enabled are not
# included in the multi-armed bandit cron job query.
Strategy = namedtuple('Strategy', 'name probability manually_enable')

# Number of testcases to use for the corpus subset strategy.
# See https://crbug.com/682311 for more information.
# Size 100 has a slightly higher chance as it seems to be the best one so far.
CORPUS_SUBSET_NUM_TESTCASES = [10, 20, 50, 75, 75, 100, 100, 100, 125, 125, 150]

# Supported fuzzing strategies.
CORPUS_MUTATION_RADAMSA_STRATEGY = Strategy(
    name='corpus_mutations_radamsa', probability=0.15, manually_enable=False)
CORPUS_SUBSET_STRATEGY = Strategy(
    name='corpus_subset', probability=0.50, manually_enable=True)
FORK_STRATEGY = Strategy(name='fork', probability=0.50, manually_enable=False)
RANDOM_MAX_LENGTH_STRATEGY = Strategy(
    name='random_max_len', probability=0.15, manually_enable=False)
VALUE_PROFILE_STRATEGY = Strategy(
    name='value_profile', probability=0.33, manually_enable=False)
USE_EXTRA_SANITIZERS_STRATEGY = Strategy(
    name='extra_sanitizers', probability=0.10, manually_enable=False)

# Keep this strategy order for strategy combination tracking as strategy
# combinations are tracked as strings.
LIBFUZZER_STRATEGY_LIST = [
    CORPUS_MUTATION_RADAMSA_STRATEGY,
    RANDOM_MAX_LENGTH_STRATEGY,
    VALUE_PROFILE_STRATEGY,
    FORK_STRATEGY,
    CORPUS_SUBSET_STRATEGY,
    USE_EXTRA_SANITIZERS_STRATEGY,
]

AFL_STRATEGY_LIST = [
    CORPUS_MUTATION_RADAMSA_STRATEGY,
    CORPUS_SUBSET_STRATEGY,
]

# Lists of prefix and boolean strategies maintained for libFuzzer stats.
LIBFUZZER_STRATEGIES_WITH_PREFIX_VALUE = [
    CORPUS_SUBSET_STRATEGY,
    FORK_STRATEGY,
]

LIBFUZZER_STRATEGIES_WITH_PREFIX_VALUE_TYPE = {
    'corpus_subset': int,
    'fork': int,
}

LIBFUZZER_STRATEGIES_WITH_BOOLEAN_VALUE = [
    CORPUS_MUTATION_RADAMSA_STRATEGY,
    RANDOM_MAX_LENGTH_STRATEGY,
    VALUE_PROFILE_STRATEGY,
    USE_EXTRA_SANITIZERS_STRATEGY,
]

# To ensure that all strategies present in |strategy_list| are parsed for stats.
assert (set(LIBFUZZER_STRATEGY_LIST) ==
        set(LIBFUZZER_STRATEGIES_WITH_PREFIX_VALUE +
            LIBFUZZER_STRATEGIES_WITH_BOOLEAN_VALUE))
