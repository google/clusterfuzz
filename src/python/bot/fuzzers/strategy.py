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
CORPUS_SUBSET_NUM_TESTCASES = [10, 20, 50, 75, 75, 100, 100, 100, 125, 125, 150]

# Supported fuzzing strategies.
CORPUS_MUTATION_RADAMSA_STRATEGY = 'corpus_mutations_radamsa'
CORPUS_MUTATION_ML_RNN_STRATEGY = 'corpus_mutations_ml_rnn'
CORPUS_SUBSET_STRATEGY = 'corpus_subset'
RANDOM_MAX_LENGTH_STRATEGY = 'random_max_len'
RECOMMENDED_DICTIONARY_STRATEGY = 'recommended_dict'
VALUE_PROFILE_STRATEGY = 'value_profile'
