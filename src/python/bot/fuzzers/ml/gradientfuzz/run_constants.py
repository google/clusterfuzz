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
"""Constants for GradientFuzz training process."""

import enum

# Script names.
GENERATE_DATA_SCRIPT = 'libfuzzer_to_numpy.py'
TRAIN_MODEL_SCRIPT = 'train.py'
GENERATE_LOCATIONS_SCRIPT = 'gradient_gen_critical_locs.py'
GENERATE_MUTATIONS_SCRIPT = 'gen_mutations.py'

# For `libfuzzer_to_numpy.py`.
INPUT_DIR_FLAG = '--input-dir'
DATASET_NAME_FLAG = '--dataset-name'
CUTOFF_PERCENTILE_FLAG = '--cutoff-percentile'
CUTOFF_STD_FLAG = '--cutoff-std'
MEDIAN_MULT_FLAG = '--median-mult-cutoff'
FUZZ_TARGET_BINARY_FLAG = '--fuzz-target-binary'

# For `train.py`.
RUN_NAME_FLAG = '--run-name'
NEUZZ_CONFIG_FLAG = '--neuzz-config'
LR_FLAG = '--lr'
EPOCHS_FLAG = '--epochs'
OPTIMIZER_FLAG = '--optimizer'
VAL_SPLIT_FLAG = '--val-split'
ARCHITECTURE_FLAG = '--architecture'
BATCH_SIZE_FLAG = '--batch-size'
VAL_BATCH_SIZE_FLAG = '--val-batch-size'
DATASET_FLAG = '--dataset'
NUM_HIDDEN_FLAG = '--num-hidden'

# For `gradient_gen_critical_locs.py`.
PATH_TO_SEEDS_FLAG = '--path-to-seeds'
PATH_TO_LENGTHS_FLAG = '--path-to-lengths'
GENERATION_NAME_FLAG = '--generation-name'
GRADIENT_GEN_METHOD_FLAG = '--gradient-gen-method'
NUM_OUTPUT_LOCS_FLAG = '--num-output-locs'
TOP_K_FLAG = '--top-k'

# For `gen_mutations.py`.
MUTATION_NAME_FLAG = '--mutation-name'
MUTATION_GEN_METHOD_FLAG = '--mutation-gen-method'
NUM_MUTATIONS_FLAG = '--num-mutations'
NEIGHBORHOOD_MAX_WIDTH_FLAG = '--neighborhood-max-width'
ARITH_MIN_FLAG = '--arith-min'
ARITH_MAX_FLAG = '--arith-max'


class ExitCode(enum.Enum):
  """Exit code for training and generation."""
  SUCCESS = enum.auto()
  INVALID_PATH = enum.auto()
  CORPUS_TOO_SMALL = enum.auto()
  TENSORFLOW_ERROR = enum.auto()
