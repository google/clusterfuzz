# Copyright 2020 Google Inc.
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
#
################################################################################
"""libFuzzer Neural Smoothing - Globals."""

__author__ = 'Ryan Cao (ryancao@google.com)'

import tensorflow.keras as keras
from bot.fuzzers.ml.gradientfuzz import models
from datetime import datetime
import enum


class ModelTypes(enum.Enum):
  """
  To classify model types.
  """
  FEEDFORWARD = enum.auto()
  RNN = enum.auto()


class ExitCodes(enum.Enum):
  """
  For ClusterFuzz.
  """
  SUCCESS = enum.auto()


# For main directory tree.
MODEL_DIR = 'models'
DATASET_DIR = 'data'
GENERATED_DIR = 'generated'
REQUIRED_DIRS = [MODEL_DIR, DATASET_DIR, GENERATED_DIR]

# Filenames + Extensions (under DATASET_DIR/[dataset_name]/).
STANDARD_INPUT_DIR = 'inputs'
STANDARD_LABEL_DIR = 'labels'
INPUT_FILENAME = 'input-{num:06d}.npy'
LABEL_FILENAME = 'label-{num:06d}.npy'
INPUT_LENGTHS_FILENAME = 'input_lengths.json'
RAW_INPUT_FILE_NAMES_FILENAME = 'input_file_names.json'
BRANCH_LABELS_FILENAME = 'branches.json'
BRANCH_COVERAGE_PLOT_FILENAME = 'branch_coverage_dist_plot.png'
INPUT_LENGTH_PLOT_FILENAME = 'input_lengths_dist_plot.png'

# Filenames + Extensions (under MODEL_DIR/[run_name]/).
TENSORBOARD_DIR = 'tensorboard'
CONFIG_FILENAME = 'config.json'
CHECKPOINT_HEADER = 'cp-epoch-'
CHECKPOINT_FILENAME = 'cp-epoch-{epoch:04d}'
CP_EPOCH_NUM_DIGITS = 5

# Filenames + Extensions (under GENERATED_DIR/[generation_name]/).
GRADIENTS_DIR = 'gradients'
MUTATIONS_DIR = 'mutations'

# Model architecture constants.
NEUZZ_ONE_HIDDEN_LAYER_MODEL = 'neuzz_one_hidden'
NEUZZ_THREE_HIDDEN_LAYER_MODEL = 'neuzz_three_hidden'
LSTM_MODEL = 'rnn_lstm'
GRU_MODEL = 'rnn_gru'
ARCHITECTURE_MAP = {
    NEUZZ_ONE_HIDDEN_LAYER_MODEL: models.NEUZZModelOneHidden,
    NEUZZ_THREE_HIDDEN_LAYER_MODEL: models.NEUZZModelThreeHidden,
    LSTM_MODEL: models.SimpleLSTMModel,
    GRU_MODEL: models.SimpleGRUModel
}

MODEL_TYPE_MAP = {
    NEUZZ_ONE_HIDDEN_LAYER_MODEL: ModelTypes.FEEDFORWARD,
    NEUZZ_THREE_HIDDEN_LAYER_MODEL: ModelTypes.FEEDFORWARD,
    LSTM_MODEL: ModelTypes.RNN,
    GRU_MODEL: ModelTypes.RNN,
}

# Optimizer constants.
RMSPROP = 'RMSProp'
ADAM = 'Adam'
SGD = 'SGD'
OPTIMIZER_MAP = {
    RMSPROP: keras.optimizers.RMSprop,
    ADAM: keras.optimizers.Adam,
    SGD: keras.optimizers.SGD
}

# Training defaults. (See get_train_opts() in opts.py)
DEFAULT_LR = 3e-4
DEFAULT_TRAIN_BATCH_SIZE = 16
DEFAULT_VAL_BATCH_SIZE = 32
DEFAULT_OPTIMIZER = ADAM
DEFAULT_VAL_SPLIT = 0.2
DEFAULT_NUM_EPOCHS = 50
DEFAULT_HIDDEN_SIZE = 256


# Utility function defaults.
def default_run_name():
  now = datetime.now()
  return ('run_on_' + now.strftime('%m-%d-%y') +
          '_at_' + now.strftime('%H:%M:%S'))


# NEUZZ configuration constants.
def populate_with_neuzz(config):
  """
  From
  https://github.com/Dongdongshe/neuzz/blob/2c7179557a491266ca1478e5f8c431d0b69d3e3a/nn.py.

  The values given below are exactly those found in the original
  NEUZZ repository. Line numbers reference `nn.py` in the above link.
  """

  config['architecture'] = NEUZZ_ONE_HIDDEN_LAYER_MODEL

  # Line 353.
  config['lr'] = 1e-4

  # Line 345.
  config['epochs'] = 50

  # Line 353.
  config['optimizer'] = ADAM

  # Line 343.
  config['batch_size'] = 32


# Data processing (see libfuzzer_to_numpy.py).
COVERAGE_MARKER = 'FULL COVERAGE:\n'
PRINT_COV_FLAG = '-print_full_coverage=1'
RUNS_FLAG = '-runs=0'
COVERED = 'C'

# Data analysis (count_prop_covered_branches.py/plot_dataset_lengths.py).
HIST_NUM_BINS_COVERAGE = 40
HIST_NUM_BINS_INPUT_LEN = 40
HIST_COVERAGE_X_TITLE = 'Percentage of Branches Covered'
HIST_COVERAGE_Y_TITLE = 'Number of Input Files'
HIST_INPUT_LEN_X_TITLE = 'Input Length (Bytes)'
HIST_INPUT_LEN_Y_TITLE = 'Number of Input Files'

# Gradient generation (see gen_gradients.py).
METADATA_FILENAME = 'metadata.json'
NEUZZ_RANDOM_BRANCHES = 'neuzz_random_branches'
GRADIENT_OPTS = [NEUZZ_RANDOM_BRANCHES]

# Mutation generation opts (see get_gen_mutations_opts() in opts.py).
NEUZZ_MUTATION = 'neuzz_mutation'
SIMPLE_RANDOM = 'simple_random'
LIMITED_NEIGHBORHOOD = 'limited_neighborhood'
MUTATION_OPTS = [NEUZZ_MUTATION, SIMPLE_RANDOM, LIMITED_NEIGHBORHOOD]
NEUZZ_NUM_MUT_RANGES = 2  # TODO(ryancao): THIS IS SET TO 14 IN NEUZZ
NEUZZ_MUT_IDX_RANGES = [2**x for x in range(NEUZZ_NUM_MUT_RANGES)]
DEFAULT_NUM_MUTATIONS = 10
NEIGHBORHOOD_DEFAULT_MAX_WIDTH = 5
# Source:
# https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html
# (See "Simple arithmetics" section)
ARITH_DEFAULT_MIN = -35
ARITH_DEFAULT_MAX = 35

# Mutation generation (see gen_mutations.py).
MAX_BYTE_VAL = 255
MIN_BYTE_VAL = 0
PLUS_MUTATION_PREFIX = ('plus-mutation-branch-{branch_idx:03d}-' +
                        'range-{start:04d}-num-{num:04d}-')
MINUS_MUTATION_PREFIX = ('minus-mutation-branch-{branch_idx:03d}-' +
                         'range-{start:04d}-num-{num:04d}-')
GENERIC_MUTATION_PREFIX = 'mutation-branch-{branch_idx:03d}-num-{num:04d}-'
ORIGINAL_PREFIX = 'original-'
