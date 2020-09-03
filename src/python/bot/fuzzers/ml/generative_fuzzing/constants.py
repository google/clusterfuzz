# Copyright 2020 Google LLC
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
"""Constants for ML models."""

from builtins import object

# Default embedding dimension.
EMBEDDING_DIM = 256
MASK_EMBEDDING_DIM = 257

# Default d_model for GPT model.
DEFAULT_GPT_D_MODEL = 512

# Default d_model for BERT model.
DEFAULT_BERT_D_MODEL = 512

# Default number of heads for GPT model.
DEFAULT_GPT_NUM_HEADS = 8

# Default number of heads for BERT model.
DEFAULT_BERT_NUM_HEADS = 8

# Mask value in BERT model is 256.
BERT_MASK_VALUE = 256
MASK_VALUE = 256

# Size of the alphabet in BERT model.
# Since there is a [mask] character, the size is 257.
BERT_ALPHA_SIZE = 257

# Size of the alphabet including MASK token.
MASK_ALPHA_SIZE = 257

# Size of the alphabet that we work with.
ALPHA_SIZE = 256

# Display training progress for every 50 batches.
DISPLAY_FREQ = 50

# Length of progress bar.
DISPLAY_LEN = 70

# VAE model relevant parameters.
VAE_ENCODER_LAYER_1_DIM = 128
VAE_ENCODER_LAYER_2_DIM = 10
VAE_DECODER_LAYER_1_DIM = 128

# Default max length of file is 100K.
DEFAULT_MAX_LENGTH = 100000

class ExitCode(object):
    """Exit code for training and generation."""
    SUCCESS = 0
    INVALID_PATH = 1
    CORPUS_TOO_SMALL = 2
    TENSORFLOW_ERROR = 3
