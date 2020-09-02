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
"""libFuzzer Neural Smoothing - Dataset Objects."""

import glob
import os

from natsort import natsorted
import numpy as np
import tensorflow.keras as keras

import bot.fuzzers.ml.gradientfuzz.constants as constants


class ProgramDataset(keras.utils.Sequence):
  """
    Simple Sequence object usable alongside keras.Model.

    Takes a list of input and label filepaths (order MUST match!)
    and loads .npy files on the fly (preventing OOM errors on GPU
    from loading entire dataset as a single Numpy array).
    """

  def __init__(self, input_file_paths, label_file_paths, batch_size,
               is_rnn_dataset):
    """
      ProgramDataset loads inputs from saved .npy files on the fly.
      """
    self._input_file_paths = input_file_paths
    self._label_file_paths = label_file_paths
    self._batch_size = batch_size
    self._is_rnn_dataset = is_rnn_dataset
    assert len(self._input_file_paths) == len(self._label_file_paths)

  def __len__(self):
    return int(np.floor(len(self._input_file_paths) / self._batch_size))

  def __getitem__(self, idx):
    batch_x_paths = self._input_file_paths[idx * self._batch_size:(idx + 1) *
                                           self._batch_size]
    batch_x = np.stack([np.load(file_name) for file_name in batch_x_paths])
    batch_y_paths = self._label_file_paths[idx * self._batch_size:(idx + 1) *
                                           self._batch_size]
    batch_y = np.stack([np.load(file_name) for file_name in batch_y_paths])

    # RNN data shape is (B, T, D) -- batch_sz, timesteps, data_dim
    if self._is_rnn_dataset:
      batch_x = np.expand_dims(batch_x, -1)

    return (batch_x, batch_y)

  def get_input_shape(self):
    """
      N.B. Assumes all inputs are the same shape!
      """
    sample_in = np.load(self._input_file_paths[0])
    if self._is_rnn_dataset:
      return np.expand_dims(sample_in, -1).shape

    return sample_in.shape

  def get_output_dim(self):
    """
      N.B. Assumes labels are 1-dimensional!
      """
    return np.load(self._label_file_paths[0]).shape[0]


def get_dataset_from(config):
  """
    Dataset format: two separate numpy files.
    x -- np.ndarray(num_seeds, max_seed_len)
    y -- np.ndarray(num_seeds, num_program_branches)

    Args:
        config (dict): Run configuration dictionary (usually from
            parser.parse_args()).

    Returns:
        train_dataset (ProgramDataset): As specified by config['dataset_name'].
        val_dataset (ProgramDataset): As specified by config['dataset_name'],
            if 0 < config['val_split'] < 1, else None.
    """

  # Grabs saved NumPy files.
  dataset_path = os.path.join(constants.DATASET_DIR, config['dataset_name'])

  if not os.path.isdir(dataset_path):
    print('Error: Dataset directory {} does not exist.'.format(dataset_path))
    return None

  train_dataset, val_dataset = None, None

  # Sorted for consistency in train/val split when re-loading datasets.
  input_file_paths = natsorted(
      list(
          glob.glob(
              os.path.join(dataset_path, constants.STANDARD_INPUT_DIR, '*'))))
  label_file_paths = natsorted(
      list(
          glob.glob(
              os.path.join(dataset_path, constants.STANDARD_LABEL_DIR, '*'))))

  # Check if we need an RNN dataset
  is_rnn_dataset = constants.MODEL_TYPE_MAP[config[
      'architecture']] == constants.ModelTypes.RNN

  # Perform val split if specified.
  val_split = config['val_split']
  if 0 < val_split < 1:
    print('Splitting data into {}/{} train/val.'.format(1 - val_split,
                                                        val_split))
    split_idx = int(np.floor(len(input_file_paths) * val_split))
    train_input_file_paths = input_file_paths[split_idx:]
    train_label_file_paths = label_file_paths[split_idx:]
    val_input_file_paths = input_file_paths[:split_idx]
    val_label_file_paths = label_file_paths[:split_idx]
    train_dataset = ProgramDataset(train_input_file_paths,
                                   train_label_file_paths, config['batch_size'],
                                   is_rnn_dataset)
    val_dataset = ProgramDataset(val_input_file_paths, val_label_file_paths,
                                 config['batch_size'], is_rnn_dataset)
  else:
    print('Not using a validation set!')
    train_dataset = ProgramDataset(input_file_paths, label_file_paths,
                                   config['batch_size'], is_rnn_dataset)

  # Populate config with dataset input/output shapes.
  config['input_shape'] = train_dataset.get_input_shape()
  config['output_dim'] = train_dataset.get_output_dim()

  return train_dataset, val_dataset
