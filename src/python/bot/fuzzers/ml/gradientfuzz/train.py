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
"""libFuzzer Neural Smoothing - Network Training."""

import os

import tensorflow as tf
import tensorflow.keras as keras

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.data_utils as data_utils
import bot.fuzzers.ml.gradientfuzz.model_utils as model_utils
import bot.fuzzers.ml.gradientfuzz.models as models
import bot.fuzzers.ml.gradientfuzz.opts as opts
import bot.fuzzers.ml.gradientfuzz.utils as utils


def load_existing_model_from(config):
  """
    Loads the latest version of a PREVIOUSLY compiled model from arguments.

    Args:
        config (dict): Run configuration dictionary (usually from
            parser.parse_args()).

    Returns:
        model (keras.Model): loaded model from config.
    """
  latest_filename = tf.train.latest_checkpoint(
      utils.get_full_path(config['run_name']))

  print('Loading \"{}\" model from {}...'.format(config['architecture'],
                                                 latest_filename))
  model = models.make_model_from_layer(
      constants.ARCHITECTURE_MAP[config['architecture']],
      config['output_dim'],
      config['input_shape'],
      hidden_layer_dim=config['num_hidden'])
  model.load_weights(latest_filename).expect_partial()

  # Update 'cur_epoch' in config, since training loop doesn't do it.
  config['cur_epoch'] = int(
      latest_filename[-constants.CP_EPOCH_NUM_DIGITS + 1:])
  print('Last saved epoch: {}.'.format(config['cur_epoch']))
  utils.save_model_config(config)

  # Training options.
  model.compile(
      optimizer=constants.OPTIMIZER_MAP[config['optimizer']](
          learning_rate=config['lr']),
      loss=keras.losses.BinaryCrossentropy(from_logits=False),
      metrics=[model_utils.BitmapAcc(),
               model_utils.NeuzzJaccardAcc()])

  return model


def get_new_model_from(config):
  """
    Creates and returns a NEW compiled model from arguments.
    Assumes NOT using a pre-determined config (e.g. --neuzz-config),
    and assumes the model doesn't already exist.

    Args:
        config (dict): Run configuration dictionary (usually from
            parser.parse_args()).

    Returns:
        model (keras.Model): new model constructed from config.
    """

  # Model options.
  model = models.make_model_from_layer(
      constants.ARCHITECTURE_MAP[config['architecture']],
      config['output_dim'],
      config['input_shape'],
      hidden_layer_dim=config['num_hidden'])

  # Training options.
  model.compile(
      optimizer=constants.OPTIMIZER_MAP[config['optimizer']](
          learning_rate=config['lr']),
      loss=keras.losses.BinaryCrossentropy(from_logits=False),
      metrics=[model_utils.BitmapAcc(),
               model_utils.NeuzzJaccardAcc()])

  return model


def train_model(model, config, train_dataset, val_dataset):
  """
    Constructs keras.Callbacks to save model progress and runs model.fit().

    Args:
        model (keras.Model): Model to train.
        config (dict): Configuration as constructed by `config_from_args()`
            in `utils.py`.
        train_dataset (ProgramDataset): Training set for model.
        val_dataset (ProgramDatset): Val set for model (backprop doesn't
            happen on these).

    Returns:
        tf.callbacks.History object documenting training history.
    """
  utils.save_model_config(config)
  callback_list = model_utils.get_callbacks(config)
  model.fit(
      train_dataset,
      batch_size=config['batch_size'],
      epochs=config['epochs'],
      verbose=1,
      callbacks=callback_list,
      validation_data=val_dataset,
      shuffle=True,
      initial_epoch=config['cur_epoch'],
      validation_batch_size=config['val_batch_size'],
      validation_freq=1,
      workers=os.cpu_count(),
      use_multiprocessing=False)
  return constants.ExitCodes.SUCCESS


def main():
  """
    Takes configuration as specified by arguments in `get_train_args()` in
    `opts.py` and trains a model, saving every five epochs.

    Args:
        N/A

    Returns:
        N/A (model weights saved under models/[architecture]/[run-name])
    """
  utils.make_required_dirs()
  config, new_model = utils.config_from_args(opts.get_train_args())
  utils.pretty_print(config)

  # Grab dataset and model from config.
  train_dataset, val_dataset = data_utils.get_dataset_from(config)
  if new_model:
    model = get_new_model_from(config)
  else:
    model = load_existing_model_from(config)

  model_utils.print_model_summary(model, config, config['input_shape'])
  train_model(model, config, train_dataset, val_dataset)


if __name__ == '__main__':
  main()
