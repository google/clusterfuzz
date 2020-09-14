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
"""libFuzzer Neural Smoothing - Training Utilities."""

import os

import tensorflow as tf
import tensorflow.keras as keras

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.utils as utils


class BitmapAcc(keras.metrics.Metric):
  """
    Counts number of matched predictions vs. gt branch coverage.

    For example:
        predicted =     [0, 0, 1, 1, 0]
        true_coverage = [0, 0, 0, 1, 1]
        all_matches =   [True, True, False, True, False]

    BitmapAcc:
        count_true(all_matches) / len(all_matches) --> 60%
    """

  def __init__(self, name='bitmap_acc', **kwargs):
    super(BitmapAcc, self).__init__(name=name, **kwargs)
    self.total_correct = self.add_weight(
        name='total_correct', initializer='zeros')
    self.total_branches = self.add_weight(
        name='total_branches', initializer='zeros')

  def update_state(self, *args, **kwargs):
    """
      Assumes y_true, y_pred are literal bitmaps of shape
          (batch_sz, num_branches).
      Computes (total matches) / (total branches).
      """
    y_true, y_pred = args
    y_pred = tf.cast(tf.round(y_pred), tf.bool)
    total_correct_branches = tf.reduce_sum(
        tf.cast(tf.equal(y_true, y_pred), tf.float32))
    total_incorrect_branches = tf.reduce_sum(
        tf.cast(tf.not_equal(y_true, y_pred), tf.float32))
    self.total_correct.assign_add(total_correct_branches)
    self.total_branches.assign_add(
        tf.add(total_correct_branches, total_incorrect_branches))

  def result(self):
    return self.total_correct / self.total_branches

  def reset_states(self):
    self.total_correct.assign(0.0)
    self.total_branches.assign(0.0)


class NeuzzJaccardAcc(keras.metrics.Metric):
  """
    Jaccard accuracy metric, following NEUZZ codebase.

    For example:
        predicted =        [0, 0, 1, 1, 0]
        true_coverage =    [0, 0, 0, 1, 1]
        positive_matches = [False, False, False, True, False]
        positive_any =     [False, False, True, True, True]

    NeuzzJaccardAcc:
        count_true(positive_matches) / count_true(positive_any) --> 33.3%
    """

  def __init__(self, name='neuzz_jaccard_acc', **kwargs):
    super(NeuzzJaccardAcc, self).__init__(name=name, **kwargs)
    self.true_positives = self.add_weight(
        name='true_positives', initializer='zeros')
    self.total_errors = self.add_weight(
        name='total_errors', initializer='zeros')

  def update_state(self, *args, **kwargs):
    """
      https://github.com/Dongdongshe/neuzz/blob/2c7179557a491266ca1478e5f8c431d0b69d3e3a/nn.py#L151.
      Computes (true positives) / (true positives + errors).
      """
    y_true, y_pred = args
    y_pred = tf.cast(tf.round(y_pred), tf.bool)
    self.true_positives.assign_add(
        tf.reduce_sum(tf.cast(tf.logical_and(y_true, y_pred), tf.float32)))
    self.total_errors.assign_add(
        tf.reduce_sum(tf.cast(tf.not_equal(y_true, y_pred), tf.float32)))

  def result(self):
    return self.true_positives / (self.true_positives + self.total_errors)

  def reset_states(self):
    self.true_positives.assign(0.0)
    self.total_errors.assign(0.0)


def compile_like_neuzz(model: keras.Model):
  """
    Uses NEUZZ hyperparams to compile model.

    Args:
        model (keras.Model): Model to be compiled.

    Returns:
        model (keras.Model): Model compiled with NEUZZ hyperparams.
    """
  optim = keras.optimizers.Adam(lr=0.0001)
  model.compile(
      loss=keras.losses.BinaryCrossentropy,
      optimizer=optim,
      metrics=[NeuzzJaccardAcc()])
  return model


def get_callbacks(config):
  """
    Creates checkpoint and TensorBoard callbacks.

    Args:
        config (dict): Config dict with args as keys
            (see `get_train_args()` in opts.py).

    Returns:
        List of keras.callbacks.Callback objects to be passed to model.fit().
    """
  model_dir_path = utils.get_full_path(config['run_name'])

  cp_callback = keras.callbacks.ModelCheckpoint(
      filepath=os.path.join(model_dir_path, constants.CHECKPOINT_FILENAME),
      monitor='val_neuzz_jaccard_acc',
      mode='max',
      save_freq='epoch',
      save_weights_only=True,
      save_best_only=True,
  )

  tb_callback = keras.callbacks.TensorBoard(
      log_dir=os.path.join(model_dir_path, constants.TENSORBOARD_DIR))

  return [cp_callback, tb_callback]


def print_model_summary(model, config, input_shape):
  """
    Builds model with given input shape and prints model layers.

    Args:
        model (keras.Model): Model in question.
        config (dict): Config dict with args as keys
            (see `get_train_args()` in opts.py).
        input_shape (tuple): Dataset input dimensions.

    Returns:
        N/A
    """
  print('\n')
  model.build((config['batch_size'], *input_shape))
  model.summary()
  print()
