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
"""Train ml rnn model."""

from __future__ import print_function

import argparse
import math
import os
import sys
import time

import constants
import numpy as np
import tensorflow as tf
from tensorflow.contrib import layers
from tensorflow.contrib import rnn
import utils

# Training suggestions
#
# Training only:
#     Leave all the parameters as they are in constants.py.
#     Disable validation to run a bit faster (set validation=False).
#     You can follow progress in Tensorboard: tensorboard --logdir=log
#
# Training and experimenting (default):
#     Keep validation enabled.
#     You can now play with the parameters and follow the effects in
#     Tensorboard.
#     A good choice of parameters ensures that the testing and validation
#     curves stay close. To see the curves drift apart ("overfitting") try
#     to use an insufficient amount of training data.


def main(args):
  """Main function to train the model.

  Args:
    args: Parsed arguments.

  Returns:
    Execution status defined by `constants.ExitCode`.
  """
  # Validate paths.
  if not validate_paths(args):
    return constants.ExitCode.INVALID_PATH

  # Extract paths.
  input_dir = args.input_dir
  model_dir = args.model_dir
  log_dir = args.log_dir
  existing_model = args.existing_model

  # Extract model parameters.
  batch_size = args.batch_size
  dropout_pkeep = args.dropout_pkeep
  hidden_state_size = args.hidden_state_size
  hidden_layer_size = args.hidden_layer_size
  learning_rate = args.learning_rate

  # Extract additional flags.
  debug = args.debug
  validation = args.validation

  # Split corpus for training and validation.
  # validation_text will be empty if validation is False.
  code_text, validation_text, input_ranges = utils.read_data_files(
      input_dir, validation=validation)

  # Bail out if we don't have enough corpus for training.
  if len(code_text) < batch_size * constants.TRAINING_SEQLEN + 1:
    return constants.ExitCode.CORPUS_TOO_SMALL

  # Get corpus files info. Will be used in debug mode to generate sample text.
  files_info_list = []
  if debug:
    files_info_list = utils.get_files_info(input_dir)
    assert files_info_list

  # Calculate validation batch size. It will be 0 if we choose not to validate.
  validation_batch_size = len(validation_text) // constants.VALIDATION_SEQLEN

  # Display some stats on the data.
  epoch_size = len(code_text) // (batch_size * constants.TRAINING_SEQLEN)
  utils.print_data_stats(len(code_text), len(validation_text), epoch_size)

  # Set graph-level random seed, so any random sequence generated in this
  # graph is repeatable. It could also be removed.
  tf.set_random_seed(0)

  # Define placeholder for learning rate, dropout and batch size.
  lr = tf.placeholder(tf.float32, name='lr')
  pkeep = tf.placeholder(tf.float32, name='pkeep')
  batchsize = tf.placeholder(tf.int32, name='batchsize')

  # Input data.
  input_bytes = tf.placeholder(tf.uint8, [None, None], name='input_bytes')
  input_onehot = tf.one_hot(input_bytes, constants.ALPHA_SIZE, 1.0, 0.0)

  # Expected outputs = same sequence shifted by 1, since we are trying to
  # predict the next character.
  expected_bytes = tf.placeholder(tf.uint8, [None, None], name='expected_bytes')
  expected_onehot = tf.one_hot(expected_bytes, constants.ALPHA_SIZE, 1.0, 0.0)

  # Input state.
  hidden_state = tf.placeholder(
      tf.float32, [None, hidden_state_size * hidden_layer_size],
      name='hidden_state')

  # "naive dropout" implementation.
  cells = [rnn.GRUCell(hidden_state_size) for _ in range(hidden_layer_size)]
  dropcells = [
      rnn.DropoutWrapper(cell, input_keep_prob=pkeep) for cell in cells
  ]
  multicell = rnn.MultiRNNCell(dropcells, state_is_tuple=False)
  multicell = rnn.DropoutWrapper(multicell, output_keep_prob=pkeep)

  output_raw, next_state = tf.nn.dynamic_rnn(
      multicell, input_onehot, dtype=tf.float32, initial_state=hidden_state)
  next_state = tf.identity(next_state, name='next_state')

  # Reshape training outputs.
  output_flat = tf.reshape(output_raw, [-1, hidden_state_size])
  output_logits = layers.linear(output_flat, constants.ALPHA_SIZE)

  # Reshape expected outputs.
  expected_flat = tf.reshape(expected_onehot, [-1, constants.ALPHA_SIZE])

  # Compute training loss.
  loss = tf.nn.softmax_cross_entropy_with_logits_v2(
      logits=output_logits, labels=expected_flat)
  loss = tf.reshape(loss, [batchsize, -1])

  # Use softmax to normalize training outputs.
  output_onehot = tf.nn.softmax(output_logits, name='output_onehot')

  # Use argmax to get the max value, which is the predicted bytes.
  output_bytes = tf.argmax(output_onehot, 1)
  output_bytes = tf.reshape(output_bytes, [batchsize, -1], name='output_bytes')

  # Choose Adam optimizer to compute gradients.
  optimizer = tf.train.AdamOptimizer(lr).minimize(loss)

  # Stats for display.
  seqloss = tf.reduce_mean(loss, 1)
  batchloss = tf.reduce_mean(seqloss)
  accuracy = tf.reduce_mean(
      tf.cast(
          tf.equal(expected_bytes, tf.cast(output_bytes, tf.uint8)),
          tf.float32))
  loss_summary = tf.summary.scalar('batch_loss', batchloss)
  acc_summary = tf.summary.scalar('batch_accuracy', accuracy)
  summaries = tf.summary.merge([loss_summary, acc_summary])

  # Init Tensorboard stuff.
  # This will save Tensorboard information in folder specified in command line.
  # Two sets of data are saved so that you can compare training and
  # validation curves visually in Tensorboard.
  timestamp = str(math.trunc(time.time()))
  summary_writer = tf.summary.FileWriter(
      os.path.join(log_dir, timestamp + '-training'))
  validation_writer = tf.summary.FileWriter(
      os.path.join(log_dir, timestamp + '-validation'))

  # Init for saving models.
  # They will be saved into a directory specified in command line.
  saver = tf.train.Saver(max_to_keep=constants.MAX_TO_KEEP)

  # For display: init the progress bar.
  step_size = batch_size * constants.TRAINING_SEQLEN
  frequency = constants.DISPLAY_FREQ * step_size
  progress = utils.Progress(
      constants.DISPLAY_FREQ,
      size=constants.DISPLAY_LEN,
      msg='Training on next {} batches'.format(constants.DISPLAY_FREQ))

  # Set initial state.
  state = np.zeros([batch_size, hidden_state_size * hidden_layer_size])
  session = tf.Session()

  # We continue training on exsiting model, or start with a new model.
  if existing_model:
    print('Continue training on existing model: {}'.format(existing_model))
    try:
      saver.restore(session, existing_model)
    except:
      print('Failed to restore existing model since model parameters do not '
            'match.', file=sys.stderr)
      return constants.ExitCode.TENSORFLOW_ERROR
  else:
    print('No existing model provided. Start training with a new model.')
    session.run(tf.global_variables_initializer())

  # Num of bytes we have trained so far.
  steps = 0

  # Training loop.
  for input_batch, expected_batch, epoch in utils.rnn_minibatch_sequencer(
      code_text,
      batch_size,
      constants.TRAINING_SEQLEN,
      nb_epochs=constants.EPOCHS):

    # Train on one mini-batch.
    feed_dict = {
        input_bytes: input_batch,
        expected_bytes: expected_batch,
        hidden_state: state,
        lr: learning_rate,
        pkeep: dropout_pkeep,
        batchsize: batch_size
    }

    _, predicted, new_state = session.run(
        [optimizer, output_bytes, next_state], feed_dict=feed_dict)

    # Log training data for Tensorboard display a mini-batch of sequences
    # every `frequency` batches.
    if debug and steps % frequency == 0:
      feed_dict = {
          input_bytes: input_batch,
          expected_bytes: expected_batch,
          hidden_state: state,
          pkeep: 1.0,
          batchsize: batch_size
      }
      predicted, seq_loss, batch_loss, acc_value, summaries_value = session.run(
          [output_bytes, seqloss, batchloss, accuracy, summaries],
          feed_dict=feed_dict)
      utils.print_learning_learned_comparison(
          input_batch, predicted, seq_loss, input_ranges, batch_loss, acc_value,
          epoch_size, steps, epoch)
      summary_writer.add_summary(summaries_value, steps)

    # Run a validation step every `frequency` batches.
    # The validation text should be a single sequence but that's too slow.
    # We cut it up and batch the pieces (slightly inaccurate).
    if validation and steps % frequency == 0 and validation_batch_size:
      utils.print_validation_header(len(code_text), input_ranges)
      validation_x, validation_y, _ = next(
          utils.rnn_minibatch_sequencer(validation_text, validation_batch_size,
                                        constants.VALIDATION_SEQLEN, 1))
      null_state = np.zeros(
          [validation_batch_size, hidden_state_size * hidden_layer_size])
      feed_dict = {
          input_bytes: validation_x,
          expected_bytes: validation_y,
          hidden_state: null_state,
          pkeep: 1.0,
          batchsize: validation_batch_size
      }
      batch_loss, acc_value, summaries_value = session.run(
          [batchloss, accuracy, summaries], feed_dict=feed_dict)
      utils.print_validation_stats(batch_loss, acc_value)

      # Save validation data for Tensorboard.
      validation_writer.add_summary(summaries_value, steps)

    # Display a short text generated with the current weights and biases.
    # If enabled, there will be a large output.
    if debug and steps // 4 % frequency == 0:
      utils.print_text_generation_header()
      file_info = utils.random_element_from_list(files_info_list)
      first_byte, file_size = file_info['first_byte'], file_info['file_size']
      ry = np.array([[first_byte]])
      rh = np.zeros([1, hidden_state_size * hidden_layer_size])
      sample = [first_byte]
      for _ in range(file_size - 1):
        feed_dict = {
            input_bytes: ry,
            pkeep: 1.0,
            hidden_state: rh,
            batchsize: 1
        }
        ryo, rh = session.run([output_onehot, next_state], feed_dict=feed_dict)
        rc = utils.sample_from_probabilities(ryo, topn=10 if epoch <= 1 else 2)
        sample.append(rc)
        ry = np.array([[rc]])
      print(repr(utils.decode_to_text(sample)))
      utils.print_text_generation_footer()

    # Save a checkpoint every `10 * frequency` batches. Each checkpoint is
    # a version of model.
    if steps // 10 % frequency == 0:
      saved_model_name = constants.RNN_MODEL_NAME + '_' + timestamp
      saved_model_path = os.path.join(model_dir, saved_model_name)
      saved_model = saver.save(session, saved_model_path, global_step=steps)
      print('Saved model: {}'.format(saved_model))

    # Display progress bar.
    if debug:
      progress.step(reset=steps % frequency == 0)

    # Update state.
    state = new_state
    steps += step_size

  # Save the model after training is done.
  saved_model_name = constants.RNN_MODEL_NAME + '_' + timestamp
  saved_model_path = os.path.join(model_dir, saved_model_name)
  saved_model = saver.save(session, saved_model_path, global_step=steps)
  print('Saved model: {}'.format(saved_model))

  return constants.ExitCode.SUCCESS


def validate_paths(args):
  """Validate paths.

  Args:
    args: Parsed arguments.

  Returns:
    True if all paths are valid, False otherwise.
  """
  if not os.path.exists(args.input_dir):
    print('Input directory {} does not exist'.format(args.input_dir),
          file=sys.stderr)
    return False

  if not os.path.exists(args.model_dir):
    os.mkdir(args.model_dir)

  if not os.path.exists(args.log_dir):
    os.mkdir(args.log_dir)

  if args.existing_model and not utils.validate_model_path(args.existing_model):
    print('Existing model {} does not exist'.format(args.existing_model),
          file=sys.stderr)
    return False

  return True


def parse_args():
  """Parse command line arguments.

  Returns:
    Parsed arguement object.
  """
  parser = argparse.ArgumentParser('Training RNN model on existing testcases')

  parser.add_argument('--input-dir', help='Input folder path', required=True)
  parser.add_argument('--log-dir', help='Log folder path', required=True)
  parser.add_argument('--model-dir', help='Path to save models', required=True)

  # Optional arguments: model parameters and additional flags.
  parser.add_argument(
      '--batch-size', help='Batch size', type=int, default=constants.BATCH_SIZE)
  parser.add_argument(
      '--debug', help='Print training progress', action='store_true')
  parser.add_argument(
      '--dropout-pkeep',
      help='Dropout probability (keep rate)',
      type=float,
      default=constants.DROPOUT_PKEEP)
  parser.add_argument(
      '--existing-model', help='Continue training on existing model')
  parser.add_argument(
      '--hidden-state-size',
      help='Hidden state size of LSTM cell',
      type=int,
      default=constants.HIDDEN_STATE_SIZE)
  parser.add_argument(
      '--hidden-layer-size',
      help='Hidden layer size of LSTM model',
      type=int,
      default=constants.HIDDEN_LAYER_SIZE)
  parser.add_argument(
      '--learning-rate',
      help='Learning rate',
      type=float,
      default=constants.LEARNING_RATE)
  parser.add_argument(
      '--validation',
      help='Print validation stats during training',
      action='store_true')

  return parser.parse_args()


if __name__ == '__main__':
  parsed_args = parse_args()
  sys.exit(main(parsed_args))
