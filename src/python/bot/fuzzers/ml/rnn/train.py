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

import argparse
import math
import numpy as np
import os
import sys
import tensorflow as tf
import time

from bot.fuzzers.ml.rnn import constants
from bot.fuzzers.ml.rnn import utils

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


@tf.function
def train_step(model, optimizer, input_data, expected_data, train=False):
  """Train the model for one step.

  Args:
    model: RNN model to train/predict.
    optimize: optimizer to use to train the model.
    input_data: input sequence to the model.
    expected_data: expected output of the model.

  Returns:
    Tuple containing the sequential loss between the expected output and the
    real output, the batch loss between the two, the accuracy metric value as
    well as the most likely predicted output.
  """
  with tf.GradientTape() as tape:
    predicted_data = model(input_data)
    loss = tf.keras.losses.sparse_categorical_crossentropy(
        expected_data, predicted_data, from_logits=True)
    seq_loss = tf.reduce_mean(input_tensor=loss, axis=1)
    batch_loss = tf.reduce_mean(input_tensor=seq_loss)

    output_bytes = tf.cast(
        tf.argmax(predicted_data, axis=-1), expected_data.dtype)
    accuracy = tf.reduce_mean(
        tf.cast(tf.equal(expected_data, output_bytes), tf.float32))

  if train:
    grads = tape.gradient(loss, model.trainable_variables)
    optimizer.apply_gradients(zip(grads, model.trainable_variables))

  return seq_loss, batch_loss, accuracy, output_bytes


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

  # Set global random seed, so any random sequence generated is repeatable.
  # It could also be removed.
  tf.random.set_seed(0)

  # Build the RNN model.
  model = utils.build_model(hidden_layer_size * hidden_state_size,
                            dropout_pkeep, batch_size, debug)

  # Choose Adam optimizer to compute gradients.
  optimizer = tf.keras.optimizers.Adam(learning_rate)

  # Init Tensorboard stuff.
  # This will save Tensorboard information in folder specified in command line.
  # Two sets of data are saved so that you can compare training and
  # validation curves visually in Tensorboard.
  timestamp = str(math.trunc(time.time()))
  summary_writer = tf.summary.create_file_writer(
      os.path.join(log_dir, timestamp + '-training'))
  validation_writer = tf.summary.create_file_writer(
      os.path.join(log_dir, timestamp + '-validation'))

  # For display: init the progress bar.
  step_size = batch_size * constants.TRAINING_SEQLEN
  frequency = constants.DISPLAY_FREQ * step_size
  progress = utils.Progress(
      constants.DISPLAY_FREQ,
      size=constants.DISPLAY_LEN,
      msg='Training on next {} batches'.format(constants.DISPLAY_FREQ))

  # We continue training on existing model, or start with a new model.
  if existing_model:
    print('Continue training on existing model: {}'.format(existing_model))
    try:
      model.load_weights(existing_model)
    except:
      print(
          ('Failed to restore existing model since model '
           'parameters do not match.'),
          file=sys.stderr)
      return constants.ExitCode.TENSORFLOW_ERROR
  else:
    print('No existing model provided. Start training with a new model.')

  # Num of bytes we have trained so far.
  steps = 0

  # Training loop.
  for input_batch, expected_batch, epoch in utils.rnn_minibatch_sequencer(
      code_text,
      batch_size,
      constants.TRAINING_SEQLEN,
      nb_epochs=constants.EPOCHS):

    # Train on one mini-batch.
    seq_loss, batch_loss, accuracy, output_bytes = train_step(
        model, optimizer, input_batch, expected_batch, train=True)

    # Log training data for Tensorboard display a mini-batch of sequences
    # every `frequency` batches.
    if debug and steps % frequency == 0:
      utils.print_learning_learned_comparison(
          input_batch, output_bytes, seq_loss, input_ranges, batch_loss,
          accuracy, epoch_size, steps, epoch)
      with summary_writer.as_default():  # pylint: disable=not-context-manager
        tf.summary.scalar('batch_loss', batch_loss, step=steps)
        tf.summary.scalar('batch_accuracy', accuracy, step=steps)
      summary_writer.flush()

    # Run a validation step every `frequency` batches.
    # The validation text should be a single sequence but that's too slow.
    # We cut it up and batch the pieces (slightly inaccurate).
    if validation and steps % frequency == 0 and validation_batch_size:
      utils.print_validation_header(len(code_text), input_ranges)
      validation_x, validation_y, _ = next(
          utils.rnn_minibatch_sequencer(validation_text, validation_batch_size,
                                        constants.VALIDATION_SEQLEN, 1))

      validation_model = utils.build_model(
          hidden_layer_size * hidden_state_size, dropout_pkeep,
          validation_batch_size, False)
      last_weights = tf.train.latest_checkpoint(model_dir)
      if last_weights:
        validation_model.load_weights(tf.train.latest_checkpoint(model_dir))
        validation_model.build(tf.TensorShape([validation_batch_size, None]))
        validation_model.reset_states()

      # Run one single inference step
      _, batch_loss, accuracy, _ = train_step(
          validation_model, optimizer, validation_x, validation_y, train=False)

      utils.print_validation_stats(batch_loss, accuracy)

      # Save validation data for Tensorboard.
      with validation_writer.as_default():  # pylint: disable=not-context-manager
        tf.summary.scalar('batch_loss', batch_loss, step=steps)
        tf.summary.scalar('batch_accuracy', accuracy, step=steps)
      validation_writer.flush()

    # Display a short text generated with the current weights and biases.
    # If enabled, there will be a large output.
    if debug and steps // 4 % frequency == 0:
      utils.print_text_generation_header()
      file_info = utils.random_element_from_list(files_info_list)
      first_byte, file_size = file_info['first_byte'], file_info['file_size']
      ry = np.array([[first_byte]])
      sample = [first_byte]

      generation_model = utils.build_model(
          hidden_layer_size * hidden_state_size, dropout_pkeep, 1, False)
      last_weights = tf.train.latest_checkpoint(model_dir)
      if last_weights:
        generation_model.load_weights(tf.train.latest_checkpoint(model_dir))
        generation_model.build(tf.TensorShape([1, None]))
        generation_model.reset_states()

      for _ in range(file_size - 1):
        prediction = generation_model(ry)
        prediction = tf.squeeze(prediction, 0).numpy()
        rc = utils.sample_from_probabilities(
            prediction, topn=10 if epoch <= 1 else 2)
        sample.append(rc)
        ry = np.array([[rc]])

      print(repr(utils.decode_to_text(sample)))
      utils.print_text_generation_footer()

    # Save a checkpoint every `10 * frequency` batches. Each checkpoint is
    # a version of model.
    if steps // 10 % frequency == 0:
      saved_model_name = constants.RNN_MODEL_NAME + '_' + timestamp
      saved_model_path = os.path.join(model_dir, saved_model_name)
      model.save_weights(saved_model_path)
      print('Saved model: {}'.format(saved_model_path))

    # Display progress bar.
    if debug:
      progress.step(reset=steps % frequency == 0)

    # Update state.
    steps += step_size

  # Save the model after training is done.
  saved_model_name = constants.RNN_MODEL_NAME + '_' + timestamp
  saved_model_path = os.path.join(model_dir, saved_model_name)
  model.save_weights(saved_model_path)
  print('Saved model: {}'.format(saved_model_path))

  return constants.ExitCode.SUCCESS


def validate_paths(args):
  """Validate paths.

  Args:
    args: Parsed arguments.

  Returns:
    True if all paths are valid, False otherwise.
  """
  if not os.path.exists(args.input_dir):
    print(
        'Input directory {} does not exist'.format(args.input_dir),
        file=sys.stderr)
    return False

  if not os.path.exists(args.model_dir):
    os.mkdir(args.model_dir)

  if not os.path.exists(args.log_dir):
    os.mkdir(args.log_dir)

  if args.existing_model and not utils.validate_model_path(args.existing_model):
    print(
        'Existing model {} does not exist'.format(args.existing_model),
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
