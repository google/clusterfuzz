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
"""Generate inputs using ml rnn model."""

import argparse
import math
import numpy as np
import os
import sys
import tensorflow as tf
import time

from bot.fuzzers.ml.rnn import constants
from bot.fuzzers.ml.rnn import utils

# Reset batch_size for generation: generate multiple inputs in each run.
BATCH_SIZE = 100

# Pick one byte from topn bytes with highest probabilities.
# It's recommended to use 10 for intermediate checkpoint models, since the
# model is less accurate; use a smaller value for fully trained models.
# The larger it is set, the more randomness we give.
TOPN = 4

# The upper limit for bytes generated in each round. Having this limit
# guarantees that some units can be generated within 10 minutes.
UPPER_LENGTH_LIMIT = 10000

# The lower limit for bytes generated in each round. This is to avoid
# duplicate generation for small units.
LOWER_LENGTH_LIMIT = 4


def main(args):
  """Main function to generate inputs.

  Args:
    args: Parsed arguments.

  Returns:
    Execution status defined by `constants.ExitCode`.
  """
  # Validate required paths.
  if not validate_paths(args):
    return constants.ExitCode.INVALID_PATH

  # Extract paths.
  input_dir = args.input_dir
  output_dir = args.output_dir
  model_path = args.model_path

  # Extract model parameters.
  count = args.count
  hidden_state_size = args.hidden_state_size
  hidden_layer_size = args.hidden_layer_size

  # Use timestamp as part of identifier for each testcase generated.
  timestamp = str(math.trunc(time.time()))

  print('\nusing model {} to generate {} inputs...'.format(model_path, count))

  # Restore the RNN model by building it and loading the weights.
  model = utils.build_model(hidden_layer_size * hidden_state_size,
                            constants.DROPOUT_PKEEP, constants.BATCH_SIZE,
                            False)
  try:
    model.load_weights(model_path)
  except ValueError:
    print('Incompatible model parameters.', file=sys.stderr)
    return constants.ExitCode.TENSORFLOW_ERROR

  model.build(tf.TensorShape([constants.BATCH_SIZE, None]))
  model.reset_states()

  corpus_files_info = utils.get_files_info(input_dir)
  if not corpus_files_info:
    return constants.ExitCode.CORPUS_TOO_SMALL

  new_units_count = 0
  while new_units_count < count:
    # Reset hidden states each time to generate new inputs, so that
    # different rounds will not interfere.
    model.reset_states()

    # Randomly select `BATCH_SIZE` number of inputs from corpus.
    # Record their first byte and file length.
    new_files_bytes = []
    corpus_files_length = []
    for i in range(BATCH_SIZE):
      file_info = utils.random_element_from_list(corpus_files_info)
      first_byte, file_size = file_info['first_byte'], file_info['file_size']
      new_files_bytes.append([first_byte])
      corpus_files_length.append(file_size)

    # Use 1st and 3rd quartile values as lower and upper bound respectively.
    # Also make sure they are within upper and lower bounds.
    max_length = int(np.percentile(corpus_files_length, 75))
    max_length = min(max_length, UPPER_LENGTH_LIMIT)

    min_length = int(np.percentile(corpus_files_length, 25))
    min_length = max(LOWER_LENGTH_LIMIT, min_length)

    # Reset in special cases where min_length exceeds upper limit.
    if min_length >= max_length:
      min_length = LOWER_LENGTH_LIMIT

    input_bytes = np.array(new_files_bytes)

    for _ in range(max_length - 1):
      try:
        output = model(input_bytes).numpy()
      except tf.errors.InvalidArgumentError:
        print(
            ('Failed to run TensorFlow operations since '
             'model parameters do not match.'),
            file=sys.stderr)
        return constants.ExitCode.TENSORFLOW_ERROR

      for i in range(BATCH_SIZE):
        predicted_byte = utils.sample_from_probabilities(output[i], topn=TOPN)
        new_files_bytes[i].append(predicted_byte)
        input_bytes[i][0] = predicted_byte

    # Use timestamp as part of file name.
    for i in range(BATCH_SIZE):
      new_file_name = '{}_{:0>8}'.format(timestamp, new_units_count)
      new_file_path = os.path.join(output_dir, new_file_name)

      # Use existing input length if possible, but make sure it is between
      # min_length and max_length.
      new_file_length = max(min_length, min(corpus_files_length[i], max_length))
      new_file_byte_array = bytearray(new_files_bytes[i][:new_file_length])

      with open(new_file_path, 'wb') as new_file:
        new_file.write(new_file_byte_array)
      print('generate input: {}, feed byte: {}, input length: {}'.format(
          new_file_path, new_files_bytes[i][0], new_file_length))

      # Have we got enough inputs?
      new_units_count += 1
      if new_units_count >= count:
        break

  print('Done.')
  return constants.ExitCode.SUCCESS


def validate_paths(args):
  """Validate required paths.

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

  if not utils.validate_model_path(args.model_path):
    print('Model {} does not exist'.format(args.model_path), file=sys.stderr)
    return False

  if not os.path.exists(args.output_dir):
    os.mkdir(args.output_dir)

  return True


def parse_args():
  """Parse command line arguments.

  Returns:
    Parsed arguement object.
  """
  parser = argparse.ArgumentParser(
      'Generating testcases using the model trained with train.py script.')

  parser.add_argument('--input-dir', help='Input folder path', required=True)
  parser.add_argument('--output-dir', help='Output folder path', required=True)
  parser.add_argument(
      '--model-path', help='Path to trained model', required=True)
  parser.add_argument(
      '--count',
      help='Number of similar inputs to generate',
      type=int,
      required=True)

  # Optional arguments: model parameters.
  # Warning: parameter values must match the model specified above.
  parser.add_argument(
      '--hidden-state-size',
      help='Hidden state size of LSTM cell (must match model)',
      type=int,
      default=constants.HIDDEN_STATE_SIZE)
  parser.add_argument(
      '--hidden-layer-size',
      help='Hidden layer size of LSTM model (must match model)',
      type=int,
      default=constants.HIDDEN_LAYER_SIZE)

  return parser.parse_args()


if __name__ == '__main__':
  parsed_args = parse_args()
  sys.exit(main(parsed_args))
