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
"""Inference based on existing model weigths."""

from __future__ import print_function

from builtins import range
from builtins import str

import os
import sys
import math
import time

from bot.fuzzers.ml import constants
from bot.fuzzers.ml import config

from bot.fuzzers.ml.generators.random_generator import RandomGenerator
from bot.fuzzers.ml.generators.random_delete_generator \
  import RandomDeleteGenerator
from bot.fuzzers.ml.generators.rnn_generator import RNNGenerator
from bot.fuzzers.ml.generators.rnn_mk_generator import RNNMKGenerator
from bot.fuzzers.ml.generators.rnn_insert_generator import RNNInsertGenerator
from bot.fuzzers.ml.generators.rnn_score_generator \
  import RNNScoreGenerator
from bot.fuzzers.ml.generators.rnn_score_insert_generator \
  import RNNScoreInsertGenerator
from bot.fuzzers.ml.generators.gpt_generator import GPTGenerator
from bot.fuzzers.ml.generators.gpt_insert_generator import GPTInsertGenerator
from bot.fuzzers.ml.generators.bert_mask_generator import BERTMaskGenerator
from bot.fuzzers.ml.generators.bert_first_generator import BERTFirstGenerator
from bot.fuzzers.ml.generators.bert_batch_generator import BERTBatchGenerator
from bot.fuzzers.ml.generators.bert_batch_insert_generator \
  import BERTBatchInsertGenerator
from bot.fuzzers.ml.generators.vae_generator import VAEGenerator


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

  if not os.path.exists(args.model_weights_path):
    print(
        'Model weight path {} does not exist'.format(args.model_weights_path),
        file=sys.stderr)
    return False

  if not os.path.exists(args.output_dir):
    os.mkdir(args.output_dir)

  return True


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

  if args.model_name.upper() == 'RANDOM':
    generator = RandomGenerator(args.input_dir, args.pos_change,
                                args.generate_batch_size)
  elif args.model_name.upper() == 'RANDOM_DELETE':
    generator = RandomDeleteGenerator(args.input_dir, args.pos_change,
                                      args.generate_batch_size)
  elif args.model_name.upper() == 'RNN':
    generator = RNNGenerator(args.hidden_layer_number, args.hidden_state_size,
                             args.dropout_pkeep, args.model_weights_path,
                             args.input_dir, args.pos_change,
                             args.predict_window_size, args.generate_batch_size,
                             args.temperature)
  elif args.model_name.upper() == 'RNN_MK':
    generator = RNNMKGenerator(args.hidden_layer_number, args.hidden_state_size,
                               args.dropout_pkeep, args.model_weights_path,
                               args.input_dir, args.pos_change,
                               args.predict_window_size,
                               args.generate_batch_size, args.temperature)
  elif args.model_name.upper() == 'RNN_INSERT':
    generator = RNNInsertGenerator(args.hidden_layer_number,
                                   args.hidden_state_size, args.dropout_pkeep,
                                   args.model_weights_path, args.input_dir,
                                   args.pos_change, args.predict_window_size,
                                   args.generate_batch_size, args.temperature,
                                   args.insert_nums)
  elif args.model_name.upper() == 'RNN_SCORE':
    generator = RNNScoreGenerator(args.hidden_layer_number,
                                  args.hidden_state_size, args.dropout_pkeep,
                                  args.model_weights_path, args.input_dir,
                                  args.pos_change, args.predict_window_size,
                                  args.generate_batch_size, args.temperature)
  elif args.model_name.upper() == 'RNN_SCORE_INSERT':
    generator = RNNScoreInsertGenerator(
        args.hidden_layer_number, args.hidden_state_size, args.dropout_pkeep,
        args.model_weights_path, args.input_dir, args.pos_change,
        args.predict_window_size, args.generate_batch_size, args.temperature,
        args.insert_nums)
  elif args.model_name.upper() == 'GPT':
    generator = GPTGenerator(
        args.hidden_layer_number, constants.DEFAULT_GPT_D_MODEL,
        constants.DEFAULT_GPT_NUM_HEADS, args.hidden_state_size,
        constants.ALPHA_SIZE, args.predict_window_size, args.dropout_pkeep,
        args.model_weights_path, args.input_dir, args.pos_change,
        args.generate_batch_size, args.temperature)
  elif args.model_name.upper() == 'GPT_INSERT':
    generator = GPTInsertGenerator(
        args.hidden_layer_number, constants.DEFAULT_GPT_D_MODEL,
        constants.DEFAULT_GPT_NUM_HEADS, args.hidden_state_size,
        constants.ALPHA_SIZE, args.predict_window_size, args.dropout_pkeep,
        args.model_weights_path, args.input_dir, args.pos_change,
        args.generate_batch_size, args.temperature, args.insert_nums)
  elif args.model_name.upper() == 'BERT_BATCH':
    generator = BERTBatchGenerator(
        args.hidden_layer_number, constants.DEFAULT_BERT_D_MODEL,
        constants.DEFAULT_BERT_NUM_HEADS, args.hidden_state_size,
        args.predict_window_size, args.dropout_pkeep, args.model_weights_path,
        args.input_dir, args.pos_change, args.generate_batch_size,
        args.temperature)
  elif args.model_name.upper() == 'BERT_MASK':
    generator = BERTMaskGenerator(
        args.hidden_layer_number, constants.DEFAULT_BERT_D_MODEL,
        constants.DEFAULT_BERT_NUM_HEADS, args.hidden_state_size,
        args.predict_window_size, args.dropout_pkeep, args.model_weights_path,
        args.input_dir, args.pos_change, args.generate_batch_size,
        args.temperature)
  elif args.model_name.upper() == 'BERT_FIRST':
    generator = BERTFirstGenerator(
        args.hidden_layer_number, constants.DEFAULT_BERT_D_MODEL,
        constants.DEFAULT_BERT_NUM_HEADS, args.hidden_state_size,
        args.predict_window_size, args.dropout_pkeep, args.model_weights_path,
        args.input_dir, args.pos_change, args.generate_batch_size,
        args.temperature)
  elif args.model_name.upper() == 'BERT_BATCH_INSERT':
    generator = BERTBatchInsertGenerator(
        args.hidden_layer_number, constants.DEFAULT_BERT_D_MODEL,
        constants.DEFAULT_BERT_NUM_HEADS, args.hidden_state_size,
        args.predict_window_size, args.dropout_pkeep, args.model_weights_path,
        args.input_dir, args.pos_change, args.generate_batch_size,
        args.temperature, args.insert_nums)
  elif args.model_name.upper() == 'VAE':
    generator = VAEGenerator(args.generate_batch_size, args.predict_window_size,
                             args.model_weights_path, args.pos_change,
                             args.input_dir, args.temperature)
  else:
    print(f"No applicable model {args.model_name}.", file=sys.stderr)
    sys.exit(constants.ExitCode.TENSORFLOW_ERROR)

  timestamp = str(math.trunc(time.time()))

  new_units_count = 0
  while new_units_count < args.count:
    new_files_bytes = generator.generate()

    # Use timestamp as part of file name.
    for i in range(args.generate_batch_size):
      new_file_name = '{}_{:0>8}'.format(timestamp, new_units_count)
      new_file_path = os.path.join(args.output_dir, new_file_name)

      with open(new_file_path, 'wb') as new_file:
        new_file.write(new_files_bytes[i])
      print(
          f'generate input: {new_file_path}, '\
          f'input length: {len(new_files_bytes[i])}'
      )

      # Check if we have got enough files or not.
      new_units_count += 1
      if new_units_count >= args.count:
        break

  print('Done.')
  return constants.ExitCode.SUCCESS


if __name__ == '__main__':
  parsed_args = config.generate_parse_args()
  print(parsed_args)
  sys.exit(main(parsed_args))
