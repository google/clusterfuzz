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
"""libFuzzer Neural Smoothing - Location Generation."""

import glob
import json
import os
import tqdm

import numpy as np
import tensorflow as tf

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.opts as opts
import bot.fuzzers.ml.gradientfuzz.model_utils as model_utils
import bot.fuzzers.ml.gradientfuzz.models as models
import bot.fuzzers.ml.gradientfuzz.utils as utils


@tf.function
def get_input_grads(model, input_tensor, is_rnn):
  """
    Computes partial derivatives with respect to input over ALL output
        components.

    Args:
        model (keras.Model): Trained neural net with which to compute gradients.
        input_tensor (tf.constant): Input file to generate gradients against.
        is_rnn (bool): Whether model is RNN-type.

    Returns:
        tf.tensor: Gradient tensor of shape (num_branches, input_length).
        ----------------------------------------------------------
        | g_{1, 1} g_{1, 2} g_{1, 3} ... g_{1, input_len}        |
        | ...                                                    |
        | g_{num_output_locs, 1} ... g_{num_branches, input_len} |
        ----------------------------------------------------------
    """
  use_pfor = not is_rnn
  with tf.GradientTape(watch_accessed_variables=False) as gradient_tape:
    gradient_tape.watch(input_tensor)
    model_outputs = model(input_tensor, training=False)
  return tf.squeeze(
      gradient_tape.jacobian(
          model_outputs, input_tensor, experimental_use_pfor=use_pfor))


def generate_all_critical_locs(args, model, config, metadata_dict):
  """
    Generates location files under generated/[generation-name]/gradient_locs/
    as specified by `args`, using `model`.

    N.B. ONE critical locations file (in the form of a numpy array) is
    generated per seed file. Its format is:
    ---------------------------------------------------------
    | l_{1, 1} l_{1, 2} l_{1, 3} ... l_{1, top_k}           |
    | ...                                                   |
    | l_{num_output_locs, 1} ... l_{num_output_locs, top_k} |
    ---------------------------------------------------------
    where l_{i, j} is the index (i.e. byte number in input file) of the jth
    largest gradient component with respect to branch i.

    Args:
        args (argparse.Namespace): See function
            `get_gradient_gen_critical_locs_args()` under opts.py.
        model (keras.Model): Trained neural net with which to compute gradients.
        config (dict): Model config as produced by `config_from_args()` under
            utils.py.
        metadata_dict (dict): Stores information about which output branches
            gradients were taken with respect to, as well as all the information
            from `args`.

    Returns:
        N/A
    """
  is_rnn = constants.MODEL_TYPE_MAP[config[
      'architecture']] == constants.ModelTypes.RNN
  seed_file_paths = list(glob.glob(os.path.join(args.path_to_seeds, '*')))
  save_dir = os.path.join(constants.GENERATED_DIR, args.generation_name,
                          constants.GRADIENTS_DIR)
  print('Computing gradients... Saving all critical location files under {}'
        .format(save_dir))
  input_length_mapping = json.load(open(args.path_to_lengths, 'r'))

  for seed_file_path in tqdm.tqdm(seed_file_paths):

    # Grab save path for generated gradient location files.
    seed_file_name = os.path.basename(seed_file_path)
    save_path = os.path.join(save_dir, seed_file_name)
    input_length = input_length_mapping[seed_file_name]

    # Load seed file and get number of output locations to look at.
    seed_file_numpy = np.load(seed_file_path)
    num_output_locs = min(args.num_output_locs, len(seed_file_numpy))

    # TODO(ryancao): Implement other output-picking methods. (Not just a limited
    # subset, e.g. non-coverage! We can even add gradients from multiple
    # [uncovered] branches!)
    chosen_branches = None
    if args.gradient_gen_method == constants.NEUZZ_RANDOM_BRANCHES:
      chosen_branches = np.random.choice(
          range(config['output_dim']), size=num_output_locs, replace=False)

    # Save which branches were chosen for each file under metadata.
    metadata_dict['files_to_branches'][seed_file_name] = list(
        int(x) for x in chosen_branches)

    # Compute ALL gradients and record specified ones.
    # Add extra input_len dimension to seed file if using RNN-style model.
    processed_seed_file_numpy = np.expand_dims(
        seed_file_numpy, -1) if is_rnn else seed_file_numpy
    input_tensor = tf.constant(
        np.expand_dims(processed_seed_file_numpy, axis=0), dtype=tf.float32)
    all_gradients = get_input_grads(model, input_tensor, is_rnn)

    # Select only the chosen branches, and keep only the top-k indices
    # within the actual original input length, in order.
    selected_gradients = all_gradients.numpy()[chosen_branches, :]
    all_gradient_locs = np.flip(
        np.argsort(np.abs(selected_gradients), axis=1), axis=1)
    all_keeper_locs = []
    for gradients_per_branch in all_gradient_locs:
      all_valid_locs = gradients_per_branch[gradients_per_branch < input_length]
      padding = np.zeros(len(gradients_per_branch) - len(all_valid_locs))
      keeper_locs = np.concatenate((all_valid_locs, padding))[:args.top_k]
      all_keeper_locs.append(keeper_locs)
    all_keeper_locs = np.stack(all_keeper_locs)

    np.save(save_path, all_keeper_locs)

  metadata_save_path = os.path.join(save_dir, constants.METADATA_FILENAME)
  print('Finished computing gradients + locations! Saving metadata to {}...'
        .format(metadata_save_path))
  json.dump(metadata_dict, open(metadata_save_path, 'w'))


def main():
  """
    Given a specified corpus directory and pre-trained neural net, generates
    critical locations (ripe for mutation) for each seed file in the corpus
    directory as specified by the pre-trained neural net's gradients.

    Args:
        N/A (see `get_gradient_gen_critical_locs_args()` in opts.py)

    Returns:
        N/A (generated files saved to generated/[generation-name]/gradients)
    """
  # Gets args and creates directory to save generated critical indices.
  args = opts.get_gradient_gen_critical_locs_args()
  generation_dir = os.path.join(constants.GENERATED_DIR, args.generation_name)
  if os.path.isdir(generation_dir):
    raise RuntimeError(
        '{} already exists as a generated directory.'.format(generation_dir))
  os.makedirs(os.path.join(generation_dir, constants.GRADIENTS_DIR))

  # Load pretrained model config.
  if not utils.run_exists(args.run_name):
    raise RuntimeError('That run does not exist. Check under {}/'.format(
        constants.MODEL_DIR))

  config_filepath = os.path.join(
      utils.get_full_path(args.run_name), constants.CONFIG_FILENAME)
  config = json.load(open(config_filepath, 'r'))
  print('Successfully loaded model from config {}'.format(config_filepath))

  # Load model from pretrained weights.
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
  model_utils.print_model_summary(model, config, config['input_shape'])

  # Generate gradients from given args!
  if opts.check_gradient_gen_critical_locs_args(args):
    metadata_dict = vars(args)
    metadata_dict['files_to_branches'] = {}
    generate_all_critical_locs(args, model, config, metadata_dict)


if __name__ == '__main__':
  main()
