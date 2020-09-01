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
"""libFuzzer Neural Smoothing - Argparse Options."""

__author__ = 'Ryan Cao (ryancao@google.com)'

import bot.fuzzers.ml.gradientfuzz.constants as constants
import argparse


def get_train_args():
  """
    Returns needed args specifying run name, training/dataset
    options, and model architecture for a full training run.
    For use in `train.py`.

    Args:
        N/A

    Returns:
        argparse.Namespace object with specified args.
    """
  parser = argparse.ArgumentParser()

  # Run name.
  parser.add_argument(
      '--run-name', help='Unique identifier for this run.', type=str)

  # Full-on configs.
  parser.add_argument(
      '--neuzz-config',
      help='Train NEUZZ model and hyperparams.',
      action='store_true')

  # Training options.
  parser.add_argument(
      '--lr',
      help='learning rate (default: {}).'.format(constants.DEFAULT_LR),
      type=float,
      default=constants.DEFAULT_LR)
  parser.add_argument(
      '--epochs',
      help='number of epochs (default: {}).'.format(
          constants.DEFAULT_NUM_EPOCHS),
      type=int,
      default=constants.DEFAULT_NUM_EPOCHS)
  parser.add_argument(
      '--optimizer',
      help='Optimizer to use (Default: {}).'.format(
          constants.DEFAULT_OPTIMIZER),
      type=str,
      default=constants.DEFAULT_OPTIMIZER,
      choices=list(constants.OPTIMIZER_MAP.keys()))

  # Dataset options.
  parser.add_argument(
      '--dataset-name',
      help='Dataset name (Look under {}/).'.format(constants.DATASET_DIR),
      type=str)
  parser.add_argument(
      '--val-split',
      help='Proportion of dataset to use as validation set (default {}).'
      .format(constants.DEFAULT_VAL_SPLIT),
      type=float,
      default=constants.DEFAULT_VAL_SPLIT)
  parser.add_argument(
      '--batch-size',
      help='Batch size (default: {}).'.format(
          constants.DEFAULT_TRAIN_BATCH_SIZE),
      type=int,
      default=constants.DEFAULT_TRAIN_BATCH_SIZE)
  parser.add_argument(
      '--val-batch-size',
      help='Validation set batch size (default: {}).'.format(
          constants.DEFAULT_VAL_BATCH_SIZE),
      type=int,
      default=constants.DEFAULT_VAL_BATCH_SIZE)

  # Model options.
  parser.add_argument(
      '--architecture',
      help='Model architecture to use.',
      type=str,
      default=constants.NEUZZ_ONE_HIDDEN_LAYER_MODEL,
      choices=list(constants.ARCHITECTURE_MAP.keys()))
  parser.add_argument(
      '--num-hidden',
      help=('Hidden dimension size (feedforward and RNN models only. ' +
            'Default: {}).').format(constants.DEFAULT_HIDDEN_SIZE),
      type=int,
      default=constants.DEFAULT_HIDDEN_SIZE)

  args = parser.parse_args()
  return args


def check_train_args(args):
  """
    Ensures that all required args exist when building a new model from scratch.

    Args:
        args (argparse.Namespace): Arguments from get_train_args().

    Returns:
        boolean: True if required args are present, and False otherwise.
    """
  if args.architecture is None:
    print('Error: --architecture is required for new models!')
    return False

  if args.dataset_name is None:
    print('Error: --dataset-name is required for new models! ' +
          '(Check {}/ directory).'.format(constants.DATASET_DIR))
    return False

  return True


def get_gradient_gen_critical_locs_args():
  """
    Returns needed args specifying run name, seed directory,
    generated file directory, and location generation method.
    For use in `gradient_gen_critical_locs.py`.

    Args:
        N/A

    Returns:
        argparse.Namespace object with specified args.
    """
  parser = argparse.ArgumentParser()

  # For loading trained model.
  parser.add_argument(
      '--run-name',
      required=True,
      help=('Pre-trained model\'s run name. ' +
            'Should be under {}/[architecture]/ directory.'.format(
                constants.MODEL_DIR)))

  # For getting seed files + save dir.
  parser.add_argument(
      '--path-to-seeds', required=True, help='Path to seed file directory.')

  parser.add_argument(
      '--path-to-lengths',
      required=True,
      help='Path to file-to-input-length dictionary.')

  parser.add_argument(
      '--generation-name',
      required=True,
      help='Name of generated gradient files directory (to be saved under ' +
      '{}/[generation-name]/{}).'
      .format(constants.GENERATED_DIR, constants.GRADIENTS_DIR))

  # How to generate.
  parser.add_argument(
      '--gradient-gen-method',
      required=True,
      help='Which outputs to generate gradients with respect to.',
      choices=constants.GRADIENT_OPTS)

  # Required mutation options for NEUZZ.
  parser.add_argument(
      '--num-output-locs',
      help='Number of branches for which to generate gradients.',
      type=int,
      default=1)
  parser.add_argument(
      '--top-k',
      help='Keep [top-k] input gradient components.',
      type=int,
      default=500)

  args = parser.parse_args()
  return args


def check_gradient_gen_critical_locs_args(args):
  """
    Ensures that proper arguments are set for each gradient gen method.

    Args:
        args (argparse.Namespace): Arguments from
            `get_gradient_gen_critical_locs_args()`.

    Returns:
        A boolean indicating whether it's okay to continue.
    """
  if args.gradient_gen_method == constants.NEUZZ_RANDOM_BRANCHES:

    if args.num_output_locs is None:
      print('Error: --num-output-locs must be specified in conjunction with {}.'
            .format(constants.NEUZZ_RANDOM_BRANCHES))
      return False

    if args.top_k is None:
      print('Error: --top-k must be specified in conjunction with {}.'.format(
          constants.NEUZZ_RANDOM_BRANCHES))
      return False

  return True


def get_gen_mutations_args():
  """
    Returns needed args specifying which directory to save mutated
    files under and which mutation generation method to use.
    For `gen_mutations.py`.

    Args:
        N/A

    Returns:
        argparse.Namespace object with specified args.
    """
  parser = argparse.ArgumentParser()

  # For running actual mutations from trained model.
  parser.add_argument(
      '--generation-name',
      required=True,
      help='Name of generated gradient files directory (gradients saved under '
      + '{}/[generation-name]/{}).'
      .format(constants.GENERATED_DIR, constants.GRADIENTS_DIR))

  parser.add_argument(
      '--mutation-name',
      required=True,
      help='Name of mutated inputs files directory (mutated files saved under '
      + '{}/[generation-name]/{}/[mutation-name]/).'
      .format(constants.GENERATED_DIR, constants.MUTATIONS_DIR))

  parser.add_argument(
      '--mutation-gen-method',
      required=True,
      help='Which mutation method to use.',
      choices=constants.MUTATION_OPTS)

  parser.add_argument(
      '--path-to-lengths',
      required=True,
      help='Path to file-to-input-length dictionary.')

  # TODO(ryancao): Mutation options for NEUZZ.

  # Mutation options for simple random.
  parser.add_argument(
      '--num-mutations',
      help='Number of mutations to perform for each file. (Default: {})'.format(
          constants.DEFAULT_NUM_MUTATIONS),
      type=int,
      default=constants.DEFAULT_NUM_MUTATIONS)

  # Mutation options for limited neighborhood.
  parser.add_argument(
      '--neighborhood-max-width',
      help='Max number of bytes to mutate (in either direction) of ' +
      'critical bytes. (Default: {})'
      .format(constants.NEIGHBORHOOD_DEFAULT_MAX_WIDTH),
      type=int,
      default=constants.NEIGHBORHOOD_DEFAULT_MAX_WIDTH)

  parser.add_argument(
      '--arith-min',
      help='Smallest byte delta to add to critical bytes. (Default: {})'.format(
          constants.ARITH_DEFAULT_MIN),
      type=int,
      default=constants.ARITH_DEFAULT_MIN)

  parser.add_argument(
      '--arith-max',
      help='Largest byte delta to add to critical bytes. (Default: {})'.format(
          constants.ARITH_DEFAULT_MAX),
      type=int,
      default=constants.ARITH_DEFAULT_MAX)

  args = parser.parse_args()
  return args


def check_gen_mutations_args(args):
  """
    Ensures that proper arguments are set for each mutation gen method.

    Args:
        args (argparse.Namespace): Arguments from `get_gen_mutations_args()`.

    Returns:
        A boolean indicating whether it's okay to continue.
    """
  if args.mutation_gen_method == constants.NEUZZ_MUTATION:
    pass

  elif args.mutation_gen_method == constants.SIMPLE_RANDOM:
    if args.num_mutations <= 0:
      print('Error: --num-mutations argument must be positive!')
      return False

  elif args.mutation_gen_method == constants.LIMITED_NEIGHBORHOOD:
    if args.num_mutations <= 0:
      print('Error: --num-mutations argument must be positive!')
      return False
    if args.arith_min >= 0:
      print('Error: --arith-min must be negative!')
      return False
    if args.arith_max <= 0:
      print('Error: --arith-max must be positive!')
      return False
    if args.neighborhood_max_width < 0:
      print('Error: --neighborhood-max-width must be non-negative!')
      return False

  return True
