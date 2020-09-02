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
"""libFuzzer Neural Smoothing - Utility Functions."""

import glob
import os
import json

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.opts as opts


def make_required_dirs():
  for directory in constants.REQUIRED_DIRS:
    _ = os.path.isdir(directory) or os.makedirs(directory)


def get_full_path(run_name):
  '''
    TODO(ryancao): Warning -- Assumes all runs (independent of architecture)
        have UNIQUE names!!!
    '''
  for full_model_path in glob.glob(os.path.join(constants.MODEL_DIR, '*', '*')):
    model_run_name = os.path.split(full_model_path)[1]
    if model_run_name == run_name:
      return full_model_path
  return None


def run_exists(run_name):
  return get_full_path(run_name) is not None


def pretty_print(config):
  print('\n===== CONFIG =====')
  for k, v in config.items():
    print('{} : {}'.format(k, v))
  print('==================\n')


def config_from_args(args):
  '''
    Creates config file from command-line args.

    Args:
        args (argparse.Namespace): Arguments from parser.parse_args().

    Returns:
        config (dict): Run configuration settings dictionary.
        boolean: True if required args are present, and False otherwise.
    '''

  # Load existing run.
  if run_exists(args.run_name):
    print('Resuming training of run {}...'.format(args.run_name))
    config_filepath = os.path.join(
        get_full_path(args.run_name), constants.CONFIG_FILENAME)
    config = json.load(open(config_filepath, 'r'))
    return config, False

  # Otherwise, initialize with given arguments.
  config = vars(args)
  config['cur_epoch'] = 0

  # Inittialize run name.
  if config['run_name'] is None:
    default_run_name = constants.default_run_name()
    print(
        'No run name specified -- defaulting to {}...'.format(default_run_name))
    config['run_name'] = default_run_name

  # Create run using NEUZZ hyperparameters.
  if args.neuzz_config:
    print('Creating new model with NEUZZ config...')
    constants.populate_with_neuzz(config)

  # All runs MUST have dataset_dir and architecture.
  if not opts.check_train_args(args):
    assert False

  # Run name and directories
  os.makedirs(
      os.path.join(constants.MODEL_DIR, config['architecture'],
                   config['run_name']))

  save_model_config(config)
  return config, True


def save_model_config(config):
  config_filepath = os.path.join(
      get_full_path(config['run_name']), constants.CONFIG_FILENAME)
  with open(config_filepath, 'w') as f:
    json.dump(config, f)


def get_latest_filename(config):
  model_filepath = os.path.join(
      get_full_path(config['run_name']), constants.CHECKPOINT_HEADER + '*')
  latest_filename = sorted(glob.glob(model_filepath), key=os.path.getmtime)[0]
  return latest_filename
