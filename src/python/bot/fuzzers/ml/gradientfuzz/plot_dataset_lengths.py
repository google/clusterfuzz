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
"""libFuzzer Neural Smoothing - Dataset Stats."""

__author__ = 'Ryan Cao (ryancao@google.com)'

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.plot_utils as plot_utils
import argparse
import glob
import numpy as np
import os
import tqdm


def plot_lengths(dataset_name,
                 all_inputs,
                 plot_name_prefix='',
                 plot_title='Input Length Distribution'):
  """
    Plots distribution of input lengths given a list of zero-padded numpy
    byte arrays. Used as a subroutine for `libfuzzer_to_numpy.py`.

    Args:
        dataset_name (str): Dataset directory to save under
            (data/[dataset_name]).
        all_inputs (list(np.ndarray)): List of input numpy byte arrays.
        plot_name_prefix (str): Used for pre/post-truncation graph title
            indication.
        plot_title (str): Title at top of plot.

    Returns:
        N/A
    """
  lengths = np.zeros(len(all_inputs))
  for idx, _ in enumerate(all_inputs):
    all_nonzero = np.nonzero(all_inputs[idx])
    if len(all_nonzero[0]) == 0:
      # This is also indicative of an input with only 0s for bytes.
      # Our padding is all zeros (for input length consistency in
      # feedforward models).
      lengths[idx] = 0
    else:
      lengths[idx] = np.max(all_nonzero)

  print('\nAverage input length/std: {} | {}'.format(
      np.mean(lengths), np.std(lengths)))
  print('Input length boxplot: {} | {} | {} | {} | {}'.format(
      np.min(lengths), np.percentile(lengths, 25), np.median(lengths),
      np.percentile(lengths, 75), np.max(lengths)))

  save_path = os.path.join(
      constants.DATASET_DIR, dataset_name,
      plot_name_prefix + constants.INPUT_LENGTH_PLOT_FILENAME)

  plot_utils.plot_histogram(
      lengths,
      save_path,
      plot_title,
      x_axis_title=constants.HIST_INPUT_LEN_X_TITLE,
      y_axis_title=constants.HIST_INPUT_LEN_Y_TITLE,
      bins=constants.HIST_NUM_BINS_INPUT_LEN)


def read_and_plot(dataset_name, num_bins=None):
  """
    Plots a single histogram and saves under data/[dataset_name].

    Standalone plotting utility for input lengths.
    N.B. Loads ONE numpy input in at a time, so won't run out of
    memory.

    Args:
        dataset_name (str): Dataset directory to search for
            (under data/[dataset_name]).
        num_bins (int): Number of bins for histogram.

    Returns:
        N/A
    """
  dataset_dir = os.path.join(constants.DATASET_DIR, dataset_name,
                             constants.STANDARD_INPUT_DIR)
  all_dataset_files = list(glob.glob(os.path.join(dataset_dir, '*')))
  lengths = np.zeros(len(all_dataset_files))
  for idx in tqdm.tqdm(range(len(all_dataset_files))):
    all_nonzero = np.nonzero(np.load(all_dataset_files[idx]))
    if len(all_nonzero[0]) == 0:
      lengths[idx] = 0
    else:
      lengths[idx] = np.max(all_nonzero)

  save_path = os.path.join(constants.DATASET_DIR, dataset_name,
                           constants.INPUT_LENGTH_PLOT_FILENAME)

  plot_utils.plot_histogram(
      lengths,
      save_path,
      'Input Length Distribution',
      x_axis_title=constants.HIST_INPUT_LEN_X_TITLE,
      y_axis_title=constants.HIST_INPUT_LEN_Y_TITLE,
      bins=num_bins)


def get_args():
  """
    Returns needed arguments specifying dataset and number of histogram
    bins for manual use.

    Args:
        N/A

    Returns:
        argparse.Namespace object with specified args.
    """
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--dataset-name',
      required=True,
      help='Name of dataset (look under {}/).'.format(constants.DATASET_DIR))
  parser.add_argument(
      '--num-bins', help='Number of bins in histogram.', type=int)
  return parser.parse_args()


def main():
  """
    Plots distribution of inputs lengths (number of bytes) over
    all inputs in dataset.
    """
  args = get_args()
  read_and_plot(args.dataset_name, args.num_bins)


if __name__ == '__main__':
  main()
