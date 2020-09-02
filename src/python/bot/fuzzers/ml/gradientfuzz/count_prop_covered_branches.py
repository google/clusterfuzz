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

import glob
import os
import argparse

import tqdm
import numpy as np

import bot.fuzzers.ml.gradientfuzz.constants as constants
import bot.fuzzers.ml.gradientfuzz.plot_utils as plot_utils


def plot_coverage_distribution(dataset_name,
                               all_coverage,
                               plot_name_prefix='',
                               plot_title='Distribution of Branch Coverage'):
  """
    Plots a single histogram and saves under data/[dataset_name].

    Plotting utility for branch coverage distribution.
    Used as a subroutine for libfuzzer_to_numpy.

    Args:
        dataset_name (str): Dataset directory to save under
            (data/[dataset_name]).
        all_coverage (list(np.ndarray)): List of coverage indicator vectors.
        plot_name_prefix (str): Used for pre/post-truncation graph title
            indication.
        plot_title (str): Title at top of plot.

    Returns:
        N/A
    """
  total_covered = 0
  total_branches = 0
  proportions_covered = []
  for numpy_in in all_coverage:
    total_covered += np.sum(numpy_in)
    total_branches += len(numpy_in)
    proportions_covered.append(total_covered / total_branches)

  print('\nTotal covered/total branches: {}/{} ({}%)'.format(
      total_covered, total_branches, 100 * total_covered / total_branches))

  save_path = os.path.join(
      constants.DATASET_DIR, dataset_name,
      plot_name_prefix + constants.BRANCH_COVERAGE_PLOT_FILENAME)

  plot_utils.plot_histogram(
      proportions_covered,
      save_path,
      plot_title,
      x_axis_title=constants.HIST_COVERAGE_X_TITLE,
      y_axis_title=constants.HIST_COVERAGE_Y_TITLE,
      bins=constants.HIST_NUM_BINS_COVERAGE)


def count_covered_branches_from(dataset_name, num_bins=None):
  """
    Plots a single histogram and saves under data/[dataset_name].

    Standalone plotting utility for branch coverage distribution.
    N.B. Loads ONE numpy input in at a time, so won't run out of
    memory.

    Args:
        dataset_name (str): Dataset directory to search for
            (under data/[dataset_name]).
        num_bins (int): Number of bins for histogram.

    Returns:
        N/A
    """
  all_dataset_labels = glob.glob(
      os.path.join(constants.DATASET_DIR, dataset_name,
                   constants.STANDARD_LABEL_DIR, '*'))
  total_covered = 0
  total_branches = 0
  proportions_covered = []

  for dataset_input_name in tqdm.tqdm(all_dataset_labels):
    numpy_in = np.load(dataset_input_name)
    total_covered += np.sum(numpy_in)
    total_branches += len(numpy_in)
    proportions_covered.append(total_covered / total_branches)

  print('Total covered/total branches: {}/{} ({}%)'.format(
      total_covered, total_branches, 100 * total_covered / total_branches))

  save_path = os.path.join(constants.DATASET_DIR, dataset_name,
                           constants.BRANCH_COVERAGE_PLOT_FILENAME)

  plot_utils.plot_histogram(
      proportions_covered,
      save_path,
      'Distribution of Branch Coverage',
      x_axis_title=constants.HIST_COVERAGE_X_TITLE,
      y_axis_title=constants.HIST_COVERAGE_Y_TITLE,
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
    Plots distribution of proportions of covered branches
    across all inputs in dataset.
    """
  args = get_args()
  count_covered_branches_from(args.dataset_name, args.num_bins)


if __name__ == '__main__':
  main()
