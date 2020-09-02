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
"""libFuzzer Neural Smoothing - Plotting Functions."""

import seaborn as sns
import matplotlib.pyplot as plt

sns.set(color_codes=True)


def plot_histogram(hist,
                   save_path,
                   title,
                   x_axis_title=None,
                   y_axis_title=None,
                   bins=None):
  """
    Basic seaborn histogram plotting wrapper with title.

    Args:
        hist (list(int)): List of numbers to construct histogram over.
        save_path (str): Save histogram image to this path.
        title (str): Title at top of histogram.
        x_axis_title (str): Title along x-axis.
        y_axis_title (str): Title along y-axis.
        bins (int): Number of histogram bins.

    Returns:
        N/A (histogram image saved under save_path)
    """
  # Get bins and plot histogram.
  if bins is None:
    bins = plt.rcParams['hist.bins']
  ax = sns.distplot(hist, kde=False, bins=bins)

  # Set axis labels.
  if x_axis_title is not None:
    ax.set_xlabel(x_axis_title)
  if y_axis_title is not None:
    ax.set_ylabel(y_axis_title)

  # Get plot and save to save_path.
  fig = ax.get_figure()
  fig.suptitle(title)
  fig.savefig(save_path)
  plt.clf()
  print('Saved under {}'.format(save_path))
