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
"""libFuzzer Neural Smoothing - Coverage Parsing."""

import argparse
import glob
import json
import math
import os
import subprocess
import sys
import threading

import numpy as np

from system import environment
import bot.fuzzers.ml.gradientfuzz.constants as constants


def get_branch_coverage(libfuzzer_out, get_branch_numbers=False):
  """
    Returns Numpy indicator array of branches.

    For example, in a program with five branches, where branches 0, 2, and 3
    are covered, the output will be np.ndarray([1, 0, 1, 1, 0]).

    Args:
        libfuzzer_out (list): Raw output from running libfuzzer
            binary on a single file.
        get_branch_numbers (bool): Whether to output corresponding
            branch numbers alongside indicator array.

    Returns:
        coverage (np.ndarray): Coverage indicator for branches (see above).
    """
  line_indicators = {}
  for line in libfuzzer_out:
    try:
      split_line = line.split(' ')
      covered = (split_line[0] == constants.COVERED)
      for branch_num in [int(x) for x in split_line[1:]]:
        if branch_num not in line_indicators:
          line_indicators[branch_num] = []
        line_indicators[branch_num].append(covered)

    except ValueError:
      print('Skipping line \"{}\"'.format(line))

  # Populate indicator Numpy array.
  sorted_branches = sorted(line_indicators.keys())
  list_coverage = []
  for line in sorted_branches:
    list_coverage.extend(line_indicators[line])
  coverage = np.asarray(list_coverage)

  # Returns list of branch numbers in order.
  if get_branch_numbers:
    branch_numbers = []
    for branch_num in sorted_branches:
      branch_numbers.extend([branch_num] * len(line_indicators[branch_num]))
    return coverage, branch_numbers

  return coverage


def process_one_fuzzer(test_case_path, fuzz_target_binary, first=False):
  """
    Processes a single test case using a manually-specified fuzzer binary.

    Args:
        test_case_path (str): Full path to raw input file.
        fuzz_target_binary (str): Full path to fuzzer executable.
        first (bool): Whether to output branch numbers alongside coverage.

    Returns:
        coverage (np.ndarray): See documentation for `get_branch_coverage()`
            above.
    """
  libfuzzer_out = subprocess.getoutput(' '.join([
      fuzz_target_binary, constants.PRINT_COV_FLAG, constants.RUNS_FLAG,
      test_case_path
  ]))
  libfuzzer_out = libfuzzer_out[libfuzzer_out.find(constants.COVERAGE_MARKER) +
                                len(constants.COVERAGE_MARKER):].split('\n')
  return get_branch_coverage(libfuzzer_out, first)


def bytes_from_file(filename, chunksize=8192):
  """
    Reads bytes from a file as a generator. Taken straight from
    https://stackoverflow.com/questions/1035340/reading-binary-file-and-looping-over-each-byte/1035456#1035456.

    Args:
        filename (str): Full path to file to be read byte-by-byte.
        chunksize (int): How many bytes to read in at a time.

    Yields:
        b (byte): Next byte from file.
    """
  with open(filename, "rb") as f:
    while True:
      chunk = f.read(chunksize)
      if chunk:
        for b in chunk:
          yield b
      else:
        break


def convert_input_to_numpy(test_case_path):
  """
    Converts a single input file into a Numpy array of its raw bytes.

    Args:
        test_case_path (str): Full path to file.

    Returns:
        numpy_in (np.ndarray): Numpy array of bytes from file.
    """
  numpy_in = []
  for byte in bytes_from_file(test_case_path):
    numpy_in.append(byte)
  numpy_in = np.asarray(numpy_in)
  return numpy_in


def worker_fn(all_data, start_idx, end_idx, fuzzer_binary_path, 
              process_inputs_only):
  """
    Processes a range of inputs based on index.

    Should be free from race conditions, since
    each thread handles its own range of indices.

    Args:
        all_data (tuple(list)):
            all_coverage (list): List into which coverage np arrays are written.
            all_inputs (list): List into which input np byte arrays are written.
            input_file_paths (list): Full paths to each input file.
            all_input_lengths (list): List into which input lengths are written.
        start_idx (int): Process files beginning at this index
            (for multithreading; inclusive).
        end_idx (int): Process files ending at this index
            (for multithreading; exclusive).
        process_inputs_only (bool): Whether to only convert inputs to numpy
            (no coverage information generated).

    Returns:
        N/A
    """
  all_coverage, all_inputs, input_file_paths, all_input_lengths = all_data
  for idx in range(start_idx, end_idx):
    test_case_path = input_file_paths[idx]

    if not process_inputs_only:
      coverage = process_one_fuzzer(test_case_path, fuzzer_binary_path)
      all_coverage[idx] = coverage

    numpy_input = convert_input_to_numpy(test_case_path)
    all_input_lengths[idx] = len(numpy_input)
    all_inputs[idx] = numpy_input


def process_all(input_dir,
                output_dir,
                fuzz_target_binary,
                cutoff_std,
                cutoff_percentile,
                median_mult_cutoff,
                pad=True,
                process_inputs_only=False):
  """
    Processes every file in input_dir with libFuzzer and
    saves both inputs and labels in numpy array form under
    output_dir.

    Args:
        input_dir (str): Directory from which to read raw input files.
        output_dir (str): Directory to which to save numpy byte array
            inputs and labels.
        fuzz_target_binary (str): Path to compiled fuzz target.
        cutoff_std (float): Prune all inputs where
            len(input) > mean_length(inputs) + std_length(inputs).
        cutoff_percentile (int): Prune all inputs above [cutoff_percentile]
            percentile with respect to input length.
        median_mult_cutoff(float): Prune all inputs where
            len(input) > median_length(inputs) * median_mult_cutoff.
        pad (bool): Whether to pad all inputs to the same length.
        process_inputs_only (bool): Whether to only convert raw inputs to
            Numpy arrays (i.e. no fuzz target specified).

    Returns:
        N/A (results saved under data/[dataset_name]/{inputs, labels})
    """

  print('Processing files under {}...\n'.format(input_dir))

  input_file_paths = list(glob.glob(os.path.join(input_dir, '*')))
  all_input_lengths = [None] * len(input_file_paths)
  all_coverage = [None] * len(input_file_paths)
  all_inputs = [None] * len(input_file_paths)

  if len(input_file_paths) == 0:
    print('No input files found under {}. Program exiting.'.format(input_dir))
    return

  # Get branch numbers first.
  if not process_inputs_only:
    _, branch_numbers = process_one_fuzzer(
        input_file_paths[0], fuzz_target_binary, first=True)

  # Divide into number of usable CPUs for parallelism.
  workers = [None] * os.cpu_count()
  num_inputs_per_worker = math.ceil(len(input_file_paths) / os.cpu_count())
  for worker_idx, _ in enumerate(workers):
    start_idx = worker_idx * num_inputs_per_worker
    end_idx = min(
        len(input_file_paths), (worker_idx + 1) * num_inputs_per_worker)
    workers[worker_idx] = threading.Thread(
        target=worker_fn,
        args=((all_coverage, all_inputs, input_file_paths, all_input_lengths),
              start_idx, end_idx, fuzz_target_binary, process_inputs_only))
    workers[worker_idx].start()

  for worker in workers:
    worker.join()

  # Should always report on the same number of branches, regardless of
  # coverage status.
  if not process_inputs_only:
    for coverage in all_coverage:
      assert coverage.shape == all_coverage[0].shape

  # Perform dataset pruning based on input length.
  cutoff_len = None

  # Delete inputs with length over (mean + cutoff_std * std).
  if cutoff_std is not None:
    input_mean_len = np.mean(all_input_lengths)
    input_std_len = np.std(all_input_lengths)
    cutoff_len = input_mean_len + cutoff_std * input_std_len

  elif cutoff_percentile is not None:
    cutoff_len = np.percentile(all_input_lengths, cutoff_percentile)

  elif median_mult_cutoff is not None:
    cutoff_len = np.median(all_input_lengths) * median_mult_cutoff

  if cutoff_len is not None:
    print('\nDiscarding inputs of length over {}...'.format(int(cutoff_len)))
    orig_num_files = len(all_inputs)

    all_inputs, all_coverage, input_file_paths, all_input_lengths = \
        zip(*list(filter(lambda x: len(x[0]) <= cutoff_len, zip(
            all_inputs, all_coverage, input_file_paths, all_input_lengths))))

    all_inputs, all_coverage = list(all_inputs), list(all_coverage)
    input_file_paths, all_input_lengths = list(input_file_paths), list(
        all_input_lengths)

    print('{} files removed due to length.'.format(orig_num_files -
                                                   len(all_inputs)))

  # Pad all inputs to be same length.
  if pad:
    max_input_len = max(len(x) for x in all_inputs)
    for idx, _ in enumerate(all_inputs):
      all_inputs[idx] = np.pad(all_inputs[idx],
                               [0, max_input_len - len(all_inputs[idx])])

  # Save input lengths to un-pad later.
  input_length_mapping = {}

  print('\nSaving inputs under {}...'.format(
      os.path.join(output_dir, constants.STANDARD_INPUT_DIR)))

  for num_input, _ in enumerate(all_inputs):
    input_basename = constants.INPUT_FILENAME.format(num=num_input)
    input_save_path = os.path.join(output_dir, constants.STANDARD_INPUT_DIR,
                                   input_basename)
    np.save(input_save_path, all_inputs[num_input])
    input_length_mapping[input_basename] = all_input_lengths[num_input]

  input_lengths_save_path = os.path.join(output_dir,
                                         constants.INPUT_LENGTHS_FILENAME)
  print('Saving input lengths under {}...'.format(input_lengths_save_path))
  json.dump(input_length_mapping, open(input_lengths_save_path, 'w'))

  if not process_inputs_only:
    print('Saving labels under {}...'.format(
        os.path.join(output_dir, constants.STANDARD_LABEL_DIR)))
    for num_label, _ in enumerate(all_coverage):
      label_save_path = os.path.join(
          output_dir,
          constants.STANDARD_LABEL_DIR,
          constants.LABEL_FILENAME.format(num=num_label))
      np.save(label_save_path, all_coverage[num_label])

  input_filenames_file_name = os.path.join(
      output_dir, constants.RAW_INPUT_FILE_NAMES_FILENAME)
  print('Saving input filenames to {}...'.format(input_filenames_file_name))
  json.dump(input_file_paths, open(input_filenames_file_name, 'w'))

  if not process_inputs_only:
    branch_number_save_path = os.path.join(output_dir,
                                           constants.BRANCH_LABELS_FILENAME)
    print('Saving branch numbers to {}...'.format(branch_number_save_path))
    json.dump(branch_numbers, open(branch_number_save_path, 'w'))


def parse_args():
  """
    Returns needed args specifying raw input directory,
    dataset name, cutoff statistics, and whether to pad
    inputs to max input length.

    Args:
        N/A

    Returns:
        argparse.Namespace object with specified args.
    """
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--input-dir', help='Path to corpus directory.', required=True)
  parser.add_argument(
      '--dataset-name',
      help='Dataset name (outputs are saved under {}/[dataset_name]).'.format(
          constants.DATASET_DIR),
      required=True)
  parser.add_argument(
      '--cutoff-std',
      help='Remove inputs longer than (mean len) + cutoff_std * (std len).',
      type=int)
  parser.add_argument(
      '--cutoff-percentile',
      help='Remove inputs longer than the [cutoff_percentile]th percentile.',
      type=int)
  parser.add_argument(
      '--median-mult-cutoff',
      help='Remove inputs longer than [median len] * [median-mult-cutoff].',
      type=int)
  parser.add_argument(
      '--pad',
      help='Whether to pad inputs to longest input length. (Default: True)',
      type=bool,
      default=True)
  parser.add_argument(
      '--process-inputs-only',
      help='Whether only process raw input files to Numpy. (Default: False)',
      type=bool,
      default=False)
  parser.add_argument(
      '--fuzz-target-binary',
      help='Path to fuzz target executable. MUST be specified unless ' +
      '--process-inputs-only is invoked.',
      type=str)
  return parser.parse_args()


def main():
  """
  Converts all input files from [input-dir] into numpy, runs
  fuzzer binary on them to get coverage, and saves inputs and
  labels as numpy arrays in a ready-to-use format by `ProgramDataset`
  in data_utils.py.

  Outputs two directories and two files.

  Directories include
      > label dir (data/[dataset_name]/labels/label-{num}.npy)
      > input dir (data/[dataset_name]/inputs/input-{num}.npy)

  Files include
      > input filenames list file (data/[dataset_name]/input_file_names.json)
      > branch numbers file (data/[dataset_name]/branches.json)
  """
  args = parse_args()
  output_dir = os.path.join(constants.DATASET_DIR, args.dataset_name)

  # Argument error checking.
  if os.path.isdir(output_dir):
    print('Error: {} is already a named dataset directory (check under {}/).'
          .format(output_dir, constants.DATASET_DIR))
    sys.exit()

  if not args.process_inputs_only and args.fuzz_target_binary is None:
    print('Error: Exactly one of --process-inputs-only and ' +
          '--fuzz-target-binary must be specified.')
    sys.exit()

  cutoff_args = [
      args.cutoff_std, args.cutoff_percentile, args.median_mult_cutoff
  ]
  num_cutoff_args = sum(cutoff_arg is not None for cutoff_arg in cutoff_args)
  if num_cutoff_args > 1:
    print('Error: Only one of [--cutoff-std, --cutoff-percentile, ' +
          '--median-mult-cutoff] may be specified.')
    sys.exit()

  if num_cutoff_args == 0:
    print('Warning: Proceeding with no dataset pruning.')
    print('All inputs will be kept, regardless of length.\n')

  os.makedirs(os.path.join(output_dir, constants.STANDARD_INPUT_DIR))
  os.makedirs(os.path.join(output_dir, constants.STANDARD_LABEL_DIR))

  # For fuzz target coverage printing.
  os.environ['ASAN_SYMBOLIZER_PATH'] = environment.get_llvm_symbolizer_path()

  process_all(
      args.input_dir,
      output_dir,
      args.fuzz_target_binary,
      args.cutoff_std,
      args.cutoff_percentile,
      args.median_mult_cutoff,
      pad=args.pad,
      process_inputs_only=args.process_inputs_only)


if __name__ == '__main__':
  main()
