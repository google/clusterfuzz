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
"""Generates new inputs using pretrained GradientFuzz model."""
# pylint: disable=g-statement-before-imports
try:
  # ClusterFuzz dependencies.
  from python.base import modules
  modules.fix_module_search_paths()
except ImportError:
  pass

import glob
import os
import shutil
import sys

from bot.fuzzers.ml.gradientfuzz import constants
from bot.fuzzers.ml.gradientfuzz import run_constants
from bot.tasks import ml_train_utils
from google_cloud_utils import storage
from metrics import logs
from system import environment
from system import new_process
from system import shell


def download_model_from_gcs(local_model_dir, fuzzer_name):
  """
  Pulls zipped model directory from GCS bucket, copies into `local_model_dir`,
  and unzips.

  Args:
    local_model_dir (str): Full path to directory where model folder should
        be saved.
    fuzzer_name (str): Full name of fuzzer as passed to `execute_task` during
        training.

  Returns:
    Boolean indicating whether the model was successfully downloaded.
  """
  run_name = fuzzer_name + run_constants.RUN_NAME_SUFFIX

  # Establish GCS download path.
  gcs_corpus_bucket = environment.get_value('CORPUS_BUCKET')
  if not gcs_corpus_bucket:
    logs.log('Corpus bucket is not set. Skipping generation step.')
    return False

  gcs_model_directory = ml_train_utils.get_gcs_model_directory(
      run_constants.GRADIENTFUZZ_DIR, fuzzer_name)

  path_to_gcs_model = f'{gcs_model_directory}/{run_name}' + '.zip'

  logs.log(f'GCS model directory for fuzzer {fuzzer_name} is ' +
           f'{path_to_gcs_model}.')

  # Check if the zipped model directory exists, then download it.
  if not storage.exists(path_to_gcs_model):
    logs.log(f'GradientFuzz model for fuzzer {fuzzer_name} does not exist. ' +
             'Skipping generation step.')
    return False

  result = storage.copy_file_from(path_to_gcs_model, local_model_dir)

  if not result:
    logs.log('Failed to download GradientFuzz model for fuzzer ' +
             f'{fuzzer_name}. Skipping generation step.')
    return False

  # Unzip the model directory, then delete the zip file.
  zipped_path = os.path.join(local_model_dir, f'{run_name}.zip')
  unzipped_path = os.path.join(local_model_dir, f'{run_name}')
  shutil.unpack_archive(zipped_path, extract_dir=unzipped_path)
  shell.remove_file(zipped_path)

  return True


def create_directory_tree():
  """
  Mimics the directory tree as would be created by running
  `gradientfuzz/train.py`.

  TODO(ryancao): Are we allowed to use the current script directory?
  Or do we have to pass in a different root directory?
  """
  # FIXME: Get model architecture BEFORE downloading from GCS!
  model_dir = os.path.join(constants.MODEL_DIR, run_constants.DUMMY_MODEL_DIR)
  if not os.path.isdir(model_dir):
    os.makedirs(model_dir)

  if not os.path.isdir(constants.DATASET_DIR):
    os.makedirs(constants.DATASET_DIR)


def generate_numpy_inputs(input_directory):
  """
  Runs libfuzzer_to_numpy.py generation script to convert raw inputs stored in
  `input_directory` into Numpy arrays to be processed.

  Args:
    input_directory (str): Absolute path to corpus.

  Returns:
    (new_process.ProcessResult): Result of `run_and_wait()`.
    (str): Dataset name (results stored under data/[dataset_name]).
  """
  dataset_name = os.path.basename(input_directory)
  script_path = run_constants.GENERATE_DATA_SCRIPT
  args_list = [
      script_path,
      run_constants.PROCESS_INPUTS_ONLY_FLAG,
      run_constants.INPUT_DIR_FLAG,
      input_directory,
      run_constants.DATASET_NAME_FLAG,
      dataset_name,
      run_constants.MEDIAN_MULT_FLAG,
      run_constants.DEFAULT_MEDIAN_MULT_CUTOFF,
  ]

  logs.log(f'Launching input gen with args: "{args_list}".')

  # Run process in current directory (bot/fuzzers/ml/gradientfuzz).
  input_gen_proc = new_process.ProcessRunner(sys.executable)
  return input_gen_proc.run_and_wait(
      additional_args=args_list,
      timeout=run_constants.DATA_GEN_TIMEOUT), dataset_name


def generate_critical_locations(dataset_name, fuzzer_name):
  """
  Invokes `gradient_gen_critical_locations.py` script to generate a critical
  locations file for each input file in the input corpus.

  Args:
    dataset_name (str): Numpy inputs previously generated under
        [data/[dataset_name]/inputs/].
    fuzzer_name (str): Name of fuzzer for which mutated inputs are
        being generated.

  Returns:
    (new_process.ProcessResult): Result of `run_and_wait()`.
    (str): Gen name (results stored under generated/[gen-name]).
  """
  script_path = run_constants.GENERATE_LOCATIONS_SCRIPT
  run_name = fuzzer_name + run_constants.RUN_NAME_SUFFIX
  path_to_seeds = os.path.join(constants.DATASET_DIR, dataset_name,
                               constants.STANDARD_INPUT_DIR)
  path_to_lengths = os.path.join(constants.DATASET_DIR, dataset_name,
                                 constants.INPUT_LENGTHS_FILENAME)
  gen_name = f'{fuzzer_name}_{dataset_name}'

  args_list = [
      script_path,
      run_constants.RUN_NAME_FLAG,
      run_name,
      run_constants.PATH_TO_SEEDS_FLAG,
      path_to_seeds,
      run_constants.PATH_TO_LENGTHS_FLAG,
      path_to_lengths,
      run_constants.GENERATION_NAME_FLAG,
      gen_name,
      run_constants.NUM_OUTPUT_LOCS_FLAG,
      run_constants.DEFAULT_NUM_OUTPUT_LOCS,
      run_constants.TOP_K_FLAG,
      run_constants.DEFAULT_TOP_K,
  ]

  logs.log(f'Launching critical location generation with args: "{args_list}".')

  # Run process in current directory (bot/fuzzers/ml/gradientfuzz).
  crit_loc_gen_proc = new_process.ProcessRunner(sys.executable)
  return crit_loc_gen_proc.run_and_wait(
      additional_args=args_list,
      timeout=run_constants.LOC_GEN_TIMEOUT), gen_name


def generate_mutations(gen_name, dataset_name):
  """
  Invokes `gen_mutations.py` script to generate mutated files from existing
  corpus files and write them to a separate directory.

  Args:
    gen_name (str): Previously generated critical locations saved under
        [generated/[gen_name]/gradients/].
    dataset_name (str): Numpy inputs previously generated under
        [data/[dataset_name]/inputs/].

  Returns:
    (new_process.ProcessResult): Result of `run_and_wait()`.
    (str): Mutated files dir name (generated mutations saved under
        [generated/[gen_name]/mutated/[mutated_dir]]).
  """
  script_path = run_constants.GENERATE_MUTATIONS_SCRIPT
  path_to_lengths = os.path.join(constants.DATASET_DIR, dataset_name,
                                 constants.INPUT_LENGTHS_FILENAME)
  mutation_name = run_constants.DEFAULT_MUT_DIR_NAME

  args_list = [
      script_path, run_constants.GENERATION_NAME_FLAG, gen_name,
      run_constants.PATH_TO_LENGTHS_FLAG, path_to_lengths,
      run_constants.MUTATION_GEN_METHOD_FLAG, constants.LIMITED_NEIGHBORHOOD,
      run_constants.MUTATION_NAME_FLAG, mutation_name
  ]

  logs.log(f'Launching mutation generation with args: "{args_list}".')

  # Run process in current directory (bot/fuzzers/ml/gradientfuzz).
  mut_gen_proc = new_process.ProcessRunner(sys.executable)
  return mut_gen_proc.run_and_wait(
      additional_args=args_list,
      timeout=run_constants.LOC_GEN_TIMEOUT), mutation_name


def execute(input_directory, output_directory, fuzzer_name):
  """Execute ML RNN generator to produce new inputs.

  It will fetch the GradientFuzz pretrained model from the GCS bucket
  specified by the environment variable `CORPUS_BUCKET` and `fuzzer_name`,
  generate critical locations for the files in `input_directory`, and
  generate mutated inputs and save them to `output_directory`.

  Args:
    input_directory (str): Seed corpus (directory) path.
    output_directory (str): The directory to save mutated inputs to.
    fuzzer_name (str): It indicates the subdirectory in the GCS bucket where
        models are stored.
  """
  if environment.platform() != 'LINUX':
    logs.log('Unsupported platform for GradientFuzz generation; skipping.')
    return

  # Validate corpus folder.
  file_count = shell.get_directory_file_count(input_directory)
  if not file_count:
    logs.log('Corpus is empty; skipping generation step.')
    return

  # Download pretrained model from GCS.
  create_directory_tree()
  model_dir = os.path.join(constants.MODEL_DIR, run_constants.DUMMY_MODEL_DIR)
  download_result = download_model_from_gcs(model_dir, fuzzer_name)
  if not download_result:
    return

  # Re-generate numpy inputs and lengths.json file.
  _, dataset_name = generate_numpy_inputs(input_directory)

  # Generate critical locations.
  _, gen_name = generate_critical_locations(dataset_name, fuzzer_name)

  # Generate mutations.
  _, mutation_name = generate_mutations(gen_name, dataset_name)

  # Copy mutated files over into suggested output directory.
  mutated_inputs_path = os.path.join(constants.GENERATED_DIR, gen_name,
                                     constants.MUTATIONS_DIR, mutation_name)
  mutated_inputs = glob.glob(os.path.join(mutated_inputs_path, '*'))
  num_mutated_inputs = len(mutated_inputs)
  if num_mutated_inputs == 0:
    logs.log_error('GradientFuzz failed to generate any new inputs for ' +
                   f'fuzzer {fuzzer_name}.')
  else:
    logs.log(f'GradientFuzz produced {num_mutated_inputs} new inputs for ' +
             f'{fuzzer_name}')

  for mutated_input in mutated_inputs:
    if not shell.copy_file(mutated_input, output_directory):
      logs.log_warn(f'Failed to copy {mutated_input} to {output_directory}.')
