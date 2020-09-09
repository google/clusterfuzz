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
"""GradientFuzz training task."""

import glob
import os
import shutil
import sys

from bot.fuzzers.ml.gradientfuzz import constants
from bot.fuzzers.ml.gradientfuzz import run_constants
from bot.tasks import ml_train_utils
from build_management import build_manager
from google_cloud_utils import storage
from metrics import logs
from system import environment
from system import new_process
from system import shell

# Model script directory.
GRADIENTFUZZ_SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'fuzzers', 'ml', 'gradientfuzz')


def get_script_path(which_script):
  """
  Gives executable path of requested script.

  Args:
    which_script (str): Script from `run_constants.py`.

  Returns:
    (str): Absolute path to requested script (Python file).
  """
  return os.path.join(GRADIENTFUZZ_SCRIPTS_DIR, which_script)


def get_corpus_directory(root_dir, fuzzer_name):
  """Gets corpus directory path based on fuzzer."""
  return os.path.join(root_dir, run_constants.CORPUS_DIR,
                      fuzzer_name + run_constants.CORPUS_SUFFIX)


def upload_model_to_gcs(model_directory, fuzzer_name):
  """
  Upload the entire model directory to GCS bucket.

  Note that metadata stored within the model directory is needed
  for the generation scripts.

  Args:
    model_directory (str): models/[architecture]/[run-name].
    fuzzer_name (str): The fuzzer the model is trained for.

  Returns:
    True if corpus can be acquired and False otherwise.
  """
  # Get GCS model path.
  gcs_model_directory = ml_train_utils.get_gcs_model_directory(
      run_constants.GRADIENTFUZZ_DIR)
  if not gcs_model_directory:
    logs.log_error('Failed to upload model: cannot get GCS model bucket.')
    return

  # Zip entire model directory and upload.
  model_dir_name = os.path.basename(model_directory)
  zipped_dir = shutil.make_archive(model_dir_name, 'zip', model_directory)
  gcs_model_path = '{}/{}'.format(gcs_model_directory, zipped_dir)

  logs.log('Uploading the model for fuzzer {} and run {} to {}.'.format(
      fuzzer_name, model_dir_name, gcs_model_path))

  # Upload files to GCS.
  result = (storage.copy_file_to(zipped_dir, gcs_model_path))

  if result:
    logs.log('Uploaded GradientFuzz model {} for fuzzer {}.'.format(
        model_dir_name, fuzzer_name))
  else:
    logs.log_error(
        'Failed to upload GradientFuzz model {} for fuzzer {}.'.format(
            model_dir_name, fuzzer_name))


def gen_inputs_labels(corpus_directory, fuzzer_binary_path):
  """
  Generates inputs and labels from raw input corpus.

  Args:
    corpus_directory (str): Path to raw inputs.
    fuzzer_binary_path (str): Path to compiled fuzz target binary.

  Returns:
    (new_process.ProcessResult): Result of `run_and_wait()`.
    (str): Dataset name (results stored under
        GRADIENTFUZZ_SCRIPTS_DIR/data/[dataset_name]).
  """
  script_path = get_script_path(run_constants.GENERATE_DATA_SCRIPT)
  dataset_name = os.path.basename(corpus_directory)
  args_list = [
      script_path,
      run_constants.FUZZ_TARGET_BINARY_FLAG,
      fuzzer_binary_path,
      run_constants.INPUT_DIR_FLAG,
      corpus_directory,
      run_constants.DATASET_NAME_FLAG,
      dataset_name,
      run_constants.MEDIAN_MULT_FLAG,
      run_constants.DEFAULT_MEDIAN_MULT_CUTOFF,
  ]

  logs.log('Launching input gen with args: "{}".'.format(str(args_list)))

  # Run process in GradientFuzz directory.
  data_gen_proc = new_process.ProcessRunner(sys.executable)

  return data_gen_proc.run_and_wait(
      additional_args=args_list,
      cwd=GRADIENTFUZZ_SCRIPTS_DIR,
      timeout=run_constants.DATA_GEN_TIMEOUT), dataset_name


def train_gradientfuzz(fuzzer_name, dataset_name, num_inputs, testing):
  """Train GradientFuzz model.

  Args:
    fuzzer_name (str): Prefix to --run-name flag.
    dataset_name (str): Inputs/labels stored under
        GRADIENTFUZZ_SCRIPTS_DIR/data/[dataset_name].
    num_inputs (int): Number of input files (for val split/batch size).
    testing (bool): Whether or not we use testing number of epochs.

  Returns:
    (new_process.ProcessResult): Result of `run_and_wait()`.
    (str): Run name (results stored under
        GRADIENTFUZZ_SCRIPTS_DIR/models/[architecture]/[run_name]).
  """
  if num_inputs < run_constants.MIN_NUM_INPUTS:
    return new_process.ProcessResult(
        return_code=run_constants.ExitCode.CORPUS_TOO_SMALL), None

  batch_size = 4 if testing else min(32, int(num_inputs * 0.4))
  val_batch_size = 4 if testing else min(32, int(num_inputs * 0.1))
  num_epochs = (
      run_constants.NUM_TEST_EPOCHS if testing else run_constants.NUM_EPOCHS)

  # TODO(ryancao) TESTING ONLY. REMOVE!
  assert batch_size == 4
  assert val_batch_size == 4
  assert num_epochs == 5
  assert num_inputs > 80

  script_path = get_script_path(run_constants.TRAIN_MODEL_SCRIPT)
  run_name = fuzzer_name + run_constants.RUN_NAME_SUFFIX
  args_list = [
      script_path, run_constants.RUN_NAME_FLAG, run_name,
      run_constants.DATASET_NAME_FLAG, dataset_name, run_constants.EPOCHS_FLAG,
      str(num_epochs), run_constants.BATCH_SIZE_FLAG,
      str(batch_size), run_constants.VAL_BATCH_SIZE_FLAG,
      str(val_batch_size), run_constants.ARCHITECTURE_FLAG,
      constants.NEUZZ_ONE_HIDDEN_LAYER_MODEL
  ]

  logs.log('Launching training with the following arguments: "{}".'.format(
      str(args_list)))

  # Run process in gradientfuzz directory.
  gradientfuzz_trainer = new_process.ProcessRunner(sys.executable)

  return gradientfuzz_trainer.run_and_wait(
      args_list,
      cwd=GRADIENTFUZZ_SCRIPTS_DIR,
      timeout=run_constants.TRAIN_TIMEOUT), run_name


def get_model_dir(run_name):
  """
  Gets full path to model directory.

  Args:
      run_name (str): Self-explanatory.

  Returns:
      (str): Full path to model dir.
  """
  for full_path in glob.glob(
      os.path.join(GRADIENTFUZZ_SCRIPTS_DIR, constants.MODEL_DIR, '*', '*')):
    if os.path.basename(full_path) == run_name:
      return full_path
  return None


def execute_task(fuzzer_name, job_type):
  """
  Performs GradientFuzz model training.

  Grabs input corpus and processes it for inputs/labels.
  Then trains a NEUZZ-like model and uploads model dir
  (with all weights and metadata) to GCS.

  Args:
    fuzzer_name (str): Name of fuzzer, e.g. libpng_read_fuzzer.
    job_type (str): Job type, e.g. libfuzzer_chrome_asan.
  """
  if not job_type:
    logs.log_error(
        'job_type is not set when training GradientFuzz for fuzzer {}.'.format(
            fuzzer_name))
    return

  # Sets up fuzzer binary build.
  environment.set_value('FUZZ_TARGET', fuzzer_name)
  build_manager.setup_build()
  fuzzer_binary_path = environment.get_value('APP_PATH')

  # Directory to place corpus. |FUZZ_INPUTS_DISK| is not size constrained.
  temp_directory = environment.get_value('FUZZ_INPUTS_DISK')

  # Recreates corpus dir without contents.
  corpus_directory = get_corpus_directory(temp_directory, fuzzer_name)
  shell.remove_directory(corpus_directory, recreate=True)

  # This actually downloads corpus directory based on fuzzer name from GCS.
  logs.log('Downloading corpus backup for {}.'.format(fuzzer_name))
  if not ml_train_utils.get_corpus(corpus_directory, fuzzer_name):
    logs.log_error(
        'Failed to download corpus backup for {}.'.format(fuzzer_name))
    return

  # First, generate input/label pairs for training.
  gen_inputs_labels_result, dataset_name = gen_inputs_labels(
      corpus_directory, fuzzer_binary_path)

  if gen_inputs_labels_result.timed_out:
    logs.log_warn('Data gen script for {} timed out.'.format(fuzzer_name))

  # Next, invoke training script.
  num_inputs = len(glob.glob(os.path.join(corpus_directory, '*')))
  testing = environment.get_value('GRADIENTFUZZ_TESTING') is not None
  train_result, run_name = train_gradientfuzz(fuzzer_name, dataset_name,
                                              num_inputs, testing)

  # TODO(ryancao): Debugging only! REMOVE.
  if run_name != 'fake_run':
    raise ValueError(train_result.output, run_name)

  # Training process exited abnormally, but not via timeout -- do not proceed.
  if train_result.return_code and not train_result.timed_out:
    if train_result.return_code == run_constants.ExitCode.CORPUS_TOO_SMALL:
      logs.log_warn(
          'GradientFuzz training task for fuzzer {} aborted due to corpus size.'
          .format(fuzzer_name))
    else:
      logs.log_error(
          'GradientFuzz training task for fuzzer {} failed with ExitCode = {}.'
          .format(fuzzer_name, train_result.return_code),
          output=train_result.output)
    return

  model_directory = get_model_dir(run_name)
  if model_directory:
    upload_model_to_gcs(model_directory, fuzzer_name)
