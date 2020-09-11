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

# Model script directory absolute path.
ML_RNN_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

# Maximum number of new units to generate.
GENERATION_MAX_COUNT = 5000


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
      run_constants.GRADIENTFUZZ_DIR, fuzzer_name
  )

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


def prepare_model_directory(fuzzer_name):
  """Prepare model directory, and return model path.

  Args:
    fuzzer_name: Name of the fuzzer to which this model belongs.

  Returns:
    Model path. For example, if `/tmp/model` is the directory containing model
    files(e.g. rnn.meta), the path should be '/tmp/model/rnn'.
  """
  # Get temporary directory.
  temp_directory = environment.get_value('BOT_TMPDIR')

  # Create model directory.
  model_directory = os.path.join(temp_directory, fuzzer_name)
  shell.remove_directory(model_directory, recreate=True)

  if not download_model_from_gcs(model_directory, fuzzer_name):
    return None

  # Got the model. Return model path.
  return os.path.join(model_directory, constants.RNN_MODEL_NAME)


def run(input_directory,
        output_directory,
        model_path,
        generation_timeout,
        generation_count=None,
        hidden_state_size=None,
        hidden_layer_size=None):
  """Generate inputs with specified model paramters.

  Args:
    input_directory: Corpus directory. Required argument for generation script.
    output_directory: New inputs directory. Required argument for generation
        script.
    model_path: Model path. Required argument for generation script.
    generation_timeout: Timeout for running generation process.
    generation_count: Number of inputs to generate. Required argument for
        generation script.
    hidden_state_size: Hidden state size of LSTM cell.
    hidden_layer_size: Hidden layer size of LSTM model.

  Returns:
    Result of running generation process. Format is defined by
    ProcessRunner.run_and_wait().
  """
  # Get generation script path.
  script_path = os.path.join(ML_RNN_SCRIPT_DIR,
                             constants.GENERATION_SCRIPT_NAME)

  # Wrap commmand arguments.
  args_list = [
      script_path,
      constants.INPUT_DIR_ARGUMENT_PREFIX + input_directory,
      constants.OUTPUT_DIR_ARGUMENT_PREFIX + output_directory,
      constants.MODEL_PATH_ARGUMENT_PREFIX + model_path,
  ]

  if generation_count:
    args_list.append(constants.GENERATION_COUNT_ARGUMENT_PREFIX +
                     str(generation_count))
  else:
    args_list.append(constants.GENERATION_COUNT_ARGUMENT_PREFIX +
                     str(GENERATION_MAX_COUNT))

  # Optional arguments.
  if hidden_state_size:
    args_list.append(constants.HIDDEN_STATE_ARGUMENT_PREFIX +
                     str(hidden_state_size))
  if hidden_layer_size:
    args_list.append(constants.HIDDEN_LAYER_ARGUMENT_PREFIX +
                     str(hidden_layer_size))

  script_environment = os.environ.copy()

  # Run process in script directory.
  rnn_runner = new_process.ProcessRunner(sys.executable)
  return rnn_runner.run_and_wait(
      args_list,
      cwd=ML_RNN_SCRIPT_DIR,
      env=script_environment,
      timeout=generation_timeout)


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


def execute(input_directory, output_directory, fuzzer_name, generation_timeout):
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
    generation_timeout (int): Maximum time (seconds) for generator to run.
  """
  if environment.platform() != 'LINUX':
    logs.log('Unsupported platform for GradientFuzz generation; skipping.')
    return

  # Validate corpus folder.
  file_count = shell.get_directory_file_count(input_directory)
  if not file_count:
    logs.log('Corpus is empty. Skip generation.')
    return

  # Number of existing inputs.
  old_corpus_units = shell.get_directory_file_count(output_directory)
  old_corpus_bytes = shell.get_directory_size(output_directory)

  # Download pretrained model from GCS.
  create_directory_tree()
  model_dir = os.path.join(constants.MODEL_DIR, run_constants.DUMMY_MODEL_DIR)
  download_result = download_model_from_gcs(model_dir, fuzzer_name)
  if not download_result:
    return

  # Re-generate numpy inputs and lengths.json file.

  result = run(input_directory, output_directory, model_path,
               generation_timeout)

  # Generation process exited abnormally but not caused by timeout, meaning
  # error occurred during execution.
  if result.return_code and not result.timed_out:
    if result.return_code == constants.ExitCode.CORPUS_TOO_SMALL:
      logs.log_warn(
          'ML RNN generation for fuzzer %s aborted due to small corpus.' %
          fuzzer_name)
    else:
      logs.log_error(
          'ML RNN generation for fuzzer %s failed with ExitCode = %d.' %
          (fuzzer_name, result.return_code),
          output=result.output)
    return

  # Timeout is not error, if we have new units generated.
  if result.timed_out:
    logs.log_warn('ML RNN generation for fuzzer %s timed out.' % fuzzer_name)

  new_corpus_units = (
      shell.get_directory_file_count(output_directory) - old_corpus_units)
  new_corpus_bytes = (
      shell.get_directory_size(output_directory) - old_corpus_bytes)
  if new_corpus_units:
    logs.log('Added %d new inputs (%d bytes) using ML RNN generator for %s.' %
             (new_corpus_units, new_corpus_bytes, fuzzer_name))
  else:
    logs.log_error(
        'ML RNN generator did not produce any inputs for %s' % fuzzer_name,
        output=result.output)
