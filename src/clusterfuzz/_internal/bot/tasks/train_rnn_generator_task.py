# Copyright 2019 Google LLC
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
"""ML training task."""

import glob
import os
import sys

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers.ml.rnn import constants
from clusterfuzz._internal.bot.tasks import ml_train_utils
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell

# Model script directory.
ML_RNN_SCRIPT_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, 'fuzzers', 'ml', 'rnn')

# Suffix of temporary directories to place training results.
LOG_DIR_SUFFIX = '_log'
MODEL_DIR_SUFFIX = '_model'
CORPUS_DIR_SUFFIX = '_corpus'

# Training timeout. In theory the longer the model is trained, the more accurate
# it will be.
TRAINING_TIMEOUT = 60 * 60


def get_last_saved_model(model_directory):
  """Get the latest trained model.

  Multiple models may be saved in model_directory. This function will
  find the latest valid model.

  Args:
    model_directory: The directory where models are saved.

  Returns:
    A dictionary with two keys: 'data' and 'index'. Each
    refers to the path of one model file. Empty dictionary will be
    returned if no valid model exists.
  """
  # The dictionary to be returned.
  model_paths = {}

  # Get a list of all index files.
  file_pattern = os.path.join(model_directory,
                              '*' + constants.MODEL_INDEX_SUFFIX)
  index_file_list = list(filter(os.path.isfile, glob.glob(file_pattern)))
  if not index_file_list:
    return model_paths

  # Sort files based on their modification time.
  index_file_list.sort(key=os.path.getmtime, reverse=True)

  # Iterate the list. For each index file, search for corresponding data file.
  for index_file_path in index_file_list:
    index_file_name = os.path.basename(index_file_path)
    file_prefix = os.path.splitext(index_file_name)[0]

    # Find data file with the same prefix (from the same model).
    data_file_name = file_prefix + constants.MODEL_DATA_SUFFIX
    data_file_path = os.path.join(model_directory, data_file_name)

    # Check if they exist.
    if os.path.exists(data_file_path) and os.path.exists(index_file_path):
      model_paths['data'] = data_file_path
      model_paths['index'] = index_file_path
      break

  return model_paths


def get_model_script_path():
  """Get model training script path."""
  return os.path.join(ML_RNN_SCRIPT_DIR, constants.TRAINING_SCRIPT_NAME)


def get_corpus_directory(directory, fuzzer_name):
  """Get corpus directory to place training corpus."""
  return os.path.join(directory, fuzzer_name + CORPUS_DIR_SUFFIX)


def get_model_log_directory(directory, fuzzer_name):
  """Get log directory to keep log files during training."""
  return os.path.join(directory, fuzzer_name + LOG_DIR_SUFFIX)


def get_model_files_directory(directory, fuzzer_name):
  """Get the directory to save model files."""
  return os.path.join(directory, fuzzer_name + MODEL_DIR_SUFFIX)


def upload_model_to_gcs(model_directory, fuzzer_name):
  """Upload the latest model to GCS bucket.

  There might be multiple intermediate models saved during training. This
  function will upload the latest one to GCS bucket.

  Args:
    model_directory: The directory to save intermediate models during training.
    fuzzer_name: The fuzzer the model is trained for.
  """
  # Get latest valid model.
  model_paths = get_last_saved_model(model_directory)
  if not model_paths:
    logs.log_error('No valid RNN model is saved during training.')
    return

  latest_data_file = model_paths['data']
  latest_index_file = model_paths['index']

  # Get GCS model path.
  gcs_model_directory = ml_train_utils.get_gcs_model_directory(
      constants.RNN_MODEL_NAME, fuzzer_name)
  if not gcs_model_directory:
    logs.log_error('Failed to upload model: cannot get GCS model bucket.')
    return

  # Basename of model files.
  data_file_name = constants.RNN_MODEL_NAME + constants.MODEL_DATA_SUFFIX
  index_file_name = constants.RNN_MODEL_NAME + constants.MODEL_INDEX_SUFFIX

  gcs_data_path = '%s/%s' % (gcs_model_directory, data_file_name)
  gcs_index_path = '%s/%s' % (gcs_model_directory, index_file_name)

  logs.log('Uploading the model for %s: %s, %s.' % (fuzzer_name, data_file_name,
                                                    index_file_name))

  # Upload files to GCS.
  result = (
      storage.copy_file_to(latest_data_file, gcs_data_path) and
      storage.copy_file_to(latest_index_file, gcs_index_path))

  if result:
    logs.log('Uploaded ML RNN model for fuzzer %s.' % fuzzer_name)
  else:
    logs.log_error('Failed to upload ML RNN model for fuzzer %s.' % fuzzer_name)


def train_rnn(input_directory,
              model_directory,
              log_directory,
              batch_size=None,
              hidden_state_size=None,
              hidden_layer_size=None):
  """Train ML RNN model.

  Args:
    input_directory: Corpus directory. Required argument for training script.
    model_directory: The directory to save models. Required argument for
        training script.
    log_directory: The directory to keep logs. Required argument for training
        script.
    batch_size: Batch size in each loop.
    hidden_state_size: Hidden state size of LSTM cell.
    hidden_layer_size: Hidden layer size of LSTM model.

  Returns:
    Training result. An object of class `new_process.ProcessResult`.
  """
  # Get the script path to run the model.
  script_path = get_model_script_path()

  # Wrap command and arguments to run training script.
  args_list = [
      script_path,
      constants.INPUT_DIR_ARGUMENT_PREFIX + input_directory,
      constants.MODEL_DIR_ARGUMENT_PREFIX + model_directory,
      constants.LOG_DIR_ARGUMENT_PREFIX + log_directory,
  ]

  # Optional argument.
  if batch_size:
    args_list.append(constants.BATCH_SIZE_ARGUMENT_PREFIX + str(batch_size))
  if hidden_state_size:
    args_list.append(constants.HIDDEN_STATE_ARGUMENT_PREFIX +
                     str(hidden_state_size))
  if hidden_layer_size:
    args_list.append(constants.HIDDEN_LAYER_ARGUMENT_PREFIX +
                     str(hidden_layer_size))

  script_environment = os.environ.copy()

  logs.log('Launching the training with the following arguments: "%s".' %
           str(args_list))

  # Run process in rnn directory.
  rnn_trainer = new_process.ProcessRunner(sys.executable)

  return rnn_trainer.run_and_wait(
      args_list,
      cwd=ML_RNN_SCRIPT_DIR,
      env=script_environment,
      timeout=TRAINING_TIMEOUT)


def execute_task(full_fuzzer_name, job_type):
  """Execute ML RNN training task.

  The task is training RNN model by default. If more models are developed,
  arguments can be modified to specify which model to use.

  Args:
    fuzzer_name: Name of fuzzer, e.g. libpng_read_fuzzer.
    job_type: Job type, e.g. libfuzzer_chrome_asan.
  """
  del job_type

  # Sets up fuzzer binary build.
  fuzz_target = data_handler.get_fuzz_target(full_fuzzer_name)
  if not fuzz_target:
    logs.log_warn(f'Fuzzer not found: {full_fuzzer_name}, skip RNN training.')
    return
  fuzzer_name = fuzz_target.project_qualified_name()

  # Directory to place training files, such as logs, models, corpus.
  # Use |FUZZ_INPUTS_DISK| since it is not size constrained.
  temp_directory = environment.get_value('FUZZ_INPUTS_DISK')

  # Get corpus.
  corpus_directory = get_corpus_directory(temp_directory, fuzzer_name)
  shell.remove_directory(corpus_directory, recreate=True)

  logs.log('Downloading corpus backup for %s.' % fuzzer_name)

  if not ml_train_utils.get_corpus(corpus_directory, fuzzer_name):
    logs.log_error('Failed to download corpus backup for %s.' % fuzzer_name)
    return

  # Get the directory to save models.
  model_directory = get_model_files_directory(temp_directory, fuzzer_name)
  shell.remove_directory(model_directory, recreate=True)

  # Get the directory to save training logs.
  log_directory = get_model_log_directory(temp_directory, fuzzer_name)
  shell.remove_directory(log_directory, recreate=True)

  result = train_rnn(corpus_directory, model_directory, log_directory)

  # Training process exited abnormally but not caused by timeout, meaning
  # error occurred during execution.
  if result.return_code and not result.timed_out:
    if result.return_code == constants.ExitCode.CORPUS_TOO_SMALL:
      logs.log_warn(
          'ML RNN training task for fuzzer %s aborted due to small corpus.' %
          fuzzer_name)
    else:
      logs.log_error(
          'ML RNN training task for fuzzer %s failed with ExitCode = %d.' %
          (fuzzer_name, result.return_code),
          output=utils.decode_to_unicode(result.output))
    return

  # Timing out may be caused by large training corpus, but intermediate models
  # are frequently saved and can be uploaded.
  if result.timed_out:
    logs.log_warn('ML RNN training task for %s timed out.' % fuzzer_name)

  upload_model_to_gcs(model_directory, fuzzer_name)
