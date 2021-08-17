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
"""Generate new inputs using ML RNN model."""
# pylint: disable=g-statement-before-imports
try:
  # ClusterFuzz dependencies.
  from clusterfuzz._internal.base import modules
  modules.fix_module_search_paths()
except ImportError:
  pass

import os
import sys

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers.ml.rnn import constants
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell

# Model script directory absolute path.
ML_RNN_SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))

# Maximum number of new units to generate.
GENERATION_MAX_COUNT = 5000


def download_model_from_gcs(local_model_directory, fuzzer_name):
  """Pull model from GCS bucket and put them in specified model directory."""
  # ML model is stored in corpus bucket.
  gcs_corpus_bucket = environment.get_value('CORPUS_BUCKET')
  if not gcs_corpus_bucket:
    logs.log('Corpus bucket is not set. Skip generation.')
    return False

  # Get cloud storage path.
  # e.g. gs://clusterfuzz-corpus/rnn/libpng_read_fuzzer
  gcs_model_directory = 'gs://%s/%s/%s' % (
      gcs_corpus_bucket, constants.RNN_MODEL_NAME, fuzzer_name)

  logs.log('GCS model directory for fuzzer %s is %s.' % (fuzzer_name,
                                                         gcs_model_directory))

  # RNN model consists of two files.
  data_filename = constants.RNN_MODEL_NAME + constants.MODEL_DATA_SUFFIX
  index_filename = constants.RNN_MODEL_NAME + constants.MODEL_INDEX_SUFFIX

  # Cloud file paths.
  gcs_data_path = '%s/%s' % (gcs_model_directory, data_filename)
  gcs_index_path = '%s/%s' % (gcs_model_directory, index_filename)

  # Check if model exists.
  if not (storage.exists(gcs_data_path) and storage.exists(gcs_index_path)):
    logs.log('ML RNN model for fuzzer %s does not exist. Skip generation.' %
             fuzzer_name)
    return False

  # Local file paths.
  local_data_path = os.path.join(local_model_directory, data_filename)
  local_index_path = os.path.join(local_model_directory, index_filename)

  # Download model files.
  result = (
      storage.copy_file_from(gcs_data_path, local_data_path) and
      storage.copy_file_from(gcs_index_path, local_index_path))

  if not result:
    logs.log('Failed to download RNN model for fuzzer %s. Skip generation.' %
             fuzzer_name)
    return False

  return True


def prepare_model_directory(fuzzer_name):
  """Prepare model directory, and return model path.

  Args:
    fuzzer_name: Name of the fuzzer to which this model belongs.

  Returns:
    Model path. For example, if `/tmp/model` is the directory containing model
    files(e.g. rnn.index), the path should be '/tmp/model/rnn'.
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
  """Generate inputs with specified model parameters.

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

  # Wrap command arguments.
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


def execute(input_directory, output_directory, fuzzer_name, generation_timeout):
  """Execute ML RNN generator to produce new inputs.

  This method should be called inside launcher, to generate a number of
  new inputs based on ML RNN model.

  It will fetch ML model from GCS bucket specified in environment
  variable `CORPUS_BUCKET`. The script to run the model resides
  in folder `tools/fuzzers/ml/rnn`.

  Args:
    input_directory: Seed corpus path. The directory should not be empty.
    output_directory: The directory to place generated inputs.
    fuzzer_name: Name of the fuzzer, e.g libpng_read_fuzzer. It indicates the
        subdirectory in gcs bucket to store models.
    generation_timeout: Time in seconds for the generator to run. Normally it
        takes <1s to generate an input, assuming the input length is <4KB.
  """
  if environment.platform() != 'LINUX':
    logs.log('Unsupported platform for ML RNN generation, skipping.')
    return

  # Validate corpus folder.
  file_count = shell.get_directory_file_count(input_directory)
  if not file_count:
    logs.log('Corpus is empty. Skip generation.')
    return

  # Number of existing new inputs. They are possibly generated by other
  # generators.
  old_corpus_units = shell.get_directory_file_count(output_directory)
  old_corpus_bytes = shell.get_directory_size(output_directory)

  # Get model path.
  model_path = prepare_model_directory(fuzzer_name)
  if not model_path:
    return

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
          output=utils.decode_to_unicode(result.output))
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
        output=utils.decode_to_unicode(result.output))
