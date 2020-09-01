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
"""Tests for train_gradientfuzz_task.py."""

import glob
import numpy as np
import os
import tempfile
import unittest

from bot.fuzzers.ml.gradientfuzz import run_constants
from bot.fuzzers.ml.gradientfuzz import constants
from bot.tasks import train_gradientfuzz_task
from system import new_process
from system import shell
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

# Directory for testing files.
GRADIENTFUZZ_TESTING_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), os.pardir, 'fuzzers',
        'ml', 'gradientfuzz'))

# Small, precompiled fuzz target.
TESTING_BINARY = 'zlib_uncompress_sample_fuzzer'

# Tiny sample corpus.
TESTING_CORPUS_DIR = 'sample_corpus'


class ExecuteTaskTest(unittest.TestCase):
  """Execute training script test."""

  def setUp(self):
    test_helpers.patch_environ(self)

    self.fuzzer_name = 'fake_fuzzer'
    self.job_type = 'fake_job'
    self.dataset_name = 'fake_dataset'
    self.run_name = 'fake_run'
    self.home_dir = train_gradientfuzz_task.GRADIENTFUZZ_SCRIPTS_DIR
    self.models_dir = os.path.join(self.home_dir, constants.MODEL_DIR)
    self.data_dir = os.path.join(self.home_dir, constants.DATASET_DIR)
    self.temp_dir = tempfile.mkdtemp()
    self.binary_path = os.path.join(GRADIENTFUZZ_TESTING_DIR, TESTING_BINARY)

    # TODO(ryancao): Fix env var name!
    os.environ['FUZZ_INPUTS_DISK'] = self.temp_dir
    os.environ['TEST_BINARY_PATH'] = self.binary_path

    test_helpers.patch(self, [
        'bot.tasks.train_gradientfuzz_task.get_corpus',
        'bot.tasks.train_gradientfuzz_task.gen_inputs_labels',
        'bot.tasks.train_gradientfuzz_task.train_gradientfuzz',
        'bot.tasks.train_gradientfuzz_task.upload_model_to_gcs',
    ])

    self.mock.get_corpus.return_value = True
    self.mock.gen_inputs_labels.return_value = new_process.ProcessResult(
        return_code=0), self.dataset_name
    self.mock.train_gradientfuzz.return_value = new_process.ProcessResult(
        return_code=0), self.run_name
    self.mock.upload_model_to_gcs.return_value = True

    # Fakes creating directory tree.
    self.fake_dataset_dir = os.path.join(self.data_dir, self.dataset_name)
    self.fake_model_dir = os.path.join(
        self.models_dir, constants.NEUZZ_ONE_HIDDEN_LAYER_MODEL, self.run_name)
    os.makedirs(self.fake_dataset_dir)
    os.makedirs(self.fake_model_dir)

  def tearDown(self):
    shell.remove_directory(self.temp_dir)
    shell.remove_directory(self.models_dir)
    shell.remove_directory(self.data_dir)

  def test_execute(self):
    """Test execute task."""
    corpus_dir = os.path.join(self.temp_dir, run_constants.CORPUS_DIR,
                              self.fuzzer_name + run_constants.CORPUS_SUFFIX)
    train_gradientfuzz_task.execute_task(self.fuzzer_name, self.job_type)

    self.mock.gen_inputs_labels.assert_called_once_with(
        corpus_dir, self.binary_path)
    self.mock.train_gradientfuzz.assert_called_once_with(
        self.fuzzer_name, 'fake_dataset')
    self.mock.upload_model_to_gcs.assert_called_once_with(
        self.fake_model_dir, self.fuzzer_name)


@test_utils.integration
class GenerateInputsIntegrationTest(unittest.TestCase):
  """
  Unit tests for generating model inputs/labels from
  raw input files.
  """

  def setUp(self):
    self.home_dir = train_gradientfuzz_task.GRADIENTFUZZ_SCRIPTS_DIR
    self.corpus_dir = os.path.join(GRADIENTFUZZ_TESTING_DIR, TESTING_CORPUS_DIR)
    self.dataset_dir = os.path.join(self.home_dir, constants.DATASET_DIR,
                                    TESTING_CORPUS_DIR)
    self.binary_path = os.path.join(GRADIENTFUZZ_TESTING_DIR, TESTING_BINARY)

  def tearDown(self):
    shell.remove_directory(os.path.join(self.home_dir, constants.DATASET_DIR))

  def check_all_same_lengths(self, files):
    standard_length = None
    for input_file in glob.glob(files):
      input_length = len(np.load(input_file))
      if standard_length is None:
        standard_length = input_length
      self.assertTrue(standard_length == input_length)

  def test_gen_inputs_labels(self):
    """
    Generates input/label pairs using a tiny corpus and
    pre-compiled binary.
    """
    result, dataset_name = train_gradientfuzz_task.gen_inputs_labels(
        self.corpus_dir, self.binary_path)

    print(result)
    print(dataset_name)

    # Asserts that directories were created.
    inputs = os.path.join(self.dataset_dir, constants.STANDARD_INPUT_DIR, '*')
    labels = os.path.join(self.dataset_dir, constants.STANDARD_LABEL_DIR, '*')
    self.assertTrue(os.path.isdir(self.dataset_dir))

    # Checks lengths of generated files.
    self.check_all_same_lengths(inputs)
    self.check_all_same_lengths(labels)


@test_utils.integration
class GradientFuzzTrainTaskIntegrationTest(unittest.TestCase):
  """
  Tests all of execute_task() except GCS functionality.
  """

  def setUp(self):
    self.input_directory = os.path.join(DATA_DIRECTORY, 'input')
    self.model_directory = tempfile.mkdtemp()
    self.log_directory = tempfile.mkdtemp()

    self.batch_size = 1
    self.hidden_state_size = 2
    self.hidden_layer_size = 1

  def tearDown(self):
    shell.remove_directory(self.model_directory)
    shell.remove_directory(self.log_directory)

  def test_train_gradientfuzz(self):
    """Test train GradientFuzz model on a simple corpus."""
    # No model exists in model directory.
    self.assertFalse(
        train_gradientfuzz_task.get_last_saved_model(self.model_directory))

    # The training should be fast (a few seconds) since sample corpus is
    # extremely small.
    result = train_gradientfuzz_task.train_gradientfuzz(
        self.input_directory, self.model_directory, self.log_directory,
        self.batch_size, self.hidden_state_size, self.hidden_layer_size)

    self.assertEqual(result.return_code, constants.ExitCode.SUCCESS)
    self.assertFalse(result.timed_out)

    # At least one model exists.
    self.assertTrue(
        train_gradientfuzz_task.get_last_saved_model(self.model_directory))

  def test_small_corpus(self):
    """Test small corpus situation."""
    # Increase batch size so the sample corpus appears small in this case.
    self.batch_size = 100

    result = train_gradientfuzz_task.train_gradientfuzz(
        self.input_directory, self.model_directory, self.log_directory,
        self.batch_size, self.hidden_state_size, self.hidden_layer_size)

    self.assertEqual(result.return_code, constants.ExitCode.CORPUS_TOO_SMALL)
    self.assertFalse(result.timed_out)

    # No model exsits after execution.
    self.assertFalse(
        train_gradientfuzz_task.get_last_saved_model(self.model_directory))
