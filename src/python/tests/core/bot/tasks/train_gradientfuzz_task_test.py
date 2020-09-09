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
"""Tests for train_gradientfuzz_task.py."""

import glob
import json
import os
import tempfile
import unittest

import numpy as np
import tensorflow as tf

from bot.fuzzers.ml.gradientfuzz import constants
from bot.fuzzers.ml.gradientfuzz import models
from bot.fuzzers.ml.gradientfuzz import run_constants
from bot.tasks import train_gradientfuzz_task
from system import new_process
from system import shell
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils

# Directory for testing files.
GRADIENTFUZZ_TESTING_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'fuzzers', 'ml',
        'gradientfuzz'))

# Small, precompiled fuzz target.
TESTING_BINARY = 'zlib_uncompress_sample_fuzzer'

# Tiny sample corpus.
TESTING_CORPUS_DIR = 'sample_corpus'

# We should keep around 78 inputs from small sample corpus after pruning.
TEST_NUM_INPUTS = 75


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

    os.environ['FUZZ_INPUTS_DISK'] = self.temp_dir
    os.environ['GRADIENTFUZZ_TESTING'] = str(True)

    test_helpers.patch(self, [
        'bot.tasks.ml_train_utils.get_corpus',
        'bot.tasks.train_gradientfuzz_task.gen_inputs_labels',
        'bot.tasks.train_gradientfuzz_task.train_gradientfuzz',
        'bot.tasks.train_gradientfuzz_task.upload_model_to_gcs',
        'build_management.build_manager.setup_build',
    ])

    self.mock.get_corpus.return_value = True
    self.mock.gen_inputs_labels.return_value = new_process.ProcessResult(
        return_code=0), self.dataset_name
    self.mock.train_gradientfuzz.return_value = new_process.ProcessResult(
        return_code=0), self.run_name
    self.mock.upload_model_to_gcs.return_value = True
    self.mock.setup_build.side_effect = self.mock_build_manager

    # Fakes creating directory tree.
    self.fake_dataset_dir = os.path.join(self.data_dir, self.dataset_name)
    self.fake_model_dir = os.path.join(
        self.models_dir, constants.NEUZZ_ONE_HIDDEN_LAYER_MODEL, self.run_name)
    os.makedirs(self.fake_dataset_dir)
    os.makedirs(self.fake_model_dir)

  def mock_build_manager(self):
    """
    Just sets the 'APP_PATH' environment variable.
    """
    os.environ['APP_PATH'] = self.binary_path

  def tearDown(self):
    shell.remove_directory(self.temp_dir)
    shell.remove_directory(self.models_dir)
    shell.remove_directory(self.data_dir)

  def test_execute(self):
    """Test execute task."""
    corpus_dir = os.path.join(self.temp_dir, run_constants.CORPUS_DIR,
                              self.fuzzer_name + run_constants.CORPUS_SUFFIX)
    train_gradientfuzz_task.execute_task(self.fuzzer_name, self.job_type)

    self.mock.gen_inputs_labels.assert_called_once_with(corpus_dir,
                                                        self.binary_path)
    self.mock.train_gradientfuzz.assert_called_once_with(
        self.fuzzer_name, 'fake_dataset', 0, True)
    self.mock.upload_model_to_gcs.assert_called_once_with(
        self.fake_model_dir, self.fuzzer_name)


@test_utils.integration
class GenerateInputsIntegration(unittest.TestCase):
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

    os.environ['GRADIENTFUZZ_TESTING'] = str(True)

  def tearDown(self):
    shell.remove_directory(os.path.join(self.home_dir, constants.DATASET_DIR))

  def check_all_same_lengths(self, files):
    standard_length = None
    for input_file in glob.glob(files):
      input_length = len(np.load(input_file))
      if standard_length is None:
        standard_length = input_length
      self.assertTrue(standard_length == input_length)

  def check_num_files(self, inputs, labels):
    self.assertTrue(len(glob.glob(inputs)) >= TEST_NUM_INPUTS)
    self.assertTrue(len(glob.glob(inputs)) == len(glob.glob(labels)))

  def test_gen_inputs_labels(self):
    """
    Generates input/label pairs using a tiny corpus and
    pre-compiled binary.
    """
    _, _ = train_gradientfuzz_task.gen_inputs_labels(self.corpus_dir,
                                                     self.binary_path)

    # Asserts that directories were created.
    inputs = os.path.join(self.dataset_dir, constants.STANDARD_INPUT_DIR, '*')
    labels = os.path.join(self.dataset_dir, constants.STANDARD_LABEL_DIR, '*')
    self.assertTrue(os.path.isdir(self.dataset_dir))

    # Ensures that number of files was correctly generated.
    self.check_num_files(inputs, labels)

    # Checks lengths of generated files.
    self.check_all_same_lengths(inputs)
    self.check_all_same_lengths(labels)


@test_utils.integration
class GradientFuzzTrainTaskIntegrationTest(unittest.TestCase):
  """
  Tests all of execute_task() except GCS functionality.
  """

  def setUp(self):
    self.fuzzer_name = 'dummy_fuzzer'
    self.job_type = 'dummy_job'
    self.home_dir = train_gradientfuzz_task.GRADIENTFUZZ_SCRIPTS_DIR
    self.corpus_dir = os.path.join(GRADIENTFUZZ_TESTING_DIR, TESTING_CORPUS_DIR)
    self.dataset_dir = os.path.join(
        self.home_dir, constants.DATASET_DIR,
        self.fuzzer_name + run_constants.CORPUS_SUFFIX)
    self.run_dir = os.path.join(
        self.home_dir, constants.MODEL_DIR,
        constants.NEUZZ_ONE_HIDDEN_LAYER_MODEL,
        self.fuzzer_name + run_constants.RUN_NAME_SUFFIX)
    self.temp_dir = tempfile.mkdtemp()
    self.binary_path = os.path.join(GRADIENTFUZZ_TESTING_DIR, TESTING_BINARY)

    os.environ['FUZZ_INPUTS_DISK'] = self.temp_dir
    os.environ['GRADIENTFUZZ_TESTING'] = str(True)

    test_helpers.patch(self, [
        'bot.tasks.ml_train_utils.get_corpus',
        'bot.tasks.train_gradientfuzz_task.upload_model_to_gcs',
        'build_management.build_manager.setup_build'
    ])

    self.mock.upload_model_to_gcs.return_value = True
    self.mock.get_corpus.side_effect = self.mock_get_corpus
    self.mock.setup_build.side_effect = self.mock_build_manager

  def mock_build_manager(self):
    """
    Just sets the 'APP_PATH' environment variable.
    """
    os.environ['APP_PATH'] = self.binary_path

  def mock_get_corpus(self, corpus_directory, _):
    """
    Copy over training corpus to temp dir.
    """
    train_files = glob.glob(os.path.join(self.corpus_dir, '*'))
    for train_file in train_files:
      target_path = os.path.join(corpus_directory, os.path.basename(train_file))
      self.assertTrue(shell.copy_file(train_file, target_path))
    return True

  def tearDown(self):
    shell.remove_directory(os.path.join(self.home_dir, constants.DATASET_DIR))
    shell.remove_directory(os.path.join(self.home_dir, constants.MODEL_DIR))
    shell.remove_directory(os.path.join(self.home_dir, constants.GENERATED_DIR))
    shell.remove_directory(self.temp_dir)

  def test_train_gradientfuzz(self):
    """
    Generate input/output pairs, then train GradientFuzz
    model on a simple corpus.
    """
    train_gradientfuzz_task.execute_task(self.fuzzer_name, self.job_type)

    # Asserts that directories were created.
    inputs = os.path.join(self.dataset_dir, constants.STANDARD_INPUT_DIR)
    labels = os.path.join(self.dataset_dir, constants.STANDARD_LABEL_DIR)
    self.assertTrue(os.path.isdir(inputs))
    self.assertTrue(os.path.isdir(labels))
    self.assertTrue(os.path.isdir(self.run_dir))

    # Attempts to load in latest model.
    ckpt_path = tf.train.latest_checkpoint(self.run_dir)
    model_config_path = os.path.join(self.run_dir, constants.CONFIG_FILENAME)
    model_config = json.load(open(model_config_path, 'r'))
    model = models.make_model_from_layer(
        constants.ARCHITECTURE_MAP[model_config['architecture']],
        model_config['output_dim'],
        model_config['input_shape'],
        hidden_layer_dim=model_config['num_hidden'])
    model.load_weights(ckpt_path).expect_partial()
