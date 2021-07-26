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
"""Tests for ML RNN generator."""

import os
import sys
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers.ml.rnn import constants
from clusterfuzz._internal.bot.fuzzers.ml.rnn import generator
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import test_utils

DATA_DIRECTORY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), 'data'))

# Parameters for the demo model.
MODEL_NAME = 'rnn'
MODEL_LAYER_SIZE = 1
MODEL_STATE_SIZE = 2


@unittest.skipIf(not os.getenv('ML_TESTS'), 'ML_TESTS=1 must be set')
@test_utils.integration
class MLRnnGeneratorIntegrationTest(unittest.TestCase):
  """ML RNN generator tests."""

  def setUp(self):
    self.model_directory = os.path.join(DATA_DIRECTORY, 'model')
    self.model_path = os.path.join(self.model_directory, MODEL_NAME)

    self.input_directory = os.path.join(DATA_DIRECTORY, 'input')
    self.output_directory = tempfile.mkdtemp()

    self.empty_directory = tempfile.mkdtemp()

  def tearDown(self):
    shell.remove_directory(self.output_directory)
    shell.remove_directory(self.empty_directory)

  def test_generate(self):
    """Test generate specified number of inputs."""
    # Set a large timeout value and a small count value to avoid timeout.
    timeout = 20
    expected_count = 2

    result = generator.run(
        self.input_directory,
        self.output_directory,
        self.model_path,
        timeout,
        generation_count=expected_count,
        hidden_state_size=MODEL_STATE_SIZE,
        hidden_layer_size=MODEL_LAYER_SIZE)

    # Process exits normally and no timeout.
    self.assertEqual(result.return_code, constants.ExitCode.SUCCESS)
    self.assertFalse(result.timed_out)

    actual_count = shell.get_directory_file_count(self.output_directory)
    self.assertEqual(expected_count, actual_count)

  def test_empty_corpus(self):
    """Test generation should abort for empty corpus."""
    # Set a large timeout value and a small count value to avoid timeout.
    timeout = 20
    expected_count = 2

    result = generator.run(
        self.empty_directory,
        self.output_directory,
        self.model_path,
        timeout,
        generation_count=expected_count,
        hidden_state_size=MODEL_STATE_SIZE,
        hidden_layer_size=MODEL_LAYER_SIZE)

    self.assertEqual(result.return_code, constants.ExitCode.CORPUS_TOO_SMALL)
    self.assertFalse(result.timed_out)

    # No new units.
    actual_count = shell.get_directory_file_count(self.output_directory)
    self.assertEqual(actual_count, 0)

  def test_invalid_model(self):
    """Test TensorFlow should throw exception if model does not match."""
    # Set a large timeout value and a small count value to avoid timeout.
    timeout = 20
    expected_count = 2

    # Change model parameters to make demo model invalid.
    invalid_state_size = 8

    result = generator.run(
        self.input_directory,
        self.output_directory,
        self.model_path,
        timeout,
        generation_count=expected_count,
        hidden_state_size=invalid_state_size,
        hidden_layer_size=MODEL_LAYER_SIZE)

    self.assertEqual(result.return_code, constants.ExitCode.TENSORFLOW_ERROR)
    self.assertFalse(result.timed_out)

    # No new units.
    actual_count = shell.get_directory_file_count(self.output_directory)
    self.assertEqual(actual_count, 0)

  @test_utils.slow
  def test_timeout(self):
    """Test timeout case in generation."""
    # Set a small timeout value and a large count value to trigger timeout.
    # Note that timeout cannot be set too small since it takes time to
    # start generator. If this test failed please increase timeout value.
    timeout = 10

    result = generator.run(
        self.input_directory,
        self.output_directory,
        self.model_path,
        timeout,
        generation_count=sys.maxsize,
        hidden_state_size=MODEL_STATE_SIZE,
        hidden_layer_size=MODEL_LAYER_SIZE)

    # Process timed out.
    self.assertNotEqual(result.return_code, constants.ExitCode.SUCCESS)
    self.assertTrue(result.timed_out)

    actual_count = shell.get_directory_file_count(self.output_directory)
    self.assertGreater(actual_count, 0)
