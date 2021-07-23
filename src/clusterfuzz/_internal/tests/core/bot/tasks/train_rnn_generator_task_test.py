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
"""Tests for train_rnn_generator_task."""

import os
import tempfile
import unittest

import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from clusterfuzz._internal.bot.fuzzers.ml.rnn import constants
from clusterfuzz._internal.bot.tasks import train_rnn_generator_task
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

MODEL_DIR = '/fake/model_directory'

# The directory containing sample corpus.
DATA_DIRECTORY = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), os.pardir, 'fuzzers', 'ml', 'rnn', 'data'))


class GetLastSavedModelTest(fake_fs_unittest.TestCase):
  """Get latest model test."""

  def setUp(self):
    """Setup for get last saved model test."""
    # Set up fake filesystem.
    test_utils.set_up_pyfakefs(self)

    # Create model directory.
    self.fs.create_dir(MODEL_DIR)

    # Create fake index file and data file.
    # Model_1 has two complete files.
    self.model_1_data_path = os.path.join(MODEL_DIR,
                                          'model_1.data-00000-of-00001')
    self.model_1_index_path = os.path.join(MODEL_DIR, 'model_1.index')

    # Create two files for model_1.
    self.fs.create_file(self.model_1_data_path)
    self.fs.create_file(self.model_1_index_path)

    # Update timestamp.
    os.utime(self.model_1_data_path, (1330711140, 1330711160))
    os.utime(self.model_1_index_path, (1330711140, 1330711160))

    # Model_2 has two complete files.
    self.model_2_data_path = os.path.join(MODEL_DIR,
                                          'model_2.data-00000-of-00001')
    self.model_2_index_path = os.path.join(MODEL_DIR, 'model_2.index')

    # Create two files for model_2.
    self.fs.create_file(self.model_2_data_path)
    self.fs.create_file(self.model_2_index_path)

    # Update timestamp. Make sure they are newer than model_1.
    os.utime(self.model_2_data_path, (1330713340, 1330713360))
    os.utime(self.model_2_index_path, (1330713340, 1330713360))

  def test_get_latest_model(self):
    """Test latest model is returned as a dictionary."""
    # Model_2 is newer than model_1, so we will get model_2.
    model_paths = train_rnn_generator_task.get_last_saved_model(MODEL_DIR)
    expected = {
        'data': self.model_2_data_path,
        'index': self.model_2_index_path
    }
    self.assertDictEqual(model_paths, expected)

  def test_get_valid_model(self):
    """Test lastest model is not returned if it is invalid."""
    # Remove one file from model_2, so model_2 is not valid.
    os.remove(self.model_2_index_path)
    self.assertFalse(os.path.exists(self.model_2_index_path))

    # Now we should get model_1.
    model_paths = train_rnn_generator_task.get_last_saved_model(MODEL_DIR)
    expected = {
        'data': self.model_1_data_path,
        'index': self.model_1_index_path
    }
    self.assertDictEqual(model_paths, expected)

  def test_no_valid_model(self):
    """Test no model is returned if all models are invalid."""
    # Remove one file from model_1 and one from model_2.
    os.remove(self.model_1_data_path)
    os.remove(self.model_2_index_path)
    self.assertFalse(os.path.exists(self.model_1_data_path))
    self.assertFalse(os.path.exists(self.model_2_index_path))

    # Now we should get empty dictionary since both models are invalid.
    model_paths = train_rnn_generator_task.get_last_saved_model(MODEL_DIR)
    expected = {}
    self.assertDictEqual(model_paths, expected)


@test_utils.with_cloud_emulators('datastore')
class ExecuteTaskTest(unittest.TestCase):
  """Execute training script test."""

  def setUp(self):
    test_helpers.patch_environ(self)

    self.fuzzer_name = 'fake_fuzzer'
    self.full_fuzzer_name = 'libFuzzer_fake_fuzzer'
    self.job_type = 'fake_job'
    self.temp_dir = tempfile.mkdtemp()

    data_types.FuzzTarget(
        engine='libFuzzer', binary='fake_fuzzer', project='test-project').put()

    os.environ['FUZZ_INPUTS_DISK'] = self.temp_dir

    test_helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.ml_train_utils.get_corpus',
        'clusterfuzz._internal.bot.tasks.train_rnn_generator_task.train_rnn',
        'clusterfuzz._internal.bot.tasks.train_rnn_generator_task.upload_model_to_gcs',
    ])

    self.mock.get_corpus.return_value = True
    self.mock.train_rnn.return_value = new_process.ProcessResult(return_code=0)
    self.mock.upload_model_to_gcs.return_value = True

  def tearDown(self):
    shell.remove_directory(self.temp_dir)

  def test_execute(self):
    """Test execute task."""
    input_directory = os.path.join(
        self.temp_dir,
        self.fuzzer_name + train_rnn_generator_task.CORPUS_DIR_SUFFIX)
    model_directory = os.path.join(
        self.temp_dir,
        self.fuzzer_name + train_rnn_generator_task.MODEL_DIR_SUFFIX)
    log_directory = os.path.join(
        self.temp_dir,
        self.fuzzer_name + train_rnn_generator_task.LOG_DIR_SUFFIX)

    train_rnn_generator_task.execute_task(self.full_fuzzer_name, self.job_type)

    self.mock.train_rnn.assert_called_once_with(input_directory,
                                                model_directory, log_directory)


@unittest.skipIf(not os.getenv('ML_TESTS'), 'ML_TESTS=1 must be set')
@test_utils.integration
class MLRnnTrainTaskIntegrationTest(unittest.TestCase):
  """ML RNN training integration tests."""

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

  def test_train_rnn(self):
    """Test train RNN model on a simple corpus."""
    # No model exists in model directory.
    self.assertFalse(
        train_rnn_generator_task.get_last_saved_model(self.model_directory))

    # The training should be fast (a few seconds) since sample corpus is
    # extremely small.
    result = train_rnn_generator_task.train_rnn(
        self.input_directory, self.model_directory, self.log_directory,
        self.batch_size, self.hidden_state_size, self.hidden_layer_size)

    self.assertEqual(result.return_code, constants.ExitCode.SUCCESS)
    self.assertFalse(result.timed_out)

    # At least one model exists.
    self.assertTrue(
        train_rnn_generator_task.get_last_saved_model(self.model_directory))

  def test_small_corpus(self):
    """Test small corpus situation."""
    # Increase batch size so the sample corpus appears small in this case.
    self.batch_size = 100

    result = train_rnn_generator_task.train_rnn(
        self.input_directory, self.model_directory, self.log_directory,
        self.batch_size, self.hidden_state_size, self.hidden_layer_size)

    self.assertEqual(result.return_code, constants.ExitCode.CORPUS_TOO_SMALL)
    self.assertFalse(result.timed_out)

    # No model exsits after execution.
    self.assertFalse(
        train_rnn_generator_task.get_last_saved_model(self.model_directory))
