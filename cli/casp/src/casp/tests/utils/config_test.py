# Copyright 2025 Google LLC
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
"""Tests for config utility functions."

  For running all the tests, use (from the root of the project):
  python -m unittest discover -s cli/casp/src/casp/tests -p config_test.py -v
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from casp.utils import config as config_utils


class ConfigUtilsTest(unittest.TestCase):
  """Tests for config utility functions."""

  def setUp(self):
    """Creates a temporary directory for each test."""
    super().setUp()
    self.temp_dir = tempfile.mkdtemp()
    self.mock_config_dir = os.path.join(self.temp_dir, '.casp')
    self.mock_config_file = os.path.join(self.mock_config_dir, 'config.json')

    self.enterContext(
        patch.object(config_utils, 'CONFIG_DIR', new=self.mock_config_dir))
    self.enterContext(
        patch.object(config_utils, 'CONFIG_FILE', new=self.mock_config_file))

  def tearDown(self):
    """Removes the temporary directory after each test."""
    super().tearDown()
    shutil.rmtree(self.temp_dir)

  def test_save_config_creates_dir_and_file(self):
    """Tests that save_config creates the 
    directory and file with correct content."""
    test_data = {'key1': 'value1', 'number': 123}

    config_utils.save_config(test_data)

    self.assertTrue(os.path.isdir(self.mock_config_dir))
    self.assertTrue(os.path.isfile(self.mock_config_file))
    with open(self.mock_config_file, 'r') as f:
      saved_data = json.load(f)
    self.assertEqual(test_data, saved_data)

  def test_load_config_file_not_exists(self):
    """Tests that load_config returns an empty 
    dict if the file doesn't exist."""
    loaded_data = config_utils.load_config()

    self.assertEqual({}, loaded_data)

  def test_save_and_load_config(self):
    """Tests saving and then loading the configuration."""
    test_data = {'user': 'testuser', 'settings': {'theme': 'dark'}}

    config_utils.save_config(test_data)

    loaded_data = config_utils.load_config()

    self.assertEqual(test_data, loaded_data)

  def test_load_config_empty_file(self):
    """Tests loading an empty config file."""
    os.makedirs(self.mock_config_dir, exist_ok=True)
    with open(self.mock_config_file, 'w') as f:
      f.write('')  # Create an empty file

    with self.assertRaises(json.JSONDecodeError):
      config_utils.load_config()

  def test_load_config_malformed_json(self):
    """Tests loading a config file with invalid JSON."""

    os.makedirs(self.mock_config_dir, exist_ok=True)
    with open(self.mock_config_file, 'w') as f:
      f.write('{ "key": "value", }')  # Invalid JSON with trailing comma

    with self.assertRaises(json.JSONDecodeError):
      config_utils.load_config()

  def test_overwrite_existing_config(self):
    """Tests that saving again overwrites the existing config."""
    initial_data = {'version': 1}
    config_utils.save_config(initial_data)

    new_data = {'version': 2, 'new_key': 'new_value'}
    config_utils.save_config(new_data)

    loaded_data = config_utils.load_config()
    self.assertEqual(new_data, loaded_data)


if __name__ == '__main__':
  unittest.main()
