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
"""Tests for dictionary_manager."""

import os
import unittest

from base import utils
from bot.fuzzers import dictionary_manager
from system import environment
from tests.test_libs import helpers as test_helpers


class DictionaryManagerTest(unittest.TestCase):
  """Dictionary management tests."""

  def setUp(self):
    """Initialize path for a local copy of the dictionary and other values."""
    test_helpers.patch_environ(self)
    self.data_directory = os.path.join(
        os.path.dirname(__file__), 'dictionary_manager_data')
    self.local_dict_path = os.path.join(
        self.data_directory, dictionary_manager.RECOMMENDED_DICTIONARY_FILENAME)
    environment.set_value('FAIL_RETRIES', 1)

  def tearDown(self):
    """Delete local copy of the updated dictionary. It should be auto-deleted,
    but we patch('system.shell.remove_file') while running the tests."""
    if os.path.exists(self.local_dict_path):
      os.remove(self.local_dict_path)

  def _parse_dictionary_file(self, dictionary_path):
    """Parse given dictionary file and return set of its lines."""
    data = utils.read_data_from_file(dictionary_path, eval_data=False)
    lines = [line.strip() for line in data.splitlines()]
    dictionary = set([line for line in lines if line])
    return dictionary

  def test_recommended_dictionary_parse(self):
    """Test parsing of recommended dictionary from fuzzer log."""
    dict_manager = dictionary_manager.DictionaryManager('fuzzer_name')
    log_data = utils.read_data_from_file(
        os.path.join(self.data_directory, 'log_with_recommended_dict.txt'),
        eval_data=False)

    recommended_dict = dict_manager.parse_recommended_dictionary_from_data(
        log_data)

    expected_dictionary_path = os.path.join(
        self.data_directory, 'expected_parsed_recommended_dictionary.txt')
    expected_dictionary = self._parse_dictionary_file(expected_dictionary_path)

    self.assertEqual(sorted(recommended_dict), sorted(expected_dictionary))

  def test_recommended_dictionary_merge(self):
    """Test merging with GCS copy of recommended dictionary."""
    fake_gcs_dict_path = os.path.join(self.data_directory,
                                      'fake_gcs_recommended_dictionary.txt')

    dict_manager = dictionary_manager.DictionaryManager('fuzzer_name')
    log_data = utils.read_data_from_file(
        os.path.join(self.data_directory, 'log_with_recommended_dict.txt'),
        eval_data=False)

    dict_from_log = dict_manager.parse_recommended_dictionary_from_data(
        log_data)
    utils.write_data_to_file('\n'.join(dict_from_log), self.local_dict_path)

    dictionary_manager.merge_dictionary_files(
        self.local_dict_path, fake_gcs_dict_path, self.local_dict_path)

    # Compare resulting dictionary with its expected result.
    merged_dictionary = self._parse_dictionary_file(self.local_dict_path)
    expected_dictionary_path = os.path.join(
        self.data_directory, 'expected_merged_recommended_dictionary.txt')
    expected_dictionary = self._parse_dictionary_file(expected_dictionary_path)

    self.assertEqual(sorted(merged_dictionary), sorted(expected_dictionary))

  def test_useless_dictionary_parse(self):
    """Test parsing of useless dictionary from fuzzer log."""
    dict_manager = dictionary_manager.DictionaryManager('fuzzer_name')
    log_data = utils.read_data_from_file(
        os.path.join(self.data_directory, 'log_with_useless_dict.txt'),
        eval_data=False)

    useless_dict = dict_manager.parse_useless_dictionary_from_data(log_data)

    expected_dictionary_path = os.path.join(
        self.data_directory, 'expected_parsed_useless_dictionary.txt')
    expected_dictionary = self._parse_dictionary_file(expected_dictionary_path)

    self.assertEqual(sorted(useless_dict), sorted(expected_dictionary))
