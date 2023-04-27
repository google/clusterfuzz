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

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import dictionary_manager
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_DIRECTORY = os.path.join(
    os.path.dirname(__file__), 'dictionary_manager_data')


class CorrectIfNeededTest(unittest.TestCase):
  """Tests for the correct_if_needed function."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.write_data_to_file',
    ])
    environment.set_value('FAIL_RETRIES', 1)

  def _validate_correction(self, input_filename, output_filename):
    full_input_filename = os.path.join(DATA_DIRECTORY, input_filename)
    dictionary_manager.correct_if_needed(full_input_filename)
    full_output_filename = os.path.join(DATA_DIRECTORY, output_filename)
    expected_output = utils.read_data_from_file(
        full_output_filename, eval_data=False).decode('utf-8')
    self.mock.write_data_to_file.assert_called_once_with(
        expected_output, full_input_filename)

  def _validate_no_action(self, input_filename):
    dictionary_manager.correct_if_needed(
        os.path.join(DATA_DIRECTORY, input_filename))
    self.assertFalse(self.mock.write_data_to_file.called)

  def test_no_action_for_valid_dict(self):
    """Ensure that we don't rewrite valid dictionaries."""
    self._validate_no_action('simple_correct_dictionary.txt')

  def test_no_action_for_complex_valid_dict(self):
    """Ensure that we don't rewrite an in-use valid dictionary."""
    self._validate_no_action('example_correct_dictionary.txt')

  def test_simple_corrections(self):
    """Ensure that we correct various classes of issues in a single dict."""
    self._validate_correction('incorrect_dictionary.txt',
                              'corrected_dictionary_expected.txt')

  def test_realworld_example(self):
    """Ensure that we can correct an in-use invalid dictionary."""
    self._validate_correction('example_invalid_dictionary.txt',
                              'example_corrected_dictionary.txt')

  def test_no_exception_on_invalid_paths(self):
    """Ensure that the function bails out on invalid file paths."""
    dictionary_manager.correct_if_needed(None)
    dictionary_manager.correct_if_needed('')
    dictionary_manager.correct_if_needed('/does/not/exist')
