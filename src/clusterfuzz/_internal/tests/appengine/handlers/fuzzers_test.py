# Copyright 2026 Google LLC
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
"""Tests for fuzzers handler."""
# pylint: disable=protected-access

import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from handlers import fuzzers


class BaseEditHandlerTest(unittest.TestCase):
  """Test BaseEditHandler."""

  def setUp(self):
    self.handler = fuzzers.BaseEditHandler()

  def test_get_fuzzer_state_str(self):
    """Test that fuzzer state str excludes specific fields."""
    fuzzer = data_types.Fuzzer(
        name='test_fuzzer',
        revision=1,
        timeout=10,
        result='bad',
        console_output='some output',
        result_timestamp=datetime.datetime(2021, 1, 1),
        return_code=1,
        sample_testcase='testcase',
        stats_columns='cols',
        stats_column_descriptions='desc',
    )

    state_str = self.handler._get_fuzzer_state_str(fuzzer)

    self.assertIn('name: test_fuzzer', state_str)
    self.assertIn('revision: 1', state_str)
    self.assertIn('timeout: 10', state_str)

    # Explicitly excluded fields
    self.assertNotIn('result:', state_str)
    self.assertNotIn('result_timestamp', state_str)
    self.assertNotIn('console_output:', state_str)
    self.assertNotIn('return_code:', state_str)
    self.assertNotIn('sample_testcase:', state_str)
    self.assertNotIn('stats_columns:', state_str)
    self.assertNotIn('stats_column_descriptions:', state_str)
