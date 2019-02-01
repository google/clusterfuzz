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
"""Tests for stats."""

import os
import unittest

from base import utils
from bot.fuzzers.libFuzzer import stats
from system import environment
from tests.test_libs import helpers as test_helpers


class PerformanceStatsTest(unittest.TestCase):
  """Performance stats tests class."""

  def setUp(self):
    """Prepare test data and necessary env variables."""
    test_helpers.patch_environ(self)
    environment.set_value('FAIL_RETRIES', '1')
    self.data_directory = os.path.join(
        os.path.dirname(__file__), 'launcher_test_data')

  def test_parse_stats_from_merge_log(self):
    """Test parsing of a log file produced by libFuzzer run with -merge=1."""
    path = os.path.join(self.data_directory, 'merge.txt')
    lines = utils.read_data_from_file(path, eval_data=False).splitlines()
    actual_stats = stats.parse_stats_from_merge_log(lines)

    expected_stats = {
        'merge_edge_coverage': 683,
        'merge_new_files': 716,
        'merge_new_features': 1639,
    }
    self.assertEqual(expected_stats, actual_stats)
