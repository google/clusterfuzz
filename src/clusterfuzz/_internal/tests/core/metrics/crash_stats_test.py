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
"""crash_stats tests."""
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import crash_stats
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class GetLastSuccessfulHourTest(unittest.TestCase):
  """Test get_last_successful_hour."""

  def test_none(self):
    """Get none because there's no last hour."""
    self.assertIsNone(crash_stats.get_last_successful_hour())

  def test_last_hour(self):
    """Get the last hour."""
    hour2 = data_types.BuildCrashStatsJobHistory()
    hour2.end_time_in_hours = 15
    hour2.put()

    hour1 = data_types.BuildCrashStatsJobHistory()
    hour1.end_time_in_hours = 10
    hour1.put()

    self.assertEqual(15, crash_stats.get_last_successful_hour())


def bq_convert_hour_to_index(hour, time_span, remainder):
  """Convert hour to index according to the SQL."""
  return (hour - remainder) // time_span


class IndexConversionTest(unittest.TestCase):
  """Test index conversion."""

  def _test(self, end_hour):
    """Test convert back and forth."""
    time_span = 24

    remainder = crash_stats.get_remainder_for_index(end_hour, time_span)
    end_index = bq_convert_hour_to_index(end_hour, time_span, remainder)
    self.assertEqual(
        end_hour,
        crash_stats.convert_index_to_hour(end_index, time_span, remainder))

    indices = []
    for h in range(end_hour - 24 * 5 + 1, end_hour + 1):
      indices.append(bq_convert_hour_to_index(h, time_span, remainder))

    hour_blocks = []
    for index in indices:
      hour_blocks.append(
          crash_stats.convert_index_to_hour(index, time_span, remainder))

    self.assertEqual(
        ([end_hour - 24 * 4] * 24 + [end_hour - 24 * 3] * 24 +
         [end_hour - 24 * 2] * 24 + [end_hour - 24] * 24 + [end_hour] * 24),
        hour_blocks)

  def test_convert_with_non_zero_remainder(self):
    """Test non-zero remainder."""
    self._test(24 * 10 + 13)
    self._test(24 * 10 + 1)
    self._test(24 * 10 - 1)

  def test_convert_with_zero_remainder(self):
    """Test zero remainder."""
    self._test(24 * 10)
