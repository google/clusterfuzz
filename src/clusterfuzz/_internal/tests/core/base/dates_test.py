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
"""Tests for dates module."""

import datetime
import unittest

from clusterfuzz._internal.base import dates


class DatesTest(unittest.TestCase):
  """Tests for date utility functions."""

  def test_time_has_expired_true(self):
    """Test that time_has_expired returns True when timestamp is older."""
    now = datetime.datetime(2026, 1, 1, 12, 0, 0)
    past = datetime.datetime(2026, 1, 1, 11, 0, 0)
    self.assertTrue(dates.time_has_expired(past, compare_to=now, seconds=1800))
    self.assertTrue(dates.time_has_expired(past, compare_to=now, minutes=30))

  def test_time_has_expired_false(self):
    """Test that time_has_expired returns False when timestamp is recent."""
    now = datetime.datetime(2026, 1, 1, 12, 0, 0)
    past = datetime.datetime(2026, 1, 1, 11, 30, 0)
    self.assertFalse(dates.time_has_expired(past, compare_to=now, hours=1))
    self.assertFalse(dates.time_has_expired(past, compare_to=now, days=1))

  def test_initialize_timezone_from_environment(self):
    """Test initialize_timezone_from_environment execution."""
    dates.initialize_timezone_from_environment()
