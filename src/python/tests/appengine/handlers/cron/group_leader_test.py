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
"""group_leader tests."""
import datetime
import unittest

from handlers.cron import group_leader
from handlers.cron import grouper


class GroupLeaderTest(unittest.TestCase):
  """Test chooseLeaders."""

  def test_empty(self):
    """Test empty."""
    testcase_map = {}
    group_leader.choose(testcase_map)
    self.assertDictEqual({}, testcase_map)

  def _make_attributes(self, testcase_id, one_time_crasher_flag, issue_id,
                       group_id, time_in_second):
    attributes = grouper.TestcaseAttributes(testcase_id)
    attributes.is_leader = False
    attributes.one_time_crasher_flag = one_time_crasher_flag
    attributes.issue_id = issue_id
    attributes.group_id = group_id
    attributes.timestamp = datetime.datetime.utcfromtimestamp(time_in_second)

    return attributes

  def test_most_recent(self):
    """Test choosing most recent when there's no high-quality testcase."""
    testcase_map = {
        1: self._make_attributes(1, True, None, 11, 10),
        2: self._make_attributes(2, True, None, 11, 1),
        3: self._make_attributes(3, True, None, 22, 10),
        4: self._make_attributes(4, True, None, 22, 1)
    }
    group_leader.choose(testcase_map)
    self.assertTrue(testcase_map[1].is_leader)
    self.assertFalse(testcase_map[2].is_leader)
    self.assertTrue(testcase_map[3].is_leader)
    self.assertFalse(testcase_map[4].is_leader)

  def test_choose_reproducible(self):
    """Test choosing being reproducible over nothing."""
    testcase_map = {
        1: self._make_attributes(1, True, None, 11, 10),
        2: self._make_attributes(2, False, None, 11, 1),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[2].is_leader)
    self.assertFalse(testcase_map[1].is_leader)

  def test_choose_has_issue_over_reproducible(self):
    """Test choosing having issue over being reproducible."""
    testcase_map = {
        1: self._make_attributes(1, False, None, 22, 10),
        2: self._make_attributes(2, True, '9', 22, 1),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[2].is_leader)
    self.assertFalse(testcase_map[1].is_leader)

  def test_choose_has_issue_and_reproducible_over_anything_else(self):
    """Test choosing having issue and being reproducible over anything else
      e.g. having issue but not reproducible."""
    testcase_map = {
        1: self._make_attributes(1, True, '10', 33, 10),
        2: self._make_attributes(2, False, None, 33, 9),
        3: self._make_attributes(3, False, '10', 33, 8),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[3].is_leader)
    self.assertFalse(testcase_map[1].is_leader)
    self.assertFalse(testcase_map[2].is_leader)
