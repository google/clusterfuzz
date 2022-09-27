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

  def _make_attributes(self,
                       testcase_id,
                       one_time_crasher_flag,
                       issue_id,
                       group_id,
                       time_in_second,
                       job_type=None,
                       security_flag=None):
    """Make testcase attributes for test."""
    attributes = grouper.TestcaseAttributes(testcase_id)
    attributes.is_leader = False
    attributes.one_time_crasher_flag = one_time_crasher_flag
    attributes.issue_id = issue_id
    attributes.group_id = group_id
    attributes.timestamp = datetime.datetime.utcfromtimestamp(time_in_second)
    attributes.job_type = job_type
    attributes.security_flag = security_flag

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

  def test_asan_over_anything_else(self):
    """Test choosing ASAN over other sanitizers in job_type."""
    testcase_map = {
        1:
            self._make_attributes(1, False, '10', 33, 10,
                                  'some_engine_asan_proj', True),
        2:
            self._make_attributes(2, False, None, 33, 9,
                                  'some_engine_ubsan_proj', True),
        3:
            self._make_attributes(3, False, '10', 33, 8,
                                  'some_engine_msan_proj'),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[1].is_leader)
    self.assertFalse(testcase_map[2].is_leader)
    self.assertFalse(testcase_map[3].is_leader)

  def test_security_over_non_security(self):
    """Test choosing security crash over non-security."""
    testcase_map = {
        1: self._make_attributes(1, False, '10', 33, 10, 'some_job', True),
        2: self._make_attributes(2, False, '11', 33, 9, 'some_job', False),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[1].is_leader)
    self.assertFalse(testcase_map[2].is_leader)

  def test_not_choosing_i386(self):
    """Test not choosing an i386 issue as leader"""
    testcase_map = {
        1:
            self._make_attributes(1, True, '10', 33, 10,
                                  'some_engine_asan_proj_i386', True),
        2:
            self._make_attributes(2, False, None, 33, 9,
                                  'some_engine_ubsan_proj', True),
        3:
            self._make_attributes(3, False, '10', 33, 8,
                                  'some_engine_asan_proj'),
    }
    group_leader.choose(testcase_map)
    print(testcase_map[1].is_leader)
    self.assertTrue(testcase_map[3].is_leader)
    self.assertFalse(testcase_map[2].is_leader)
    self.assertFalse(testcase_map[1].is_leader)

  def test_reproducible_over_non_reproducible(self):
    """Test choosing reproducible non-security bug over non-reproducinble security bug"""
    testcase_map = {
        1: self._make_attributes(1, True, None, 33, 10, 'some_job', True),
        2: self._make_attributes(2, False, None, 33, 9, 'some_job', False),
    }
    group_leader.choose(testcase_map)

    self.assertTrue(testcase_map[2].is_leader)
    self.assertFalse(testcase_map[1].is_leader)
