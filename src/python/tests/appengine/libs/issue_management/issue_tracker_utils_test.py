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
"""Tests for the issue_tracker_utils module."""

import unittest

from datastore import data_types
from libs.issue_management import issue_tracker_utils


class IssueTrackerUtilsTest(unittest.TestCase):
  """Issue tracker utils tests."""

  def test_get_issue_id(self):
    """Basic test for a case when testcase is associated with a bug."""
    testcase = data_types.Testcase()
    testcase.bug_information = '1337'
    self.assertEqual('1337', issue_tracker_utils.get_issue_id(testcase))

  def test_get_issue_id_group_bug(self):
    """Test for a case when testcase is associated with a group bug."""
    testcase = data_types.Testcase()
    testcase.group_bug_information = 31337
    self.assertEqual('31337', issue_tracker_utils.get_issue_id(testcase))

  def test_get_issue_id_no_bug(self):
    """Test for a case when testcase has no bugs associated with it."""
    testcase = data_types.Testcase()
    self.assertIsNone(issue_tracker_utils.get_issue_id(testcase))
