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
"""Tests for the issue_tracker module."""

import unittest

import mock
import six

from libs.issue_management.issue_tracker import IssueTracker
from libs.issue_management.issue_tracker import LabelStore


class LabelStoreTest(unittest.TestCase):
  """LabelStore tests."""

  def test_init_and_iter(self):
    """Test initializing and iterating LabelStore."""
    store = LabelStore(['label1', 'label2'])
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, [], store.removed)
    six.assertCountEqual(self, ['label1', 'label2'], list(store))

  def test_add(self):
    """Test adding items."""
    store = LabelStore()
    store.add('laBel1')
    six.assertCountEqual(self, ['laBel1'], store)
    six.assertCountEqual(self, ['laBel1'], store.added)
    six.assertCountEqual(self, [], store.removed)

    store.add('label2')
    six.assertCountEqual(self, ['laBel1', 'label2'], store)
    six.assertCountEqual(self, ['laBel1', 'label2'], store.added)
    six.assertCountEqual(self, [], store.removed)

    store.add('labEl2')
    six.assertCountEqual(self, ['laBel1', 'labEl2'], store)
    six.assertCountEqual(self, ['laBel1', 'labEl2'], store.added)
    six.assertCountEqual(self, [], store.removed)

  def test_remove(self):
    """Test removing items."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    store.remove('Label1')
    six.assertCountEqual(self, ['label2', 'Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, ['Label1'], store.removed)

    store.remove('Label2')
    six.assertCountEqual(self, ['Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, ['Label1', 'Label2'], store.removed)

    store.remove('LaBel2')
    six.assertCountEqual(self, ['Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, ['Label1', 'Label2'], store.removed)

    store.remove('Label4')
    six.assertCountEqual(self, ['Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, ['Label1', 'Label2'], store.removed)

  def test_add_and_remove(self):
    """Test both adding and removing."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    store.remove('Label1')
    six.assertCountEqual(self, ['label2', 'Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, ['Label1'], store.removed)

    store.add('label1')
    six.assertCountEqual(self, ['label1', 'label2', 'Label3'], store)
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, [], store.removed)

    store.remove('Label1')
    store.add('label4')
    six.assertCountEqual(self, ['label2', 'Label3', 'label4'], store)
    six.assertCountEqual(self, ['label4'], store.added)
    six.assertCountEqual(self, ['Label1'], store.removed)

  def test_reset(self):
    """Test reset."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    store.add('label4')
    store.add('label5')
    store.remove('label1')

    store.reset_tracking()
    six.assertCountEqual(self, [], store.added)
    six.assertCountEqual(self, [], store.removed)

  def test_remove_by_prefix(self):
    """Test remove_by_prefix."""
    store = LabelStore(['p-0', 'P-1', 'Q-2'])
    store.remove_by_prefix('p-')
    six.assertCountEqual(self, ['Q-2'], store)

  def test_in(self):
    """Test in operator."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    self.assertTrue('label1' in store)
    self.assertTrue('laBel2' in store)
    self.assertTrue('labeL3' in store)
    self.assertFalse('label' in store)


class TestIssueTracker(IssueTracker):
  """Test issue tracker."""

  def __init__(self):
    self.issues = {}

  def get_issue(self, issue_id):
    return self.issues.get(str(issue_id))


class GetOriginalIssueTest(unittest.TestCase):
  """Tests for get_original_issue."""

  def setUp(self):
    self.issue_tracker = TestIssueTracker()
    self.issue_tracker.issues = {
        '1': mock.Mock(id=1, merged_into=2),
        '2': mock.Mock(id=2, merged_into=3),
        '3': mock.Mock(id=3, merged_into=None),
        '4': mock.Mock(id=4, merged_into=4),
        '5': mock.Mock(id=5, merged_into=6),
        '6': mock.Mock(id=6, merged_into=5),
    }

  def test_basic(self):
    """Basic tests."""
    self.assertEqual(3, self.issue_tracker.get_original_issue(1).id)
    self.assertEqual(3, self.issue_tracker.get_original_issue(2).id)
    self.assertEqual(3, self.issue_tracker.get_original_issue(3).id)

  def test_circular_merge(self):
    """Test circular merge."""
    self.assertEqual(4, self.issue_tracker.get_original_issue(4).id)
    self.assertEqual(6, self.issue_tracker.get_original_issue(5).id)
    self.assertEqual(5, self.issue_tracker.get_original_issue(6).id)
