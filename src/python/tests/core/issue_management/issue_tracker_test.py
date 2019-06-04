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

from issue_management.issue_tracker import LabelStore

class LabelStoreTest(unittest.TestCase):
  """LabelStore tests."""

  def test_init_and_iter(self):
    """Test initializing and iterating LabelStore."""
    store = LabelStore(['label1', 'label2'])
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual([], store.removed)
    self.assertItemsEqual(['label1', 'label2'], list(store))

  def test_add(self):
    """Test adding items."""
    store = LabelStore()
    store.add('laBel1')
    self.assertItemsEqual(['laBel1'], store)
    self.assertItemsEqual(['laBel1'], store.added)
    self.assertItemsEqual([], store.removed)

    store.add('label2')
    self.assertItemsEqual(['laBel1', 'label2'], store)
    self.assertItemsEqual(['laBel1', 'label2'], store.added)
    self.assertItemsEqual([], store.removed)

    store.add('labEl2')
    self.assertItemsEqual(['laBel1', 'labEl2'], store)
    self.assertItemsEqual(['laBel1', 'labEl2'], store.added)
    self.assertItemsEqual([], store.removed)

  def test_remove(self):
    """Test removing items."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    store.remove('Label1')
    self.assertItemsEqual(['label2', 'Label3'], store)
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual(['Label1'], store.removed)

    store.remove('Label2')
    self.assertItemsEqual(['Label3'], store)
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual(['Label1', 'Label2'], store.removed)

    store.remove('LaBel2')
    self.assertItemsEqual(['Label3'], store)
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual(['Label1', 'Label2'], store.removed)

    store.remove('Label4')
    self.assertItemsEqual(['Label3'], store)
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual(['Label1', 'Label2'], store.removed)

  def test_reset(self):
    """Test reset."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    store.add('label4')
    store.add('label5')
    store.remove('label1')

    store.reset()
    self.assertItemsEqual([], store.added)
    self.assertItemsEqual([], store.removed)

  def test_remove_by_prefix(self):
    """Test remove_by_prefix."""
    store = LabelStore(['p-0', 'P-1', 'Q-2'])
    store.remove_by_prefix('p-')
    self.assertItemsEqual(['Q-2'], store)

  def test_in(self):
    """Test in operator."""
    store = LabelStore(['laBel1', 'label2', 'Label3'])
    self.assertTrue('label1' in store)
    self.assertTrue('laBel2' in store)
    self.assertTrue('labeL3' in store)
