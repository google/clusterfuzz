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
"""Tests for corpus tagging helper functions."""

from datastore import corpus_tagging
from datastore import data_types
from tests.test_libs import helpers
from tests.test_libs import test_utils
import unittest


@test_utils.with_cloud_emulators('datastore')
class CorpusTaggingTest(unittest.TestCase):
  """Test corpus tagging helper functions."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_get_targets_with_correct_tag(self):
    """Tests get_targets_with_tag returns the correct fuzz target."""
    data_types.CorpusTag(tag='Test', fuzz_target='Test_fuzz_target').put()

    self.assertEqual(
        "Test_fuzz_target",
        list(corpus_tagging.get_targets_with_tag("Test"))[0].fuzz_target)

  def test_get_no_results_with_incorrect_tag(self):
    """Tests get_targets_with_tag returns the nothing if non match the tag."""

    self.assertEqual(0, len(list(corpus_tagging.get_targets_with_tag("Test"))))

  def test_get_all_targets_with_correct_tag(self):
    """Tests that get_targets_with tag returns all and only targets with
    matching tag."""
    data_types.CorpusTag(tag='Test', fuzz_target='Test_fuzz_target1').put()

    data_types.CorpusTag(tag='Test', fuzz_target='Test_fuzz_target2').put()

    data_types.CorpusTag(
        tag='Not The Same Tag', fuzz_target='Test_fuzz_target3').put()

    self.assertEqual(2, len(list(corpus_tagging.get_targets_with_tag("Test"))))

  def test_get_tag_from_target(self):
    """Test getting the tag of a given fuzz target."""
    data_types.CorpusTag(tag='Test', fuzz_target='Test_fuzz_target').put()

    self.assertEqual(
        "Test",
        list(corpus_tagging.get_fuzz_target_tag("Test_fuzz_target"))[0].tag)
