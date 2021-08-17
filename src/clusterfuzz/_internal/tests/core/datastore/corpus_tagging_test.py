# Copyright 2020 Google LLC
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

import unittest

from clusterfuzz._internal.datastore import corpus_tagging
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class CorpusTaggingTest(unittest.TestCase):
  """Test corpus tagging helper functions."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_get_targets_with_correct_tag(self):
    """Tests get_targets_with_tag returns the correct fuzz target."""
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()

    self.assertEqual(
        'test_fuzz_target',
        corpus_tagging.get_targets_with_tag('test_tag')[0]
        .fully_qualified_fuzz_target_name)

  def test_get_no_results_with_incorrect_tag(self):
    """Tests get_targets_with_tag returns the nothing if non match the tag."""

    self.assertEqual(0, len(corpus_tagging.get_targets_with_tag('test_tag')))

  def test_get_all_targets_with_correct_tag(self):
    """Tests that get_targets_with tag returns all and only targets with
    matching tag."""
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target1').put()

    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target2').put()

    data_types.CorpusTag(
        tag='not_the_same_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target3').put()

    self.assertEqual(2, len(corpus_tagging.get_targets_with_tag('test_tag')))

  def test_get_target_with_correct_tag_when_target_has_multiple_tags(self):
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()
    data_types.CorpusTag(
        tag='test_tag2',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()

    self.assertEqual(
        'test_fuzz_target',
        corpus_tagging.get_targets_with_tag('test_tag')[0]
        .fully_qualified_fuzz_target_name)

  def test_get_tag_from_target_with_one_tag(self):
    """Test getting the tag of a given fuzz target."""
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()

    self.assertEqual(
        'test_tag',
        corpus_tagging.get_fuzz_target_tags('test_fuzz_target')[0].tag)

  def test_get_tags_from_target_with_multiple_tags(self):
    """Test getting the tags of a given fuzz target with more than one tag."""
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()
    data_types.CorpusTag(
        tag='test_tag2',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()

    tags = [
        i.tag for i in corpus_tagging.get_fuzz_target_tags('test_fuzz_target')
    ]

    self.assertEqual(tags, ['test_tag', 'test_tag2'])

  def test_get_similarly_tagged_fuzzers_returns_empty_on_no_matches(self):
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()
    data_types.CorpusTag(
        tag='test_tag2',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()

    self.assertEqual(
        {}, corpus_tagging.get_similarly_tagged_fuzzers('test_fuzz_target'))

  def test_get_similarly_tagged_fuzzers_returns_with_correct_values(self):
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target').put()
    data_types.CorpusTag(
        tag='test_tag',
        fully_qualified_fuzz_target_name='test_fuzz_target_2').put()

    self.assertEqual({
        'test_tag': ['test_fuzz_target_2']
    }, corpus_tagging.get_similarly_tagged_fuzzers('test_fuzz_target'))
