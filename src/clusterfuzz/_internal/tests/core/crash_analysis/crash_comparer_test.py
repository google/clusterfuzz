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
"""crash_comparer tests."""
import unittest

from clusterfuzz._internal.crash_analysis import crash_comparer


class CrashComparerTest(unittest.TestCase):
  """Tests CrashComparer."""

  def is_similar_helper(self, crash_state_1, crash_state_2, result=True):
    crash_comparer_instance = crash_comparer.CrashComparer(
        crash_state_1, crash_state_2)
    self.assertEqual(crash_comparer_instance.is_similar(), result)

  def test_is_similar_ascii(self):
    """Test is similar with ASCII."""
    crash_state_1 = (
        'start <= end ('
        'SAMP"0AA0AA00AAA0A00A0A0"@offsetInAnchor[19]) in TextIterator.cpp\n'
        'blink::TextIteratorAlgorithm<blink::EditingAlgorithm<blink::'
        'NodeTraversal> >::Te\n'
        'blink::PlainText\n')
    crash_state_2 = (
        'start <= end ('
        '#text "ABOUT US"@offsetInAnchor[0] vs. TABLE class="clash"@offsetI\n'
        'blink::TextIteratorAlgorithm<blink::EditingAlgorithm<blink::'
        'FlatTreeTraversal> >\n'
        'blink::PlainText\n')
    self.is_similar_helper(crash_state_1, crash_state_2, True)

  def test_is_similar_unicode(self):
    """Test is similar with unicode."""
    crash_state_1 = (
        'view_it != guest_view_registry_.end().Invalid GuestView created of '
        'type "V90P\n'
        'guest_view::GuestViewManager::ViewCreated\n'
        'guest_view::GuestViewMessageFilter::OnViewCreated\n')
    crash_state_2 = (
        'view_it != guest_view_registry_.end().Invalid GuestView created of '
        'type "_< i\n'
        'guest_view::GuestViewManager::ViewCreated\n'
        'guest_view::GuestViewMessageFilter::OnViewCreated\n')
    self.is_similar_helper(crash_state_1, crash_state_2, True)

  def test_is_not_similar(self):
    """Test not is similar."""
    crash_state_1 = (
        'start <= end ('
        'SAMP"0AA0AA00AAA0A00A0A0"@offsetInAnchor[19]) in TextIterator.cpp\n'
        'blink::TextIteratorAlgorithm<blink::EditingAlgorithm<blink::'
        'NodeTraversal> >::Te\n'
        'blink::PlainText\n')
    crash_state_2 = ('false in gles2_cmd_utils.cc\n'
                     'base::debug::DebugBreak\n'
                     'gpu::gles2::GLES2Util::GLFaceTargetToTextureTarget\n')
    self.is_similar_helper(crash_state_1, crash_state_2, False)

  def test_is_similar_shifted(self):
    """Test similar when frames have shifted slightly."""
    crash_state_1 = 'first\nsecond\nthird\n'
    crash_state_2 = 'second\nthird\nfourth\n'
    self.is_similar_helper(crash_state_1, crash_state_2, True)

    crash_state_2 = 'first\nthird\nfourth'
    self.is_similar_helper(crash_state_1, crash_state_2, True)

    crash_state_2 = 'first\nsecond\nfourth'
    self.is_similar_helper(crash_state_1, crash_state_2, True)

    crash_state_2 = 'first\nthird'
    self.is_similar_helper(crash_state_1, crash_state_2, True)

    crash_state_2 = 'other\nsecond\nthird'
    self.is_similar_helper(crash_state_1, crash_state_2, True)

  def test_only_one_frame_matching(self):
    """Test not similar when 1/3 frames match."""
    crash_state_1 = 'first\nsecond\nthird\n'
    crash_state_2 = 'second\nfourth\nfifth\n'
    self.is_similar_helper(crash_state_1, crash_state_2, False)

    crash_state_2 = 'first\nfourth\nfifth\n'
    self.is_similar_helper(crash_state_1, crash_state_2, False)

  def test_is_same_frames_wrong_order(self):
    """Test not similar when some frames match but the order doesn't match."""
    crash_state_1 = 'first\nsecond\nthird\n'
    crash_state_2 = 'second\nfirst\nfourth\n'
    self.is_similar_helper(crash_state_1, crash_state_2, False)

    crash_state_2 = 'third\nsecond\nfirst\n'
    self.is_similar_helper(crash_state_1, crash_state_2, False)
