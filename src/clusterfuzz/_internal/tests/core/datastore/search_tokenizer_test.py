# -*- coding: utf-8 -*-
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
"""search_tokenizer tests."""
# pylint: disable=protected-access
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import search_tokenizer


class ComplexTokenizeTest(unittest.TestCase):
  """Test _complex_tokenize(..)."""

  def test_empty(self):
    """Test empty string."""
    self.assertSetEqual(set(), search_tokenizer._complex_tokenize('', 3))

  def test_one_token(self):
    """Test one token."""
    self.assertSetEqual(
        set(['abcd']), search_tokenizer._complex_tokenize('abcd', 3))

  def test_multiple_tokens(self):
    """Test multiple tokens."""
    self.assertSetEqual(
        set([
            'abcd', 'abcd::edfg', 'abcd::edfghijk', 'edfg', 'edfghijk', 'hijk'
        ]), search_tokenizer._complex_tokenize('abcd::edfgHijk', 3))

  def test_multple_tokens_with_empty_tokens(self):
    """Test multiple tokens with empty tokens."""
    self.assertSetEqual(
        set([
            '::abcd', '::abcd::edfg', '::abcd::edfghijk', '::abcd::edfghijk::',
            'abcd', 'abcd::edfg', 'abcd::edfghijk', 'abcd::edfghijk::', 'edfg',
            'edfghijk', 'hijk', 'edfghijk::', 'hijk::'
        ]), search_tokenizer._complex_tokenize('::abcd::edfgHijk::', 5))

  def test_real_example(self):
    """Test real example."""
    crash_state = 'void WTF::Vector<blink::Member, 64ul'
    expected = set([
        'void',
        'void wtf',
        'void wtf::vector',
        'void wtf::vector<blink',
        'void wtf::vector<blink::member',
        'void wtf::vector<blink::member, 64ul',
        'wtf',
        'wtf::vector',
        'wtf::vector<blink',
        'wtf::vector<blink::member',
        'wtf::vector<blink::member, 64ul',
        'vector',
        'vector<blink',
        'vector<blink::member',
        'vector<blink::member, 64ul',
        'blink',
        'blink::member',
        'blink::member, 64ul',
        'member',
        'member, 64ul',
        '64ul',
    ])
    self.assertSetEqual(expected,
                        search_tokenizer._complex_tokenize(crash_state, 6))

  def test_duplicate(self):
    """Test duplicate tokens."""
    crash_state = 'a:b:a:b'
    expected = set(['a', 'b', 'a:b', 'a:b:a', 'a:b:a:b', 'b:a', 'b:a:b'])
    self.assertSetEqual(expected,
                        search_tokenizer._complex_tokenize(crash_state, 4))

  def test_exceed_limit(self):
    """Test exceeding limit."""
    crash_state = 'a:b:c'
    expected = set(['a', 'b', 'c', 'a:b', 'b:c'])
    self.assertSetEqual(expected,
                        search_tokenizer._complex_tokenize(crash_state, 2))


class TokenizeBugInformationTest(unittest.TestCase):
  """Test tokenize_bug_information(..)."""

  def test_none(self):
    """Test none."""
    testcase = data_types.Testcase()
    testcase.bug_information = None
    testcase.group_bug_information = None
    self.assertListEqual([],
                         search_tokenizer.tokenize_bug_information(testcase))

  def test_empty(self):
    """Test empty."""
    testcase = data_types.Testcase()
    testcase.bug_information = ''
    testcase.group_bug_information = 0
    self.assertListEqual([],
                         search_tokenizer.tokenize_bug_information(testcase))

  def test_tokenize(self):
    """Test tokenize."""
    testcase = data_types.Testcase()
    testcase.bug_information = '123'
    testcase.group_bug_information = 456
    self.assertListEqual(['123', '456'],
                         search_tokenizer.tokenize_bug_information(testcase))


class TokenizeImpactVersionTest(unittest.TestCase):
  """Test tokenize_impact(..)."""

  def test_empty(self):
    """Test empty."""
    self.assertEqual([], search_tokenizer.tokenize_impact_version(''))
    self.assertEqual([], search_tokenizer.tokenize_impact_version(None))

  def test_version(self):
    """Test tokenising version."""
    self.assertEqual(['52'], search_tokenizer.tokenize_impact_version('52'))
    self.assertSetEqual(
        set(['52', '52.1', '52.1.2', '52.1.2.3']),
        set(search_tokenizer.tokenize_impact_version('52.1.2.3')))


class TokenizeTest(unittest.TestCase):
  """Test tokenize(..)."""

  def test_empty(self):
    """Test empty string."""
    self.assertSetEqual(set(), search_tokenizer.tokenize(''))

  def test_non_string(self):
    """Test non string."""
    self.assertSetEqual(set(['123']), search_tokenizer.tokenize(123))
    self.assertSetEqual(set(['true']), search_tokenizer.tokenize(True))
    self.assertSetEqual(set([]), search_tokenizer.tokenize(None))

  def test_non_ascii(self):
    s = 'IsString ¿ÓÞÎ¤ utf'
    self.assertSetEqual(
        set([
            'is', 'string', 'utf', 'isstring', 'isstring utf', 'string utf',
            s.lower()
        ]), search_tokenizer.tokenize(s))

  def test_real_example(self):
    """Test real example."""
    crash_states = '\n'.join([
        'track 1 fast;',
        'android.media.MediaCodec.native_setup',
    ])
    expected = set([
        'track',
        '1',
        'fast',
        'android',
        'media',
        'codec',
        'native',
        'setup',
        'track 1',
        'track 1 fast',
        'track 1 fast;',
        '1 fast',
        '1 fast;',
        'fast;',
        'android.media',
        'android.media.media',
        'android.media.mediacodec',
        'android.media.mediacodec.native',
        'android.media.mediacodec.native_setup',
        'media.media',
        'media.mediacodec',
        'media.mediacodec.native',
        'media.mediacodec.native_setup',
        'mediacodec',
        'mediacodec.native',
        'mediacodec.native_setup',
        'codec.native',
        'codec.native_setup',
        'native_setup',
    ])
    self.assertSetEqual(expected, search_tokenizer.tokenize(crash_states))
