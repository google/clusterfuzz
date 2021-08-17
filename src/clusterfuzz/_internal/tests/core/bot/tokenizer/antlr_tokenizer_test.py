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
"""Tests for the Antlr Tokenizer."""

import unittest

from clusterfuzz._internal.bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from clusterfuzz._internal.bot.tokenizer.grammars.JavaScriptLexer import \
    JavaScriptLexer


class AntlrTokenizerTest(unittest.TestCase):
  """Tests for AntlrTokenizer"""

  def test_empty_list_on_empty_data(self):
    """Test Tokenizer works on empty list"""
    tokenizer = AntlrTokenizer(JavaScriptLexer)
    data = b''

    tokens = tokenizer.tokenize(data)

    self.assertEqual(tokens, [])

  def test_tokenize_simple_js_file(self):
    """Test tokenizer works with sample JS"""
    tokenizer = AntlrTokenizer(JavaScriptLexer)
    txt = b"""async function process(array) {
          for await (let i of array) {
              doSomething(i);
            }
          }"""

    tokens = tokenizer.tokenize(txt)
    self.assertEqual(tokens, [
        'async', ' ', 'function', ' ', 'process', '(', 'array', ')', ' ', '{',
        '\n', '          ', 'for', ' ', 'await', ' ', '(', 'let', ' ', 'i', ' ',
        'of', ' ', 'array', ')', ' ', '{', '\n', '              ',
        'doSomething', '(', 'i', ')', ';', '\n', '            ', '}', '\n',
        '          ', '}'
    ])

  def test_combine_same_as_orig(self):
    """Tests the token combiner"""
    tokenizer = AntlrTokenizer(JavaScriptLexer)
    txt = b"""async function process(array) {
          for await (let i of array) {
              doSomething(i);
            }
          }"""

    tokens = tokenizer.tokenize(txt)

    self.assertEqual(tokenizer.combine(tokens), txt)

  def test_tokenizes_malformed_without_error(self):
    """Tests tokenizer doesnt error on garbage input"""
    tokenizer = AntlrTokenizer(JavaScriptLexer)
    txt = b'aasdfj1  1jhsdf9 1 3@ 1 + => adj 193'

    tokens = tokenizer.tokenize(txt)
    self.assertEqual(tokens, [
        'aasdfj1', '  ', '1', 'jhsdf9', ' ', '1', ' ', '3', '@', ' ', '1', ' ',
        '+', ' ', '=>', ' ', 'adj', ' ', '193'
    ])
