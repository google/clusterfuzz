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
"""Antlr Tokenizer"""

from builtins import object
import antlr4


class AntlrTokenizer(object):
  """Tokenizer. Takes an Antlr Lexer created using
  $ antlr4 -Dlanguage=Pythonn <AntlrGrammar.g4>
  and allows user to tokenize files using that grammar."""

  def __init__(self, lexer):
    self._lexer = lexer

  def fill(self, stream):
    """Helper function. antlr4.CommonTokenStream.fill should work, but
    it does not fetch all of the tokens. This is a replacement that works."""
    i = 0
    while stream.fetch(1):
      i += 1
    return i

  def tokenize(self, data):
    """Takes in a file and uses the antlr lexer to return a list of tokens"""
    lexer_input = antlr4.InputStream(data)
    stream = antlr4.CommonTokenStream(self._lexer(lexer_input))

    end = self.fill(stream)

    tokens = stream.getTokens(0, end)
    return [token.text for token in tokens]

  def combine(self, tokens):
    """Token combiner passed to minimizer"""
    return ''.join(tokens)
