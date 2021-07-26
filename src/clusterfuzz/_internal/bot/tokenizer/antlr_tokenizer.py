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

import antlr4

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.minimizer import errors


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
    # Antlr expects a string, but test cases are not necessarily valid utf-8.
    try:
      lexer_input = antlr4.InputStream(data.decode('utf-8'))
    except UnicodeDecodeError:
      raise errors.AntlrDecodeError

    stream = antlr4.CommonTokenStream(self._lexer(lexer_input))
    end = self.fill(stream)
    tokens = stream.getTokens(0, end)
    return [token.text for token in tokens]

  def combine(self, tokens):
    """Token combiner passed to minimizer"""
    # This tokenizer must handle either bytes or str inputs. Antlr works with
    # strings, but the tokenizer validation step uses the original data, which
    # is always raw bytes.
    return b''.join(utils.encode_as_unicode(t) for t in tokens)
