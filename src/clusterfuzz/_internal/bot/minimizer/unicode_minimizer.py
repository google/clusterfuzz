# Copyright 2025 Google LLC
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
"""Unicode escape minimizer. Does a single attempt to replace all
unicode escapes with their corresponding UTF-8 encoded characters."""

import re

from . import errors
from . import minimizer
from . import utils

UNICODE_TOKEN_PATTERN = (
    rb'('
    rb'\\u[0-9a-fA-F]{4}'  # \uXXXX format
    rb'|'
    rb'\\u\{[0-9a-fA-F]+\}'  # \u{...} format
    rb'|'
    rb'\\x[0-9a-fA-F]{2}'  # \xXX format
    rb')')


def is_unicode_escape(s):
  """Returns true if string matches \\uXXXX, \\u{...}, or \\xXX pattern."""

  return re.fullmatch(UNICODE_TOKEN_PATTERN, s)


def split_and_decode_unicode_literal(s):
  """Splits the input file by unicode escapes.
  Then for each of unicode escapes creates two tokens:
  (1) unicode escape itself (2) utf-8 encoding of unicode escape."""

  intermediate_tokens = re.split(UNICODE_TOKEN_PATTERN, s)
  tokens = []
  for token in intermediate_tokens:
    tokens.append(token)
    if re.fullmatch(UNICODE_TOKEN_PATTERN, token):
      try:
        hex_code = b''
        if token.startswith(b'\\u{'):
          hex_code = token[3:-1]
        elif token.startswith(b'\\u') or token.startswith(b'\\x'):
          hex_code = token[2:]

        decoded_char = int(hex_code, 16)
        # JS engines require UTF-8 encoding
        tokens.append(chr(decoded_char).encode('utf-8'))

      except (ValueError, OverflowError):
        # If decoding fails, just don't append the replacement token.
        # The original escape is already in `tokens`.
        pass

  return tokens


def combine_tokens(tokens):
  """If unicode token is still present,
  remove the token that was supposed to replace it."""
  final_tokens = []
  i = 0
  while i < len(tokens):
    final_tokens.append(tokens[i])
    if is_unicode_escape(tokens[i]):
      i += 1
    i += 1

  return b''.join(final_tokens)


class UnicodeMinimizer(minimizer.Minimizer):
  """Minimizer to replace \\u0041 -> a, etc. It works the following way:
  Let's assume there's 'some text\\u0042some other text\\u0444end' string
  Tokenizer will split it into ['some text', '\u0042', 'ф', 'some other text',
  'A', 'end']. So for each unicode-escaped symbol, we will add its
  corresponding non-escaped symbol into tokens. All tokens together DON'T
  concat (but combine) to original string. That's the hack that we willingly do.
  We create a single hypothesis with all unicode escapes.
  """

  def __init__(self, *args, **kwargs):
    kwargs['tokenizer'] = split_and_decode_unicode_literal
    kwargs['token_combiner'] = combine_tokens
    minimizer.Minimizer.__init__(self, *args, **kwargs)

  def _execute(self, data):
    testcase = minimizer.Testcase(data, self)
    if not self.validate_tokenizer(data, testcase):
      raise errors.TokenizationFailureError('Unicode minimizer')
    tokens = testcase.tokens

    unicode_hypothesis = []
    for i, token in enumerate(tokens):
      if is_unicode_escape(token):
        unicode_hypothesis.append(i)

    testcase.prepare_test(unicode_hypothesis)

    testcase.process()
    return testcase

  @staticmethod
  def run(data, thread_count=minimizer.DEFAULT_THREAD_COUNT, file_extension=''):
    """Try to minimize |data| using a simple line tokenizer."""
    unicode_minimizer = UnicodeMinimizer(
        utils.test, max_threads=thread_count, file_extension=file_extension)
    return unicode_minimizer.minimize(data)
