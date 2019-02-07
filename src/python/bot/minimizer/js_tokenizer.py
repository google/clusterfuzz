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
"""Basic tokenizer for javascript tests."""

from __future__ import print_function

import sys


def first_separator_index(data, separators, check_quotes):
  """Find the first index of a separator in |data|."""
  in_quote_type = None
  escaped = False
  for index, ch in enumerate(data):
    if escaped:
      escaped = False
      continue
    elif in_quote_type:
      if ch == '\\':
        escaped = True
      elif ch == in_quote_type or ch == '\n':
        in_quote_type = None
      continue
    elif check_quotes:
      if ch == '"' or ch == "'":
        in_quote_type = ch

    if ch in separators:
      return index, ch

  return -1, None


def split_using_separators(data,
                           separators,
                           individual_tokens=None,
                           check_quotes=True):
  """Splits |data| into tokens using separator |sep|."""
  tokens = []
  while data:
    index, separator = first_separator_index(data, separators, check_quotes)
    if not separator:
      tokens += [data]
      break

    new_start = index + len(separator)
    if individual_tokens and separator in individual_tokens:
      if index != 0:
        tokens += [data[:index]]
      tokens += [separator]
    else:
      tokens += [data[:new_start]]
    data = data[new_start:]

  return tokens


def line_tokenizer(data):
  return split_using_separators(data, ['\n'], check_quotes=False)


def bracket_tokenizer(data):
  """Tokenizes across curly brackets."""
  tokens = ['{', '}', '\n']
  individual_tokens = tokens[:-1]
  return split_using_separators(data, tokens, individual_tokens)


def paren_tokenizer(data):
  """Tokenizes across parenthesis."""
  tokens = ['{', '}', '(', ')', '\n']
  individual_tokens = tokens[:-1]
  return split_using_separators(data, tokens, individual_tokens)


def comma_tokenizer(data):
  """Tokenizes across commas."""
  tokens = ['{', '}', '(', ')', '[', ']', ',', '\n']
  individual_tokens = tokens[:-1]
  return split_using_separators(data, tokens, individual_tokens)


def comment_tokenizer(data):
  """Tokenizes across single and multi-line comments."""
  tokens = []
  start_index = 0
  size = len(data)
  in_singleline_comment = False
  in_multiline_comment = False
  for index in xrange(size):
    if index == size - 1:
      # Reached end of string, append whatever we have left.
      tokens.append(data[start_index:index + 1])
    elif in_singleline_comment and data[index] == '\n':
      # Reset single line comment.
      tokens.append(data[start_index:index])
      start_index = index
      in_singleline_comment = False
    elif (data[index] == '/' and data[index + 1] == '/' and
          not in_singleline_comment and not in_multiline_comment):
      # Start single-line comment.
      tokens.append(data[start_index:index])
      start_index = index
      in_singleline_comment = True
    elif (data[index] == '/' and data[index + 1] == '*' and
          not in_singleline_comment and not in_multiline_comment):
      # Start multi-line comment.
      tokens.append(data[start_index:index])
      start_index = index
      in_multiline_comment = True
    elif (in_multiline_comment and data[index] == '*' and
          data[index + 1] == '/'):
      # End multi-line comment.
      tokens.append(data[start_index:index + 2])
      start_index = index + 2
      in_multiline_comment = False
  return tokens


def combine_tokens(tokens):
  """Helper function to combine tokens."""
  return ''.join(tokens)


def main():
  if len(sys.argv) < 2:
    print('Usage: %s <file to tokenize> [<level>]' % sys.argv[0])
    sys.exit(1)

  tokenizers = [
      comment_tokenizer, line_tokenizer, bracket_tokenizer, paren_tokenizer,
      comma_tokenizer
  ]

  level = len(tokenizers) - 1
  if len(sys.argv) > 2:
    level = int(sys.argv[2])
    assert level in xrange(0, len(tokenizers))

  print(tokenizers[level](open(sys.argv[1]).read()))


if __name__ == '__main__':
  main()
