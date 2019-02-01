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
"""Cleaned up test case tokenizer from ClusterFuzz. To be fully rewritten."""

import re


def tokenize(token_string, level=0):
  """Returns a list of html tokens, by splitting the token_string."""
  # Round 0 - Split tokens by newlines.
  # Round 1 - Split tokens by tags.
  # Round 2 - Split tokens by tag attributes.
  # Round 3 - Split tokens by ';' and ', '.

  token_string = token_string.replace('\r\n', '\n')
  token_string = token_string.replace('\r', '\n')

  token_list = []

  start_tag_symbol = '<'
  end_tag_symbol = '>'
  space_symbol = ' '
  single_quote_symbol = "'"
  double_quote_symbol = '"'

  found_start_tag = False
  consecutive_start_tag_symbol = 0
  start = 0

  for i in range(0, len(token_string)):
    found_token = False

    if token_string[i] == '\n' and not consecutive_start_tag_symbol:
      # We can easily break it into a token, when we see a new line character.
      found_token = True
    elif i > 0 and token_string[i] == end_tag_symbol \
        and token_string[i - 1] == end_tag_symbol:
      # We can have two consecutive end-tag from minimization stage.
      # In that case, best to split tokens.
      found_token = True
    elif token_string[i] == start_tag_symbol and \
        level >= 1 and not found_start_tag:
      end = 0
      for j in range(i + 1, len(token_string)):
        if j == i + 1:
          # Got a start tag.
          if re.match('[a-zA-Z!?/]', token_string[j]):
            found_start_tag = True
          else:
            found_start_tag = False
            break

        # Got a end tag.
        if found_start_tag and token_string[j] == end_tag_symbol:
          end = j
          break

        # Got two consecutive start tag, with no end tag symbol in between.
        if token_string[j] == start_tag_symbol:
          consecutive_start_tag_symbol = j
          found_start_tag = False
          break

      if found_start_tag is True:
        match = re.search(r'<[^<]*>', token_string[i:end + 1])
        if match is not None:
          # Got a full tag.
          found_token = True
          i = end + 1

    if found_token is True and i >= start:
      if level == 0:
        token_list.append(token_string[start:i])
      elif i > consecutive_start_tag_symbol > 0:
        token_list.append(token_string[start:consecutive_start_tag_symbol])
        token_list.append(token_string[consecutive_start_tag_symbol:i])
      else:
        temporary_token = token_string[start:i]

        start_tag_symbol_index = -1
        end_tag_symbol_index = temporary_token.rfind(end_tag_symbol)

        if end_tag_symbol_index > -1:
          start_tag_symbol_index = \
              temporary_token.rfind(start_tag_symbol, 0, end_tag_symbol_index)
          end_tag_symbol_index += start
        if start_tag_symbol_index > -1:
          start_tag_symbol_index += start

        if end_tag_symbol_index > start_tag_symbol_index > -1:
          token_list.append(token_string[start:start_tag_symbol_index])

          # Level 2 - Logic to handle breaking of attributes into tokens.
          if level >= 2:
            sindex = start_tag_symbol_index
            had_space_between_attributes = False
            between_same_quotes = False

            for j in range(start_tag_symbol_index, end_tag_symbol_index + 1):
              if (token_string[j] == double_quote_symbol or
                  token_string[j] == single_quote_symbol):
                between_same_quotes = not between_same_quotes

              if (not between_same_quotes and
                  ((token_string[j] == space_symbol and
                    token_string[j + 1] != space_symbol) or
                   (token_string[j] == end_tag_symbol and
                    had_space_between_attributes))):
                if token_string[j] == space_symbol:
                  had_space_between_attributes = True
                token_list.append(token_string[sindex:j])
                sindex = j
            token_list.append(token_string[sindex:end_tag_symbol_index + 1])
          else:
            token_list.append(
                token_string[start_tag_symbol_index:end_tag_symbol_index + 1])
          if end_tag_symbol_index + 1 != i:
            token_list.append(token_string[end_tag_symbol_index + 1:i])
        else:
          token_list.append(token_string[start:i])

      start = i
      consecutive_start_tag_symbol = 0
      found_start_tag = False

  # Append any remaining token string left.
  token_list.append(token_string[start:])

  # Level 3 - Split tokens on ';' and ', ' char.
  if level >= 3:
    temp_token_list = []
    for elem in token_list:
      token_split_list = elem.split(';')
      for index in range(0, len(token_split_list)):
        if index < len(token_split_list) - 1:
          temp_token_list.append(token_split_list[index] + ';')
        else:
          temp_token_list.append(token_split_list[index])

    token_list = filter(None, temp_token_list)

    temp_token_list = []
    for elem in token_list:
      token_split_list = elem.split(', ')
      for index in range(0, len(token_split_list)):
        if index < len(token_split_list) - 1:
          temp_token_list.append(token_split_list[index] + ', ')
        else:
          temp_token_list.append(token_split_list[index])

    token_list = filter(None, temp_token_list)

  # Split tokens with more than one newline char.
  temp_token_list = []
  for temporary_token in token_list:
    token_split_list = temporary_token.split('\n')
    for index in range(0, len(token_split_list)):
      if index < len(token_split_list) - 1:
        temp_token_list.append(token_split_list[index] + '\n')
      else:
        temp_token_list.append(token_split_list[index])

  # Token with only newline chars should be appended to next token.
  index = 0
  token_list = []
  temporary_token = ''
  while index < len(temp_token_list):
    if temp_token_list[index].strip() and temp_token_list[index].strip().lstrip(
        '\t'):
      if token_list:
        token_list[-1] = token_list[-1] + temporary_token
        token_list.append(temp_token_list[index])
      else:
        if temporary_token:
          token_list.append(temporary_token)
        token_list.append(temp_token_list[index])
      temporary_token = ''
    else:
      temporary_token = temporary_token + temp_token_list[index]

    index += 1

  if temporary_token:
    token_list.append(temporary_token)

  return filter(None, token_list)


def combine_tokens(tokens):
  """Helper function to combine tokens."""
  return ''.join(tokens)
