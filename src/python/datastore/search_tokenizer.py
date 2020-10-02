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
"""search_tokenizer tokenizes a string into tokens
  according to our keyword searching use cases."""

import re


def tokenize(s):
  """Tokenize a string, by line, into atomic tokens and complex tokens."""
  if not s:
    s = ''

  s = '%s' % s
  tokens = set()

  lines = s.splitlines()
  for line in lines:
    line = line.strip()
    only_ascii = re.sub(r'\s*[^\x00-\x7F]+\s*', ' ', line)
    tokens |= _complex_tokenize(only_ascii, limit=10)
    tokens.add(line.lower())

  return tokens


def tokenize_bug_information(testcase):
  """Tokenize bug information for searching."""
  bug_indices = []

  if testcase.bug_information:
    bug_indices.append(testcase.bug_information.lower().strip())
  if testcase.group_bug_information:
    bug_indices.append(str(testcase.group_bug_information))

  return bug_indices


def tokenize_impact_version(version):
  """Tokenize impact."""
  if not version:
    return []

  tokens = set()
  splitted = version.split('.')
  for index in range(len(splitted)):
    tokens.add('.'.join(splitted[0:(index + 1)]))

  return [t for t in tokens if t.strip()]


def prepare_search_keyword(s):
  """Prepare the search keywords into the form that is appropriate for searching
    according to our tokenization algorithm."""
  return s.lower().strip()


def _is_camel_case_ab(s, index):
  """Determine if the index is at 'aB', which is the start of a camel token.
    For example, with 'workAt', this function detects 'kA'."""
  return index >= 1 and s[index - 1].islower() and s[index].isupper()


def _is_camel_case_abb(s, index):
  """Determine if the index ends at 'ABb', which is the start of a camel
    token. For example, with 'HTMLParser', this function detects 'LPa'."""
  return (index >= 2 and s[index - 2].isupper() and s[index - 1].isupper() and
          s[index].islower())


def _token_indices(s):
  """Iterate through (end_current_token_index, start_next_token_index) of
    `s`, which is tokenized based on non-alphanumeric characters and camel
    casing. For example, 'aa:bbCC' have 3 tokens: 'aa', 'bb', 'CC'.
    This function iterates through (1,3), (4,5), and (6,7); they represent
    a[a]:[b]bCC, aa:b[b][C]C, and aa:bbC[C][], respectively."""
  index = 0
  length = len(s)
  while index < length:
    if not s[index].isalnum():
      end_index = index - 1
      while index < length and not s[index].isalnum():
        index += 1
      yield end_index, index
    elif _is_camel_case_ab(s, index):
      yield (index - 1), index
      index += 1
    elif _is_camel_case_abb(s, index):
      yield (index - 2), (index - 1)
      index += 1
    else:
      index += 1

  yield (length - 1), length


def _complex_tokenize(s, limit):
  """Tokenize a string into complex tokens. For example, a:b:c is tokenized into
    ['a', 'b', 'c', 'a:b', 'a:b:c', 'b:c']. This method works recursively. It
    generates all possible complex tokens starting from the first token. Then,
    it cuts off the first token and calls _complex_tokenize(..) with the rest
    of `s`.

    `limit` restricts the number of atomic tokens."""
  if not s:
    return set()

  tokens = []
  second_token_index = len(s)
  count = 0
  for end_index, next_start_index in _token_indices(s):
    tokens.append(s[0:(end_index + 1)])
    count += 1
    second_token_index = min(next_start_index, second_token_index)

    if count >= limit:
      break

  tokens = set(t.lower() for t in tokens if t.strip())
  tokens |= _complex_tokenize(s[second_token_index:], limit=limit)
  return tokens
