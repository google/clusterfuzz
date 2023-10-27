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
"""Functions for dictionary analysis and management."""

import os
import re

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils

DICTIONARY_FILE_EXTENSION = '.dict'

# A comment string to separate recommended dictionary elements from manual ones.
RECOMMENDED_DICTIONARY_HEADER = '# Recommended dictionary stored in GCS.'

DICTIONARY_PART_PATTERN = re.compile(r'([^"]+\s*=\s*)?(.*)')


def extract_dictionary_element(line):
  """Extract a dictionary element from the given string."""
  # An element should start and end with a double-quote.
  start_index = line.find('"')
  end_index = line.rfind('"')
  if start_index == -1 or end_index == -1 or start_index == end_index:
    return None

  element = line[start_index:end_index + 1]
  return element


def get_default_dictionary_path(fuzz_target_path):
  """Return default dictionary path."""
  return fuzzer_utils.get_supporting_file(fuzz_target_path,
                                          DICTIONARY_FILE_EXTENSION)


def get_dictionary_size(dictionary_content):
  """Calculate number of dictionary elements in the given string."""
  count = 0
  for line in dictionary_content.splitlines():
    if extract_dictionary_element(line):
      count += 1

  return count


def get_stats_for_dictionary_file(dictionary_path):
  """Calculate size of manual section of given dictionary."""
  if not dictionary_path or not os.path.exists(dictionary_path):
    return 0

  dictionary_content = utils.read_data_from_file(
      dictionary_path, eval_data=False).decode('utf-8')
  dictionaries = dictionary_content.split(RECOMMENDED_DICTIONARY_HEADER)

  # If there are any elements before RECOMMENDED_DICTIONARY_HEADER, those are
  # from "manual" dictionary stored in the repository.
  manual_dictionary_size = get_dictionary_size(dictionaries[0])
  return manual_dictionary_size


def _fix_dictionary_line(line, dict_path):
  """Correct a single dictionary line."""
  # Ignore blank and comment lines.
  if not line or line.strip().startswith('#'):
    return line

  match = DICTIONARY_PART_PATTERN.match(line)
  # We expect this pattern to match even invalid dictionary entries. Failures
  # to match should be treated as bugs in this function.
  if not match:
    raise errors.BadStateError(
        'Failed to correct dictionary line "{line}" in {path}.'.format(
            line=line, path=dict_path))

  name_part = match.group(1) or ''
  entry = match.group(2)

  # In some cases, we'll detect the user's intended entry as a token name. This
  # can happen if the user included unquoted tokens such as "!=" or ">=".
  if not entry and name_part:
    entry = name_part
    name_part = ''

  # Handle quote entries as a special case. This simplifies later logic.
  if entry == '"':
    entry = '"\\\""'

  if entry.startswith('"') and entry.endswith('"'):
    return name_part + entry

  # In this case, we know the entry is invalid. Escape any unescaped quotes
  # within it, then append quotes to the front and back.
  new_entry = ''
  prev_character = ''
  for character in entry:
    if character == '"' and prev_character != '\\':
      new_entry += '\\'
    new_entry += character
    prev_character = character

  new_entry = '"{entry}"'.format(entry=new_entry)
  return name_part + new_entry


def correct_if_needed(dict_path):
  """Corrects obvious errors such as missing quotes in a dictionary."""
  if not dict_path or not os.path.exists(dict_path):
    return

  content = utils.read_data_from_file(
      dict_path, eval_data=False).decode('utf-8')
  new_content = ''
  for current_line in content.splitlines():
    new_content += _fix_dictionary_line(current_line, dict_path) + '\n'

  # End of file newlines are inconsistent in dictionaries.
  if new_content.rstrip('\n') != content.rstrip('\n'):
    utils.write_data_to_file(new_content, dict_path)
