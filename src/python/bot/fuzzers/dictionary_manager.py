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

from base import errors
from base import utils
from bot.fuzzers import utils as fuzzer_utils
from google_cloud_utils import storage
from metrics import logs
from system import environment

DICTIONARY_FILE_EXTENSION = '.dict'

# Name of the file in GCS containing recommended dictionary.
RECOMMENDED_DICTIONARY_FILENAME = (
    'recommended_dictionary%s' % DICTIONARY_FILE_EXTENSION)

# A comment string to separate recommended dictionary elements from manual ones.
RECOMMENDED_DICTIONARY_HEADER = '# Recommended dictionary stored in GCS.'

# Token to split a dictionary element analyzed and metadata.
TOKEN_ANALYZE_DICT_METADATA = ' # Score: '

# Tokens to detect "Recommended dictionary" section in the output.
TOKEN_RECOMMENDED_DICT_END = 'End of recommended dictionary.'
TOKEN_RECOMMENDED_DICT_START = 'Recommended dictionary.'

# Tokens to detect "useless dictionary" section in the output.
TOKEN_USELESS_DICT_END = 'End of useless dictionary elements.'
TOKEN_USELESS_DICT_START = 'Useless dictionary elements.'

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


def get_recommended_dictionary_gcs_path(fuzzer_name):
  """Generate a GCS url to a recommended dictionary.

  Returns:
    String representing GCS path for a dictionary.
  """
  bucket_name = environment.get_value('FUZZ_LOGS_BUCKET')
  bucket_subdirectory_name = 'dictionaries'
  recommended_dictionary_gcs_path = '/%s/%s/%s/%s' % (
      bucket_name, bucket_subdirectory_name, fuzzer_name,
      RECOMMENDED_DICTIONARY_FILENAME)

  return recommended_dictionary_gcs_path


def get_stats_for_dictionary_file(dictionary_path):
  """Calculate size of manual and recommended sections of given dictionary."""
  if not dictionary_path or not os.path.exists(dictionary_path):
    return 0, 0

  dictionary_content = utils.read_data_from_file(
      dictionary_path, eval_data=False).decode('utf-8')
  dictionaries = dictionary_content.split(RECOMMENDED_DICTIONARY_HEADER)

  # If there are any elements before RECOMMENDED_DICTIONARY_HEADER, those are
  # from "manual" dictionary stored in the repository.
  manual_dictionary_size = get_dictionary_size(dictionaries[0])
  if len(dictionaries) < 2:
    return manual_dictionary_size, 0

  # Any elements after RECOMMENDED_DICTIONARY_HEADER are recommended dictionary.
  recommended_dictionary_size = get_dictionary_size(dictionaries[1])
  return manual_dictionary_size, recommended_dictionary_size


def merge_dictionary_files(original_dictionary_path,
                           recommended_dictionary_path, merged_dictionary_path):
  """Merge a list of dictionaries with given paths into a singe dictionary."""
  if original_dictionary_path and os.path.exists(original_dictionary_path):
    merged_dictionary_data = utils.read_data_from_file(
        original_dictionary_path, eval_data=False).decode('utf-8')
  else:
    merged_dictionary_data = ''

  recommended_dictionary_lines = utils.read_data_from_file(
      recommended_dictionary_path,
      eval_data=False).decode('utf-8').splitlines()

  dictionary_lines_to_add = set()
  for line in recommended_dictionary_lines:
    if line not in merged_dictionary_data:
      dictionary_lines_to_add.add(line)

  merged_dictionary_data += '\n%s\n' % RECOMMENDED_DICTIONARY_HEADER

  merged_dictionary_data += '\n'.join(dictionary_lines_to_add)
  utils.write_data_to_file(merged_dictionary_data, merged_dictionary_path)


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


class DictionaryManager(object):
  """Dictionary Manager."""

  def __init__(self, fuzzer_name):
    """Inits the DictionaryManager.

    Args:
      fuzzer_name: Name of the fuzzer.
    """
    self._fuzzer_name = fuzzer_name
    self._gcs_path = get_recommended_dictionary_gcs_path(self.fuzzer_name)

  @property
  def fuzzer_name(self):
    return self._fuzzer_name

  @property
  def gcs_path(self):
    return self._gcs_path

  def _compare_and_swap_gcs_dictionary(self, old_content, new_content):
    """Compare and swap implementation for dictionary stored in GCS. Of course,
    this function is not atomic, but window for race is acceptably small."""
    current_content = storage.read_data(self.gcs_path).decode('utf-8')
    if current_content != old_content:
      return False, current_content

    storage.write_data(new_content.encode('utf-8'), self.gcs_path)
    return True, old_content

  def download_recommended_dictionary_from_gcs(self, local_dict_path):
    """Download recommended dictionary from GCS to the given location.

    Args:
      local_dict_path: Path to a dictionary file on the disk.

    Returns:
      A boolean indicating whether downloading succeeded or not.
    """
    if environment.is_lib():
      return 0

    # When the fuzz target is initially created or when it has no new
    # coverage or dictionary recommendations, then we won't have a
    # recommended dictionary in GCS.
    if not storage.exists(self.gcs_path):
      return False

    if storage.copy_file_from(self.gcs_path, local_dict_path):
      return True

    logs.log('Downloading %s failed.' % self.gcs_path)
    return False

  def parse_recommended_dictionary_from_data(self, data):
    """Extract recommended dictionary entriees from the given string.

    Args:
      data: A string containing data from a fuzzer log.

    Returns:
      A set containing recommended dictionary lines.
    """
    log_lines = data.splitlines()
    return self.parse_recommended_dictionary_from_log_lines(log_lines)

  def parse_recommended_dictionary_from_log_lines(self, log_lines):
    """Extract recommended dictionary entriees from the given log lines.

    Args:
      log_lines: A list of strings from a fuzzer log.

    Returns:
      A set containing recommended dictionary lines.
    """
    # Process the lines in reverse order, as dictionary section is in the end.
    index = len(log_lines)
    while index:
      index -= 1
      if TOKEN_RECOMMENDED_DICT_END in log_lines[index]:
        # Found the section, now extract its entries.
        break

    recommended_entries = []
    while index:
      index -= 1
      if TOKEN_RECOMMENDED_DICT_START in log_lines[index]:
        # Beginning of the section reached, bail out.
        break

      element = extract_dictionary_element(log_lines[index])
      if element:
        recommended_entries.append(element)

    return recommended_entries

  def parse_useless_dictionary_from_data(self, data):
    """Extract useless dictionary entriees from the given string.

    Args:
      data: A string containing data from a fuzzer log.

    Returns:
      A set containing useless dictionary lines.
    """
    log_lines = data.splitlines()
    return self.parse_useless_dictionary_entries_from_log_lines(log_lines)

  def parse_useless_dictionary_entries_from_log_lines(self, log_lines):
    """Extract useless dictionary entries from the given log lines.

    Args:
      log_lines: A list of strings from a fuzzer log.

    Returns:
      A set containing useless dictionary lines.
    """
    # Process the lines in reverse order, as dictionary section is in the end.
    index = len(log_lines)
    while index:
      index -= 1
      if TOKEN_USELESS_DICT_END in log_lines[index]:
        # Found the section, now extract its entries.
        break

    useless_entries = []
    while index:
      index -= 1
      if TOKEN_USELESS_DICT_START in log_lines[index]:
        # Beginning of the section reached, bail out.
        break

      line = log_lines[index].split(TOKEN_ANALYZE_DICT_METADATA)[0]
      element = extract_dictionary_element(line)
      if element:
        useless_entries.append(element)

    return useless_entries

  def update_recommended_dictionary(self, new_dictionary):
    """Update recommended dictionary stored in GCS with new dictionary elements.

    Args:
      new_dictionary: A set of dictionary elements to be added into dictionary.

    Returns:
      A number of new elements actually added to the dictionary stored in GCS.
    """
    if environment.is_lib():
      return 0

    # If the dictionary does not already exist, then directly update it.
    if not storage.exists(self.gcs_path):
      storage.write_data('\n'.join(new_dictionary).encode('utf-8'),
                         self.gcs_path)
      return len(new_dictionary)

    # Read current version of the dictionary.
    old_dictionary_data = storage.read_data(self.gcs_path).decode('utf-8')

    # Use "Compare-and-swap"-like approach to avoid race conditions and also to
    # avoid having a separate job merging multiple recommended dictionaries.
    succeeded = False
    while not succeeded:
      # If old_dictionary_data is None, there is no dictionary in GCS yet, i.e.
      # it's empty. Otherwise, we parse it and use it.
      old_dictionary = set()
      if old_dictionary_data:
        old_dictionary = set(old_dictionary_data.splitlines())

      # Merge two dictionaries.
      new_dictionary |= old_dictionary
      if new_dictionary == old_dictionary:
        # "New dictionary" elements have been already added to GCS, bail out.
        return 0

      succeeded, old_dictionary_data = self._compare_and_swap_gcs_dictionary(
          old_dictionary_data, '\n'.join(new_dictionary))

    return len(new_dictionary) - len(old_dictionary)
