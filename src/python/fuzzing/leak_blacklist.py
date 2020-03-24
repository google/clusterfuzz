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
"""Highlights and generates suppressions for LSAN reports."""

import os
import re

from base import errors
from datastore import data_handler
from datastore import data_types
from datastore import ndb_utils
from metrics import logs
from system import environment

# Constants for highlighting.
DIRECT_LEAK_LABEL = 'Direct-leak'
DIRECT_LEAK_REGEX = re.compile(r'^ *Direct leak of')
FIRST_LEAK_DIVIDER = ('%s\nThe following leaks are not necessarily related '
                      'to the first leak.\n\n' % ('=' * 80))
STACK_REGEX = re.compile(r'^ *#[0-9]+\s0x[A-Za-z0-9]+')
STACK_START_REGEX = re.compile(r'^ *#0 ')
BLANK_LINE_REGEX = re.compile(r'^\s*$')

LSAN_TOOL_NAME = 'lsan'
LSAN_SUPPRESSION_LINE = 'leak:{function}\n'
LSAN_HEADER_COMMENT = '# This is a LSAN suppressions file.\n'


def create_empty_local_blacklist():
  """Creates an empty local blacklist."""
  lsan_suppressions_path = get_local_blacklist_file_path()
  with open(lsan_suppressions_path, 'w') as local_blacklist:
    # Insert comment on top to avoid parsing errors on empty file.
    local_blacklist.write(LSAN_HEADER_COMMENT)


def cleanup_global_blacklist():
  """Cleans out closed and deleted testcases from the global blacklist."""
  blacklists_to_delete = []
  global_blacklists = data_types.Blacklist.query(
      data_types.Blacklist.tool_name == LSAN_TOOL_NAME)
  for blacklist in global_blacklists:
    testcase_id = blacklist.testcase_id

    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      testcase = None

    # Delete entry if testcase is closed, deleted, or unreproducible.
    if not testcase or not testcase.open or testcase.one_time_crasher_flag:
      blacklists_to_delete.append(blacklist.key)

  ndb_utils.delete_multi(blacklists_to_delete)


def copy_global_to_local_blacklist(excluded_testcase=None):
  """Copies contents of global blacklist into local blacklist file, excluding
  a particular testcase (if any)."""
  lsan_suppressions_path = get_local_blacklist_file_path()
  excluded_function_name = (
      get_leak_function_for_blacklist(excluded_testcase)
      if excluded_testcase else None)

  with open(lsan_suppressions_path, 'w') as local_blacklist:
    # Insert comment on top to avoid parsing errors on empty file.
    local_blacklist.write(LSAN_HEADER_COMMENT)

    # Copy global blacklist into local blacklist.
    global_blacklists = data_types.Blacklist.query(
        data_types.Blacklist.tool_name == LSAN_TOOL_NAME)
    blacklisted_functions = []
    for blacklist in global_blacklists:
      if blacklist.function_name in blacklisted_functions:
        continue
      if blacklist.function_name == excluded_function_name:
        continue

      local_blacklist.write(
          LSAN_SUPPRESSION_LINE.format(function=blacklist.function_name))
      blacklisted_functions.append(blacklist.function_name)


def get_leak_function_for_blacklist(testcase):
  """Return leak function to be used for blacklisting."""
  crash_functions = testcase.crash_state.splitlines()
  if not crash_functions:
    return None

  return crash_functions[0]


def get_local_blacklist_file_path():
  """Return the file path to the local blacklist text file."""
  local_blacklist_path = os.path.join(environment.get_suppressions_directory(),
                                      'lsan_suppressions.txt')

  # Create the directory if it does not exists, since we need to write to it.
  blacklist_directory = os.path.dirname(local_blacklist_path)
  if not os.path.exists(blacklist_directory):
    os.makedirs(blacklist_directory)

  return local_blacklist_path


def should_be_blacklisted(testcase):
  """Returns True if testcase is reproducible and not deleted."""
  return (testcase.open and testcase.crash_type == DIRECT_LEAK_LABEL and
          not testcase.one_time_crasher_flag)


def add_crash_to_global_blacklist_if_needed(testcase):
  """Adds relevant function from testcase crash state to global blacklist."""
  testcase_id = testcase.key.id()
  if not should_be_blacklisted(testcase):
    logs.log('Testcase %s is not a reproducible leak, skipping leak blacklist.'
             % testcase_id)
    return False

  function_name = get_leak_function_for_blacklist(testcase)
  if not function_name:
    logs.log_error(
        'Testcase %s has invalid crash state, skipping leak blacklist.' %
        testcase_id)
    return False

  existing_query = data_types.Blacklist.query(
      data_types.Blacklist.function_name == function_name)
  existing_query = existing_query.filter(
      data_types.Blacklist.testcase_id == testcase_id)
  existing_query = existing_query.filter(
      data_types.Blacklist.tool_name == LSAN_TOOL_NAME)

  if existing_query.get():
    logs.log_error('Item already in leak blacklist.')
    return False

  blacklist_item = data_types.Blacklist(
      function_name=function_name,
      testcase_id=testcase_id,
      tool_name=LSAN_TOOL_NAME)
  blacklist_item.put()
  logs.log('Added %s to leak blacklist.' % function_name)

  return blacklist_item


def highlight_first_direct_leak(crash_stacktrace):
  """Highlights the first direct leak in a report.

  Args:
    crash_stacktrace: The crash report.

  Returns:
    new_report: Updated crash report with first direct leak highlighted.
  """
  new_report = []
  processed_first_leak = False
  num_stacks = 0
  highlighted_stack_index = 0
  divider_index = 0

  # Used to prevent highlighting on first indirect leak.
  direct_leak = False
  currently_highlighting = False

  for line in crash_stacktrace.splitlines():
    if DIRECT_LEAK_REGEX.match(line):
      direct_leak = True

    # Marking the end of the highlighted stack with a divider.
    if BLANK_LINE_REGEX.match(line) and currently_highlighting:
      currently_highlighting = False
      processed_first_leak = True

    if STACK_REGEX.match(line):
      if STACK_START_REGEX.match(line):
        num_stacks += 1

        if direct_leak and not processed_first_leak:
          highlighted_stack_index = num_stacks
          currently_highlighting = True

      # If the line is in the first stack, highlight.
      if currently_highlighting:
        line = '<b>%s</b>' % line

    if not processed_first_leak:
      divider_index += 1

    new_report.append(line)

  # If there's only one stack, return original report.
  if num_stacks == 1:
    return crash_stacktrace

  # If there are leaks after the highlighted leak, insert a divider.
  if highlighted_stack_index != num_stacks:
    new_report.insert(divider_index + 1, FIRST_LEAK_DIVIDER)

  return '\n'.join(new_report)
