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
"""Minimizer helper functions."""

import os
import shlex
import subprocess

from . import errors
from bot.tokenizer.antlr_tokenizer import AntlrTokenizer
from bot.tokenizer.grammars.HTMLLexer import HTMLLexer

# TODO(mbarbella): Improve configuration of the test function.
attempts = 1
test_command = None

# This list of markers is a copy of code in ClusterFuzz.
# This is kept here to keep the code standalone.
STACKTRACE_TOOL_MARKERS = [
    ' runtime error: ',
    'AddressSanitizer',
    'ASAN:',
    'CFI: Most likely a control flow integrity violation;',
    'ERROR: libFuzzer',
    'KASAN:',
    'LeakSanitizer',
    'MemorySanitizer',
    'ThreadSanitizer',
    'UndefinedBehaviorSanitizer',
    'UndefinedSanitizer',
]
STACKTRACE_END_MARKERS = [
    'ABORTING',
    'END MEMORY TOOL REPORT',
    'End of process memory map.',
    'END_KASAN_OUTPUT',
    'SUMMARY:',
    'Shadow byte and word',
    '[end of stack trace]',
    '\nExiting',
    'minidump has been written',
]
CHECK_FAILURE_MARKERS = [
    'Check failed:',
    'Device rebooted',
    'Fatal error in',
    'FATAL EXCEPTION',
    'JNI DETECTED ERROR IN APPLICATION:',
    'Sanitizer CHECK failed:',
]


def get_size_string(size):
  """Return string representation for size."""
  if size < 1 << 10:
    return '%d B' % size
  if size < 1 << 20:
    return '%d KB' % (size >> 10)
  if size < 1 << 30:
    return '%d MB' % (size >> 20)

  return '%d GB' % (size >> 30)


def has_marker(stacktrace, marker_list):
  """Return true if the stacktrace has atleast one marker
  in the marker list."""
  for marker in marker_list:
    if marker in stacktrace:
      return True

  return False


def set_test_command(new_test_command):
  """Set the command used for testing."""
  global test_command
  test_command = shlex.split(new_test_command)


def set_test_attempts(new_attempts):
  """Set the number of times to attempt the test."""
  global attempts
  attempts = new_attempts


def test(test_path):
  """Wrapper function to verify that a test does not fail for multiple runs."""
  for _ in range(attempts):
    if not single_test_run(test_path):
      return False
  return True


def single_test_run(test_path):
  """Hacky test function that checks for certain common errors."""
  if not test_command:
    raise errors.NoCommandError

  args = test_command + [test_path]
  try:
    console_output = subprocess.check_output(args, stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError as error:
    console_output = error.output

  # If we meet one of these conditions, assume we crashed.
  if ((has_marker(console_output, STACKTRACE_TOOL_MARKERS) and
       has_marker(console_output, STACKTRACE_END_MARKERS)) or
      has_marker(console_output, CHECK_FAILURE_MARKERS)):
    print('Crashed, current test size %s.' % (get_size_string(
        os.path.getsize(test_path))))
    return False

  # No crash, test passed.
  print('Not crashed, current test size %s.' % (get_size_string(
      os.path.getsize(test_path))))
  return True


def tokenize(data):
  """HTML tokenizer."""
  return AntlrTokenizer(HTMLLexer).tokenize(data)


def token_combiner(tokens):
  """Dummy token combiner."""
  return ''.join(tokens)
