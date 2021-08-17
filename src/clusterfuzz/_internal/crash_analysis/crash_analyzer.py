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
"""Functions for helping in crash analysis."""

import re

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.system import environment

ASSERT_CRASH_ADDRESSES = [
    0x0000bbadbeef,
    0x0000fbadbeef,
    0x00001f75b7dd,
    0x0000977537dd,
    0x00009f7537dd,
]
GENERIC_CRASH_TYPES = [
    'Null-dereference', 'Null-dereference READ', 'Null-dereference WRITE',
    'READ', 'UNKNOWN', 'UNKNOWN READ', 'UNKNOWN WRITE', 'WRITE',
    'Uncaught exception'
]
SIGNAL_SIGNATURES_NOT_SECURITY = [
    'Sanitizer: ABRT',
    'Sanitizer: BUS',
    'Sanitizer: FPE',
    'Sanitizer: ILL',
    'Sanitizer: breakpoint',
]
STACKTRACE_TOOL_MARKERS = [
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
UBSAN_RUNTIME_ERROR = ' runtime error: '
UBSAN_CRASH_TYPES_NON_SECURITY = [
    'Divide-by-zero',
    'Float-cast-overflow',
    # We do not name this "Signed-integer-overflow", for the sake of syntax
    # being used in LLVM and C++, as there is no "signed int" type.
    'Integer-overflow',
    'Invalid-bool-value',
    'Invalid-builtin-use',
    'Invalid-enum-value',
    'Invalid-null-argument',
    'Invalid-null-return',
    'Misaligned-address',
    'No-return-value',
    'Pointer-overflow',
    'Potential-null-reference',
    'Undefined-shift',
    # Unsigned integer overflow actually is not UB, but there is an additional
    # flag in UBSan that enables this type of check. Unsigned integer overflow
    # issues may cause some bugs, unless it's not an intended overflow, e.g. in
    # math of crpto libraries.
    'Unsigned-integer-overflow',
    'Unreachable code',
]
UBSAN_CRASH_TYPES_SECURITY = [
    'Bad-cast',
    'Index-out-of-bounds',
    'Incorrect-function-pointer-type',
    'Non-positive-vla-bound-value',
    'Object-size',
]
GOLANG_CRASH_TYPES_NON_SECURITY = [
    'Index out of range',
    'Integer divide by zero',
    'Makeslice: len out of range',
    'Slice bounds out of range',
    'Stack overflow',
]

# Default page size of 4KB.
NULL_DEREFERENCE_BOUNDARY = 0x1000


def address_to_integer(address):
  """Attempt to convert an address from a string (hex) to an integer."""
  try:
    return int(address, 16)
  except:
    return 0


def has_marker(stacktrace, marker_list):
  """Return true if the stacktrace has atleast one marker in the marker list."""
  for marker in marker_list:
    if marker in stacktrace:
      return True

  return False


def ignore_stacktrace(crash_stacktrace):
  """Return whether the stacktrace needs to be ignored."""
  # Filter crash based on search exclude pattern specified in job definition.
  search_excludes = environment.get_value('SEARCH_EXCLUDES')
  if search_excludes and re.search(search_excludes, crash_stacktrace):
    return True

  # Match stacktrace against custom defined blacklist regexes in project config.
  stack_blacklist_regexes = (
      local_config.ProjectConfig().get('stacktrace.stack_blacklist_regexes'))
  if not stack_blacklist_regexes:
    return False

  stack_blacklist_regex = re.compile(
      r'(%s)' % '|'.join(stack_blacklist_regexes))
  for line in crash_stacktrace.splitlines():
    if stack_blacklist_regex.match(line):
      return True
  return False


def is_crash(return_code, console_output):
  """Analyze the return code and console output to see if this was a crash."""
  if not return_code:
    return False

  crash_signature = environment.get_value('CRASH_SIGNATURE')
  if crash_signature:
    return re.search(crash_signature, console_output)

  return True


def is_check_failure_crash(stacktrace):
  """Return true if it a CHECK failure crash."""
  # Android-specific exception patterns.
  if environment.is_android():
    if 'Device rebooted' in stacktrace:
      return True
    if 'JNI DETECTED ERROR IN APPLICATION:' in stacktrace:
      return True
    if re.match(r'.*FATAL EXCEPTION.*:', stacktrace, re.DOTALL):
      return True

    # FIXME: Analyze why this is not working with chrome.
    # If the process has died, it is worthwhile to catch this with even a
    # NULL stack.
    # process_died_regex = (r'.*Process %s.*\(pid [0-9]+\) has died' %
    #                       environment.get_value('PKG_NAME'))
    # if re.match(process_died_regex, stacktrace, re.DOTALL):
    #   return True

    # Application CHECK failure known patterns.
  if re.match(r'.*#\s*Fatal error in', stacktrace, re.DOTALL):
    return True
  if 'Check failed:' in stacktrace:
    return True

  # Memory debugging tool CHECK failure.
  if 'Sanitizer CHECK failed:' in stacktrace:
    return True

  return False


def is_memory_tool_crash(stacktrace):
  """Return true if it is a memory debugging tool crash."""
  # Job-specific generic checks.
  crash_signature = environment.get_value('CRASH_SIGNATURE')
  if crash_signature and re.search(crash_signature, stacktrace):
    return True

  # Android specific check.
  # FIXME: Share this regex with stack_analyzer.
  if (environment.is_android() and
      re.match(r'.*signal.*\(SIG.*fault addr ([^ ]*)', stacktrace, re.DOTALL)):
    return True

  # Check if we have a complete stacktrace by location stacktrace end marker.
  # If not, bail out.
  if not has_marker(stacktrace, STACKTRACE_END_MARKERS):
    return False

  # Check if have a UBSan error.
  if has_ubsan_error(stacktrace):
    return True

  # Check if have a stacktrace start marker.
  if has_marker(stacktrace, STACKTRACE_TOOL_MARKERS):
    return True

  return False


def is_null_dereference(int_address):
  """Check to see if this is a null dereference crash address."""
  return int_address < NULL_DEREFERENCE_BOUNDARY


def is_assert_crash_address(int_address):
  """Check to see if this is an ASSERT crash based on the address."""
  return int_address in ASSERT_CRASH_ADDRESSES


def has_signal_for_non_security_bug_type(stacktrace):
  """Checks if any signal which means not security bug presented."""
  if re.search(r'^[ \t]+#0[ \t]+0x[0-9a-f]+[ \t]+in gsignal ', stacktrace,
               re.MULTILINE):
    return True

  for signature in SIGNAL_SIGNATURES_NOT_SECURITY:
    if signature in stacktrace:
      return True

  return False


def is_security_issue(crash_stacktrace, crash_type, crash_address):
  """Based on unsymbolized crash parameters, determine whether it has security
  consequences or not."""
  # Stack traces of any type can be manually labelled as a security issue.
  if re.search('FuzzerSecurityIssue(Critical|High|Medium|Low)',
               crash_stacktrace):
    return True

  # eip == 0.
  if 'pc (nil) ' in crash_stacktrace:
    return True
  if 'pc 0x00000000 ' in crash_stacktrace:
    return True
  if 'pc 0x000000000000 ' in crash_stacktrace:
    return True

  # JNI security crashes.
  if re.match(
      '.*JNI DETECTED ERROR[^\n]+(deleted|invalid|unexpected|unknown|wrong)',
      crash_stacktrace, re.DOTALL):
    return True

  if crash_type == 'CHECK failure':
    # TODO(ochang): Remove this once we pick up newer builds that distinguish
    # DCHECKs from CHECKs.
    checks_have_security_implication = environment.get_value(
        'CHECKS_HAVE_SECURITY_IMPLICATION', False)
    return checks_have_security_implication

  # Release SECURITY_CHECK in Blink shouldn't be marked as a security bug.
  if crash_type == 'Security CHECK failure':
    return False

  # Debug CHECK failure should be marked with security implications.
  if crash_type in ('Security DCHECK failure', 'DCHECK failure'):
    return True

  # Hard crash, explicitly enforced in code.
  if (crash_type == 'Fatal error' or crash_type == 'Unreachable code' or
      crash_type.endswith('Exception') or crash_type.endswith('CHECK failure')):
    return False

  if crash_type == 'Stack-overflow':
    return False

  if crash_type == 'Fatal-signal':
    return False

  if crash_type == 'Missing-library':
    return False

  if crash_type == 'Overwrites-const-input':
    return False

  # LeakSanitizer, finds memory leaks.
  if '-leak' in crash_type:
    return False

  # ThreadSanitizer, finds data races.
  if 'Data race' in crash_type:
    return False

  # ThreadSanitizer, finds lock order issues.
  if 'Lock-order-inversion' in crash_type:
    return False

  # Unexpected conditions reached in the program.
  if crash_type == 'ASSERT_NOT_REACHED':
    return False

  if crash_type in UBSAN_CRASH_TYPES_SECURITY:
    return True

  if crash_type in UBSAN_CRASH_TYPES_NON_SECURITY:
    return False

  if crash_type in GOLANG_CRASH_TYPES_NON_SECURITY:
    return False

  # Floating point exceptions.
  if crash_type == 'Floating-point-exception':
    return False

  # RUNTIME_ASSERT in V8 (not a crash, but is a sign of an error).
  if crash_type == 'RUNTIME_ASSERT':
    return False

  # Correctness failure in V8.
  if crash_type == 'V8 correctness failure':
    return False

  # By default, any assert crash is a security crash.
  # This behavior can be changed by defining
  # |ASSERTS_HAVE_SECURITY_IMPLICATION| in job definition.
  if crash_type == 'ASSERT' or 'ASSERTION FAILED' in crash_stacktrace:
    asserts_have_security_implication = environment.get_value(
        'ASSERTS_HAVE_SECURITY_IMPLICATION', True)
    return asserts_have_security_implication

  # Timeouts/OOMs.
  if crash_type in ('Timeout', 'Out-of-memory'):
    return False

  # Unexpected exit call in fuzz target.
  if crash_type == 'Unexpected-exit':
    return False

  # Kernel Failures are security bugs
  if crash_type.startswith('Kernel failure'):
    return True

  # No crash type, can't process.
  if not crash_type:
    return False

  if has_signal_for_non_security_bug_type(crash_stacktrace):
    return False

  # Anything we don't understand will be marked as security.
  if crash_type not in GENERIC_CRASH_TYPES:
    return True

  # Crash on an unknown address.
  if crash_type in GENERIC_CRASH_TYPES:
    # If the address is not near null, then we it is highly likely
    # to have security consequences.
    int_address = address_to_integer(crash_address)

    # This indicates that there was no assert, but a hard crash.
    # (as the assert would be caught by checks above). So, it
    # does have any security implication.
    if is_assert_crash_address(int_address):
      return False

    if not is_null_dereference(int_address):
      return True

  return False


def has_ubsan_error(stacktrace):
  """Return a bool whether the process output contains UBSan errors that should
  be handled as crashes. Suppressions file alone does not provide granular
  control, e.g. to ignore left shift of negative value which can cause false
  positives in some projects e.g. Chromium."""
  if UBSAN_RUNTIME_ERROR not in stacktrace:
    return False

  # FIXME: Avoid opening this file on every single call.
  ubsan_ignores_file_path = environment.get_suppressions_file(
      'ubsan', suffix='ignores')
  if not ubsan_ignores_file_path:
    # No ignore file exists or is empty, everything is allowed.
    return True

  with open(ubsan_ignores_file_path) as f:
    ubsan_ignore_signatures = f.read().splitlines()

  for line in stacktrace.splitlines():
    ignore_line = False
    for signature in ubsan_ignore_signatures:
      if signature in line:
        ignore_line = True

    if ignore_line:
      continue

    if UBSAN_RUNTIME_ERROR in line:
      return True

  return False
