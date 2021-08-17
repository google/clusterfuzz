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
"""Security Severity analysis."""

# TODO(ochang): Support other sanitizers.

import re

from clusterfuzz._internal.datastore.data_types import MISSING_VALUE_STRING
from clusterfuzz._internal.datastore.data_types import SecuritySeverity
from clusterfuzz._internal.system import environment

# These should be generic within ClusterFuzz.
LOW_SEVERITY_CRASH_TYPES = []
MEDIUM_SEVERITY_CRASH_TYPES = [
    'Container-overflow', 'Heap-buffer-overflow',
    'Incorrect-function-pointer-type', 'Index-out-of-bounds',
    'Memcpy-param-overlap', 'Non-positive-vla-bound-value', 'Object-size',
    'Stack-buffer-overflow', 'UNKNOWN', 'Use-of-uninitialized-value'
]
HIGH_SEVERITY_CRASH_TYPES = [
    'Bad-cast', 'Heap-double-free', 'Heap-use-after-free',
    'Security DCHECK failure', 'Use-after-poison'
]

SEVERITY_ORDER = [
    SecuritySeverity.LOW, SecuritySeverity.MEDIUM, SecuritySeverity.HIGH,
    SecuritySeverity.CRITICAL
]


def _modify_severity(severity,
                     delta,
                     min_severity=SecuritySeverity.LOW,
                     max_severity=SecuritySeverity.CRITICAL):
  """Increase/decrease the given |severity| by |delta|."""
  min_index = SEVERITY_ORDER.index(min_severity)
  max_index = SEVERITY_ORDER.index(max_severity)
  assert min_index != -1 and max_index != -1

  severity_index = SEVERITY_ORDER.index(severity)
  assert severity_index != -1

  max_index = min(len(SEVERITY_ORDER) - 1, max_index)

  severity_index += delta
  severity_index = min(severity_index, max_index)
  severity_index = max(severity_index, min_index)

  return SEVERITY_ORDER[severity_index]


def get_analyzer(name):
  """Return an analyzer for the given |name|."""
  if name == 'sanitizer_generic':
    return SeverityAnalyzerSanitizer()
  if name == 'sanitizer_chrome':
    return SeverityAnalyzerSanitizerChrome(is_compromised_renderer=False)
  if name == 'sanitizer_chrome_compromised_renderer':
    return SeverityAnalyzerSanitizerChrome(is_compromised_renderer=True)
  return None


def get_security_severity(crash_type, crash_output, job_name,
                          requires_gestures):
  """Convenience function to get the security severity of a crash."""
  analyzer = None
  severity_analyzer_name = environment.get_value('SECURITY_SEVERITY_ANALYZER')

  if severity_analyzer_name:
    analyzer = get_analyzer(severity_analyzer_name)
  else:
    is_chrome = 'chrome' in job_name or 'content_shell' in job_name
    is_sanitizer = ('_asan' in job_name or '_cfi' in job_name or
                    '_lsan' in job_name or '_msan' in job_name or
                    '_tsan' in job_name or '_ubsan' in job_name)

    if is_sanitizer:
      if is_chrome:
        analyzer = get_analyzer('sanitizer_chrome')
      else:
        analyzer = get_analyzer('sanitizer_generic')

  if not analyzer:
    return None

  return analyzer.analyze(crash_type, crash_output, requires_gestures)


class SeverityAnalyzerSanitizer(object):
  """Generic ASan severity analyzer."""

  def analyze(self, crash_type, crash_output, requires_gestures):
    """Return a security severity based on the ASan crash output."""

    manual_severity_match = re.search(
        r'FuzzerSecurityIssue(Critical|High|Medium|Low)', crash_output)
    if manual_severity_match:
      manual_severity = manual_severity_match.group(1)
      return string_to_severity(manual_severity)

    crash_category = crash_type.split()[0]
    if crash_category in HIGH_SEVERITY_CRASH_TYPES:
      severity = SecuritySeverity.HIGH
    elif crash_category in MEDIUM_SEVERITY_CRASH_TYPES:
      severity = SecuritySeverity.MEDIUM
    elif crash_category in LOW_SEVERITY_CRASH_TYPES:
      severity = SecuritySeverity.LOW
    else:
      return None

    if requires_gestures:
      severity = _modify_severity(severity, -1)

    if 'WRITE' in crash_type:
      severity = _modify_severity(
          severity, 1, max_severity=SecuritySeverity.HIGH)

    # TODO(ochang): Detect really weird stacks, and bump them up to high.
    # TODO(ochang): ASSERTs should be high, but right now we also hit release
    # asserts, and there's no way to tell just from the stacktrace.
    # TODO(ochang): Once ASan has some exploitability analysis, take that into
    # account too to bump up/down the severity.

    return severity


class SeverityAnalyzerSanitizerChrome(SeverityAnalyzerSanitizer):
  """Chrome specific severity analyzer."""

  PROCESS_TYPE_EXCEPTIONS = [
      'Use-of-uninitialized-value',
  ]

  def __init__(self, is_compromised_renderer):
    SeverityAnalyzerSanitizer.__init__(self)
    self.is_compromised_renderer = is_compromised_renderer

  def analyze(self, crash_type, crash_output, requires_gestures):
    """Return a security severity based on the ASan crash output."""
    # Base severity.
    severity = SeverityAnalyzerSanitizer.analyze(self, crash_type, crash_output,
                                                 requires_gestures)
    if severity is None:
      return None

    # Chrome specific severity adjustments.
    if (crash_type not in self.PROCESS_TYPE_EXCEPTIONS and
        not self.is_compromised_renderer and
        self._find_process_type(crash_output) == 'browser'):
      severity = _modify_severity(severity, 1)

    return severity

  @staticmethod
  def _find_process_type(crash_output):
    """Return the process type of the process that crashed."""
    # TODO(ochang): Support Android.
    process_type = None
    # This is best effort, and won't work in cases where we have weird stacks
    # (or V8). Since we only care right now if this is a browser process (where
    # this should be rare from an uncompromised renderer), it shouldn't matter
    # too much.
    main_function_regex = re.compile(r'content::([A-Z][a-z]+)Main\(')

    # As a fallback, search for content/browser file paths for determining the
    # browser process.
    content_browser_regex = re.compile(r'content[/\\]browser')

    for line in crash_output.splitlines():
      if 'content::ContentMain' in line:
        continue

      if content_browser_regex.search(line):
        process_type = 'browser'
        break

      match = main_function_regex.search(line)
      if not match:
        continue

      process_type = match.group(1).lower()
      break

    return process_type


def severity_to_string(severity):
  """Convert a severity value to a human-readable string."""
  severity_map = {
      SecuritySeverity.CRITICAL: 'Critical',
      SecuritySeverity.HIGH: 'High',
      SecuritySeverity.MEDIUM: 'Medium',
      SecuritySeverity.LOW: 'Low',
      SecuritySeverity.MISSING: MISSING_VALUE_STRING,
  }

  return severity_map.get(severity, '')


def string_to_severity(severity):
  """Convert a string value to a severity value."""
  severity_map = {
      'critical': SecuritySeverity.CRITICAL,
      'high': SecuritySeverity.HIGH,
      'medium': SecuritySeverity.MEDIUM,
      'low': SecuritySeverity.LOW,
  }

  if severity.lower() in severity_map:
    return severity_map[severity.lower()]

  return SecuritySeverity.MISSING
