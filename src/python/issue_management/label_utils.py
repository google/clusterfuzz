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
"""Helper functions for sheriffing."""

import re

from datastore import data_types

MEMORY_TOOLS_LABELS = [
    {
        'token': 'AddressSanitizer',
        'label': 'Stability-Memory-AddressSanitizer'
    },
    {
        'token': 'LeakSanitizer',
        'label': 'Stability-Memory-LeakSanitizer'
    },
    {
        'token': 'MemorySanitizer',
        'label': 'Stability-Memory-MemorySanitizer'
    },
    {
        'token': 'ThreadSanitizer',
        'label': 'Stability-ThreadSanitizer'
    },
    {
        'token': 'UndefinedBehaviorSanitizer',
        'label': 'Stability-UndefinedBehaviorSanitizer'
    },
    {
        'token': 'afl',
        'label': 'Stability-AFL'
    },
    {
        'token': 'libfuzzer',
        'label': 'Stability-LibFuzzer'
    },
]
MISSING_VALUE_STRING = '---'
STACKFRAME_LINE_REGEX = re.compile(r'\s*#\d+\s+0x[0-9A-Fa-f]+\s*')


def get_memory_tool_labels(stacktrace):
  """Distinguish memory tools used and return corresponding labels."""
  # Remove stack frames and paths to source code files. This helps to avoid
  # confusion when function names or source paths contain a memory tool token.
  data = ''
  for line in stacktrace.split('\n'):
    if STACKFRAME_LINE_REGEX.match(line):
      continue
    data += line + '\n'

  labels = [t['label'] for t in MEMORY_TOOLS_LABELS if t['token'] in data]
  return labels


def get_severity_from_labels(labels_lowercase):
  """Get the severity from the label list."""
  if 'security_severity-critical' in labels_lowercase:
    return data_types.SecuritySeverity.CRITICAL
  elif 'security_severity-high' in labels_lowercase:
    return data_types.SecuritySeverity.HIGH
  elif 'security_severity-medium' in labels_lowercase:
    return data_types.SecuritySeverity.MEDIUM
  elif 'security_severity-low' in labels_lowercase:
    return data_types.SecuritySeverity.LOW
  return data_types.SecuritySeverity.MISSING


def get_impact_from_labels(labels_lowercase):
  """Get the impact from the label list."""
  if 'security_impact-stable' in labels_lowercase:
    return data_types.SecurityImpact.STABLE
  elif 'security_impact-beta' in labels_lowercase:
    return data_types.SecurityImpact.BETA
  elif 'security_impact-head' in labels_lowercase:
    return data_types.SecurityImpact.HEAD
  elif 'security_impact-none' in labels_lowercase:
    return data_types.SecurityImpact.NONE
  return data_types.SecurityImpact.MISSING


def severity_to_label(severity):
  """Convert a severity value to a human-readable string."""
  severity_map = {
      data_types.SecuritySeverity.CRITICAL: 'Security_Severity-Critical',
      data_types.SecuritySeverity.HIGH: 'Security_Severity-High',
      data_types.SecuritySeverity.MEDIUM: 'Security_Severity-Medium',
      data_types.SecuritySeverity.LOW: 'Security_Severity-Low',
  }

  return severity_map[severity]


def severity_to_string(severity):
  """Convert a severity value to a human-readable string."""
  severity_map = {
      data_types.SecuritySeverity.CRITICAL: 'Critical',
      data_types.SecuritySeverity.HIGH: 'High',
      data_types.SecuritySeverity.MEDIUM: 'Medium',
      data_types.SecuritySeverity.LOW: 'Low',
      data_types.SecuritySeverity.MISSING: MISSING_VALUE_STRING
  }

  return severity_map[severity]


def impact_to_string(impact):
  """Convert an impact value to a human-readable string."""
  impact_map = {
      data_types.SecurityImpact.STABLE: 'Stable',
      data_types.SecurityImpact.BETA: 'Beta',
      data_types.SecurityImpact.HEAD: 'Head',
      data_types.SecurityImpact.NONE: 'None',
      data_types.SecurityImpact.MISSING: MISSING_VALUE_STRING
  }

  return impact_map[impact]
