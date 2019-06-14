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
"""Helper functions to file issues."""

from base import external_users
from base import utils
from datastore import data_handler
from datastore import data_types
from issue_management import issue_tracker_policy
from issue_management import label_utils
from system import environment

NON_CRASH_TYPES = [
    'Data race',
    'Direct-leak',
    'Float-cast-overflow',
    'Incorrect-function-pointer-type',
    'Integer-overflow',
    'Non-positive-vla-bound-value',
    'RUNTIME_ASSERT',
    'Undefined-shift',
    'Unsigned-integer-overflow',
]


def platform_substitution(label, testcase, _):
  """Platform ubstitution."""
  platform = None
  if environment.is_chromeos_job(testcase.job_type):
    # ChromeOS fuzzers run on Linux platform, so use correct OS-Chrome for
    # tracking.
    platform = 'Chrome'
  elif testcase.platform_id:
    platform = testcase.platform_id.split(':')[0].capitalize()

  if not platform:
    return []

  return [label.replace('%PLATFORM%', platform)]


def current_date():
  """Date format."""
  return utils.utcnow().date().isoformat()


def date_substitution(label, *_):
  """Date ubstitution."""
  return [label.replace('%YYYY-MM-DD%', current_date())]


def sanitizer_substitution(label, testcase, _):
  """Sanitizer ubstitution."""
  stacktrace = data_handler.get_stacktrace(testcase)
  memory_tool_labels = label_utils.get_memory_tool_labels(stacktrace)

  return [
      label.replace('%SANITIZER%', memory_tool)
      for memory_tool in memory_tool_labels
  ]


def severity_substitution(label, testcase, security_severity):
  """Severity ubstitution."""
  # Use severity from testcase if one is not available.
  security_severity = (
      testcase.security_severity
      if security_severity is None else security_severity)

  # Set to default high severity if we can't determine it automatically.
  if not data_types.SecuritySeverity.is_valid(security_severity):
    security_severity = data_types.SecuritySeverity.HIGH

  security_severity_string = label_utils.severity_to_string(security_severity)
  return [label.replace('%SEVERITY%', security_severity_string)]


def apply_substitutions(label, testcase, security_severity):
  """Apply label substituions."""
  label_substitutions = (
      ('%PLATFORM%', platform_substitution),
      ('%YYYY-MM-DD%', date_substitution),
      ('%SANITIZER%', sanitizer_substitution),
      ('%SEVERITY%', severity_substitution),
  )

  for marker, handler in label_substitutions:
    if marker in label:
      return handler(label, testcase, security_severity)

  return [label]


def file_issue(testcase,
               issue_tracker,
               security_severity=None,
               user_email=None,
               additional_ccs=None):
  """File an issue for the given test case."""
  issue = issue_tracker.new_issue()
  issue.title = data_handler.get_issue_summary(testcase)
  issue.body = data_handler.get_issue_description(
      testcase, reporter=user_email, show_reporter=True)

  policy = issue_tracker_policy.get(issue_tracker.project)

  # Add reproducibility flag label.
  if testcase.one_time_crasher_flag:
    issue.labels.add(policy.label('unreproducible'))
  else:
    issue.labels.add(policy.label('reproducible'))

  # Chromium-specific labels.
  if issue_tracker.project and issue_tracker.project == 'chromium':
    # Add reward labels if this is from an external fuzzer contribution.
    fuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == testcase.fuzzer_name).get()
    if fuzzer and fuzzer.external_contribution:
      issue.labels.add('reward-topanel')
      issue.labels.add('External-Fuzzer-Contribution')

    data_handler.update_issue_impact_labels(testcase, issue)

  # Add additional labels from the job definition and fuzzer.
  additional_labels = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_LABELS', testcase.job_type, testcase.fuzzer_name)
  for label in additional_labels:
    issue.labels.add(label)

  # Add additional components from the job definition and fuzzer.
  automatic_components = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_COMPONENTS', testcase.job_type, testcase.fuzzer_name)
  for component in automatic_components:
    issue.components.add(component)

  is_crash = not utils.sub_string_exists_in(NON_CRASH_TYPES,
                                            testcase.crash_type)
  properties = policy.get_new_issue_properties(
      is_security=testcase.security_flag, is_crash=is_crash)

  # Labels applied by default across all issue trackers.
  issue.status = properties.status

  # Add additional ccs from the job definition and fuzzer.
  ccs = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_CCS', testcase.job_type, testcase.fuzzer_name)

  # For externally contributed fuzzers, potentially cc the author.
  # Use fully qualified fuzzer name if one is available.
  fully_qualified_fuzzer_name = (
      testcase.overridden_fuzzer_name or testcase.fuzzer_name)
  ccs += external_users.cc_users_for_fuzzer(fully_qualified_fuzzer_name,
                                            testcase.security_flag)
  ccs += external_users.cc_users_for_job(testcase.job_type,
                                         testcase.security_flag)

  # Add the user as a cc if requested, and any default ccs for this job.
  # Check for additional ccs or labels from the job definition.
  if additional_ccs:
    ccs += [cc for cc in additional_ccs if cc not in ccs]

  # For user uploads, we assume the uploader is interested in the issue.
  if testcase.uploader_email and testcase.uploader_email not in ccs:
    ccs.append(testcase.uploader_email)

  ccs.extend(properties.ccs)

  # Get view restriction rules for the job.
  issue_restrictions = data_handler.get_value_from_job_definition(
      testcase.job_type, 'ISSUE_VIEW_RESTRICTIONS', 'security')
  should_restrict_issue = (
      issue_restrictions == 'all' or
      (issue_restrictions == 'security' and testcase.security_flag))

  if should_restrict_issue:
    issue.labels.add(policy.label('restrict_view'))

  for label in properties.labels:
    for result in apply_substitutions(label, testcase, security_severity):
      if result.startswith(policy.label('reported_prefix')) and not ccs:
        # Do not add reported label when there are no CCs.
        continue

      issue.labels.add(result)

  issue.body += properties.issue_body_footer
  if should_restrict_issue and ccs and policy.deadline_policy_message:
    issue.body += '\n\n' + policy.deadline_policy_message

  for cc in ccs:
    issue.ccs.add(cc)

  # Add additional labels from testcase metadata.
  metadata_labels = utils.parse_delimited(
      testcase.get_metadata('issue_labels', ''),
      delimiter=',',
      strip=True,
      remove_empty=True)
  for label in metadata_labels:
    issue.labels.add(label)

  issue.reporter = user_email
  issue.save()

  # Update the testcase with this newly created issue.
  testcase.bug_information = str(issue.id)
  testcase.put()

  data_handler.update_group_bug(testcase.group_id)
  return issue.id
