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

RESTRICT_TO_GOOGLERS_LABEL = 'Restrict-View-Google'

DEADLINE_NOTE = (
    'This bug is subject to a 90 day disclosure deadline. If 90 days elapse\n'
    'without an upstream patch, then the bug report will automatically\n'
    'become visible to the public.')

FIX_NOTE = (
    'When you fix this bug, please\n'
    '  * mention the fix revision(s).\n'
    '  * state whether the bug was a short-lived regression or an old bug'
    ' in any stable releases.\n'
    '  * add any other useful information.\n'
    'This information can help downstream consumers.')

QUESTIONS_NOTE = (
    'If you need to contact the OSS-Fuzz team with a question, concern, or any '
    'other feedback, please file an issue at '
    'https://github.com/google/oss-fuzz/issues.')


def add_memory_tool_label_if_needed(issue, testcase):
  """Find memory tool used and add corresponding labels to the issue."""
  stacktrace = data_handler.get_stacktrace(testcase)
  memory_tool_labels = label_utils.get_memory_tool_labels(stacktrace)
  for label in memory_tool_labels:
    issue.labels.append(label)


def add_security_severity_label_if_needed(issue, testcase,
                                          security_severity_override):
  """Add security severity label to issue."""
  if not testcase.security_flag:
    return

  # Use severity from testcase if one is not available.
  security_severity = (
      testcase.security_severity
      if security_severity_override is None else security_severity_override)

  # Set to default high severity if we can't determine it automatically.
  if not data_types.SecuritySeverity.is_valid(security_severity):
    security_severity = data_types.SecuritySeverity.HIGH

  security_severity_label = label_utils.severity_to_label(security_severity)
  issue.labels.append(security_severity_label)


def add_view_restrictions_if_needed(issue, testcase):
  """Add additional view restrictions for android and flash bugs."""
  if testcase.project_name != 'chromium':
    return

  # If the label is already there, no work to do.
  if RESTRICT_TO_GOOGLERS_LABEL in issue.labels:
    return

  job_type_lowercase = testcase.job_type.lower()
  if 'android' in job_type_lowercase or 'flash' in job_type_lowercase:
    issue.labels.append(RESTRICT_TO_GOOGLERS_LABEL)


def reported_label():
  """Return a Reported-YYYY-MM-DD label."""
  return 'Reported-' + utils.utcnow().date().isoformat()


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

  # Labels applied by default across all issue trackers.
  issue.status = 'New'
  issue.labels.append('ClusterFuzz')

  # Add label on memory tool used.
  add_memory_tool_label_if_needed(issue, testcase)

  # Add reproducibility flag label.
  if testcase.one_time_crasher_flag:
    issue.labels.append('Unreproducible')
  else:
    issue.labels.append('Reproducible')

  # Add security severity flag label.
  add_security_severity_label_if_needed(issue, testcase, security_severity)

  # Get view restriction rules for the job.
  issue_restrictions = data_handler.get_value_from_job_definition(
      testcase.job_type, 'ISSUE_VIEW_RESTRICTIONS', 'security')
  should_restrict_issue = (
      issue_restrictions == 'all' or
      (issue_restrictions == 'security' and testcase.security_flag))

  # Chromium-specific labels.
  if issue_tracker.project == 'chromium':
    # A different status system is used on the chromium tracker. Since we
    # have already reproduced the crash, we skip the Unconfirmed status.
    issue.status = 'Untriaged'

    # Add OS label.
    if environment.is_chromeos_job(testcase.job_type):
      # ChromeOS fuzzers run on Linux platform, so use correct OS-Chrome for
      # tracking.
      issue.labels.append('OS-Chrome')
    elif testcase.platform_id:
      os_label = 'OS-%s' % ((testcase.platform_id.split(':')[0]).capitalize())
      issue.labels.append(os_label)

    # Add view restrictions for internal job types.
    add_view_restrictions_if_needed(issue, testcase)

    if testcase.security_flag:
      # Apply labels specific to security bugs.
      issue.labels.append('Restrict-View-SecurityTeam')
      issue.labels.append('Type-Bug-Security')

      # Add reward labels if this is from an external fuzzer contribution.
      fuzzer = data_types.Fuzzer.query(
          data_types.Fuzzer.name == testcase.fuzzer_name).get()
      if fuzzer and fuzzer.external_contribution:
        issue.labels.append('reward-topanel')
        issue.labels.append('External-Fuzzer-Contribution')

      data_handler.update_issue_impact_labels(testcase, issue)
    else:
      # Apply labels for functional (non-security) bugs.
      if utils.sub_string_exists_in(NON_CRASH_TYPES, testcase.crash_type):
        # Non-crashing test cases shouldn't be assigned Pri-1.
        issue.labels.append('Pri-2')
        issue.labels.append('Type-Bug')
      else:
        # Default functional bug labels.
        issue.labels.append('Pri-1')
        issue.labels.append('Stability-Crash')
        issue.labels.append('Type-Bug')

  # AOSP-specific labels.
  elif issue_tracker.project == 'android':
    if testcase.security_flag:
      # Security bug labels.
      issue.add_cc('security@android.com')
      issue.labels.append('Type-Security')
      issue.labels.append('Restrict-View-Commit')
    else:
      # Functional bug labels.
      issue.labels.append('Type-Defect')

  # OSS-Fuzz specific labels.
  elif issue_tracker.project == 'oss-fuzz':
    if testcase.security_flag:
      # Security bug labels.
      issue.labels.append('Type-Bug-Security')
    else:
      # Functional bug labels.
      issue.labels.append('Type-Bug')

    if should_restrict_issue:
      issue.labels.append('Restrict-View-Commit')

  # Add additional labels from the job definition and fuzzer.
  additional_labels = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_LABELS', testcase.job_type, testcase.fuzzer_name)
  for label in additional_labels:
    issue.labels.append(label)

  # Add additional components from the job definition and fuzzer.
  automatic_components = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_COMPONENTS', testcase.job_type, testcase.fuzzer_name)
  for component in automatic_components:
    issue.components.append(component)

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

  if issue_tracker.project == 'oss-fuzz' and ccs:
    # Add a reported label for deadline tracking.
    issue.labels.append(reported_label())

    if should_restrict_issue:
      issue.body += '\n\n' + DEADLINE_NOTE

    issue.body += '\n\n' + FIX_NOTE
    issue.body += '\n\n' + QUESTIONS_NOTE

  for cc in ccs:
    issue.ccs.append(cc)

  # Add additional labels from testcase metadata.
  metadata_labels = utils.parse_delimited(
      testcase.get_metadata('issue_labels', ''),
      delimiter=',',
      strip=True,
      remove_empty=True)
  for label in metadata_labels:
    issue.labels.append(label)

  issue.reporter = user_email
  issue.save()

  # Update the testcase with this newly created issue.
  testcase.bug_information = str(issue.id)
  testcase.put()

  data_handler.update_group_bug(testcase.group_id)

  return issue.id
