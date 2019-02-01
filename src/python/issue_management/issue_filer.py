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
from issue_management.issue import Issue
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
    issue.add_label(label)


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
  issue.add_label(security_severity_label)


def add_view_restrictions_if_needed(issue, testcase):
  """Add additional view restrictions for android and flash bugs."""
  if testcase.project_name != 'chromium':
    return

  # If the label is already there, no work to do.
  if RESTRICT_TO_GOOGLERS_LABEL in issue.labels:
    return

  job_type_lowercase = testcase.job_type.lower()
  if 'android' in job_type_lowercase or 'flash' in job_type_lowercase:
    issue.add_label(RESTRICT_TO_GOOGLERS_LABEL)


def reported_label():
  """Return a Reported-YYYY-MM-DD label."""
  return 'Reported-' + utils.utcnow().date().isoformat()


def file_issue(testcase,
               itm,
               security_severity=None,
               user_email=None,
               additional_ccs=None):
  """File an issue for the given test case."""
  issue = Issue()
  issue.summary = data_handler.get_issue_summary(testcase)
  issue.body = data_handler.get_issue_description(
      testcase, reporter=user_email, show_reporter=True)

  # Labels applied by default across all issue trackers.
  issue.status = 'New'
  issue.add_label('ClusterFuzz')

  # Add label on memory tool used.
  add_memory_tool_label_if_needed(issue, testcase)

  # Add reproducibility flag label.
  if testcase.one_time_crasher_flag:
    issue.add_label('Unreproducible')
  else:
    issue.add_label('Reproducible')

  # Add security severity flag label.
  add_security_severity_label_if_needed(issue, testcase, security_severity)

  # Get view restriction rules for the job.
  issue_restrictions = data_handler.get_value_from_job_definition(
      testcase.job_type, 'ISSUE_VIEW_RESTRICTIONS', 'security')
  should_restrict_issue = (
      issue_restrictions == 'all' or
      (issue_restrictions == 'security' and testcase.security_flag))

  # Chromium-specific labels.
  if itm.project_name == 'chromium':
    # A different status system is used on the chromium tracker. Since we
    # have already reproduced the crash, we skip the Unconfirmed status.
    issue.status = 'Untriaged'

    # Add OS label.
    if environment.is_chromeos_job(testcase.job_type):
      # ChromeOS fuzzers run on Linux platform, so use correct OS-Chrome for
      # tracking.
      issue.add_label('OS-Chrome')
    elif testcase.platform_id:
      os_label = 'OS-%s' % ((testcase.platform_id.split(':')[0]).capitalize())
      issue.add_label(os_label)

    # Add view restrictions for internal job types.
    add_view_restrictions_if_needed(issue, testcase)

    if testcase.security_flag:
      # Apply labels specific to security bugs.
      issue.add_label('Restrict-View-SecurityTeam')
      issue.add_label('Type-Bug-Security')

      # Add reward labels if this is from an external fuzzer contribution.
      fuzzer = data_types.Fuzzer.query(
          data_types.Fuzzer.name == testcase.fuzzer_name).get()
      if fuzzer and fuzzer.external_contribution:
        issue.add_label('reward-topanel')
        issue.add_label('External-Fuzzer-Contribution')

      data_handler.update_issue_impact_labels(testcase, issue)
    else:
      # Apply labels for functional (non-security) bugs.
      if utils.sub_string_exists_in(NON_CRASH_TYPES, testcase.crash_type):
        # Non-crashing test cases shouldn't be assigned Pri-1.
        issue.add_label('Pri-2')
        issue.add_label('Type-Bug')
      else:
        # Default functional bug labels.
        issue.add_label('Pri-1')
        issue.add_label('Stability-Crash')
        issue.add_label('Type-Bug')

  # AOSP-specific labels.
  elif itm.project_name == 'android':
    if testcase.security_flag:
      # Security bug labels.
      issue.add_cc('security@android.com')
      issue.add_label('Type-Security')
      issue.add_label('Restrict-View-Commit')
    else:
      # Functional bug labels.
      issue.add_label('Type-Defect')

  # OSS-Fuzz specific labels.
  elif itm.project_name == 'oss-fuzz':
    if testcase.security_flag:
      # Security bug labels.
      issue.add_label('Type-Bug-Security')
    else:
      # Functional bug labels.
      issue.add_label('Type-Bug')

    if should_restrict_issue:
      issue.add_label('Restrict-View-Commit')

  # Add additional labels from the job definition and fuzzer.
  additional_labels = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_LABELS', testcase.job_type, testcase.fuzzer_name)
  for label in additional_labels:
    issue.add_label(label)

  # Add additional components from the job definition and fuzzer.
  automatic_components = data_handler.get_additional_values_for_variable(
      'AUTOMATIC_COMPONENTS', testcase.job_type, testcase.fuzzer_name)
  for component in automatic_components:
    issue.add_component(component)

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

  if itm.project_name == 'oss-fuzz' and ccs:
    # Add a reported label for deadline tracking.
    issue.add_label(reported_label())

    if issue.has_label_matching('Restrict-View-Commit'):
      issue.body += '\n\n' + DEADLINE_NOTE

    issue.body += '\n\n' + FIX_NOTE
    issue.body += '\n\n' + QUESTIONS_NOTE

  for cc in ccs:
    issue.add_cc(cc)

  # Add additional labels from testcase metadata.
  metadata_labels = utils.parse_delimited(
      testcase.get_metadata('issue_labels', ''),
      delimiter=',',
      strip=True,
      remove_empty=True)
  for label in metadata_labels:
    issue.add_label(label)

  issue.itm = itm
  issue.reporter = user_email
  issue.save()

  # Update the testcase with this newly created issue.
  testcase.bug_information = str(issue.id)
  testcase.put()

  data_handler.update_group_bug(testcase.group_id)

  return issue.id
