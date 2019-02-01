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
"""Handler for showing the testcase detail page."""

import cgi
import datetime
import jinja2
import re

from google.appengine.api import users

from base import utils
from build_management import revisions
from build_management import source_mapper
from config import db_config
from datastore import data_handler
from datastore import data_types
from fuzzing import leak_blacklist
from google_cloud_utils import blobs
from handlers import base_handler
from issue_management import issue_tracker_utils
from issue_management import label_utils
from libs import access
from libs import form
from libs import handler
from libs import helpers
from metrics import crash_stats
from system import environment

FIND_SIMILAR_ISSUES_OPTIONS = [{
    'type': 'open',
    'label': 'Open'
}, {
    'type': 'new',
    'label': 'New'
}, {
    'type': 'all',
    'label': 'All'
}]

CRASH_STATE_REGEXES = [
    r'bad-cast to (.+) from.*', r'bad-cast to (.+)', r'(.+) +in +.+'
]

COMPILED_CRASH_STATE_REGEXES = [
    re.compile(r, flags=re.IGNORECASE) for r in CRASH_STATE_REGEXES
]

MAX_PREVIEW_STACKTRACE_LINE_COUNT = 25


def _parse_suspected_cls(predator_result):
  """Parse raw suspected_cls into dict."""
  if not predator_result:
    return None

  # The raw result contains some additional information that we don't need here.
  # Everything we're concerned with is a part of the "result" object included
  # with the response.
  predator_result = predator_result['result']
  return {
      'found': predator_result.get('found'),
      'suspected_project': predator_result.get('suspected_project'),
      'suspected_components': predator_result.get('suspected_components'),
      'changelists': predator_result.get('suspected_cls'),
      'feedback_url': predator_result.get('feedback_url'),
      'error_message': predator_result.get('error_message'),
  }


def highlight_common_stack_frames(crash_stacktrace):
  """Highlights common stack frames between first two stacks."""
  crash_stacks = [[]]
  highlighted_crash_stacktrace_lines = []
  old_frame_no = 0
  stack_index = 0
  stack_trace_line_format = '^ *#([0-9]+) *0x[0-9a-f]+ (.*)'

  for line in crash_stacktrace.splitlines():
    # Stacktrace seperator prefix.
    if stack_index and line.startswith('+-'):
      break

    match = re.match(stack_trace_line_format, line)
    if match:
      frame_no = int(match.group(1))

      # This means we encountered another stack like free or alloc stack.
      if old_frame_no > frame_no:
        stack_index += 1
        crash_stacks.append([])

      crash_stacks[stack_index].append(match.group(2))
      old_frame_no = frame_no

  # If we have just one crash stack and no other stack,
  # then nothing to highlight.
  if stack_index == 0:
    return crash_stacktrace

  # Compare stack frames between first two stacks.
  match_index = -1
  start_index_crash_stack_1 = len(crash_stacks[0]) - 1
  start_index_crash_stack_2 = len(crash_stacks[1]) - 1
  while 1:
    if (crash_stacks[0][start_index_crash_stack_1] !=
        crash_stacks[1][start_index_crash_stack_2]):
      break

    match_index = [start_index_crash_stack_1, start_index_crash_stack_2]

    if not start_index_crash_stack_1:
      break
    if not start_index_crash_stack_2:
      break

    start_index_crash_stack_1 -= 1
    start_index_crash_stack_2 -= 1

  # No match found, nothing to highlight.
  if match_index == -1:
    return crash_stacktrace

  old_frame_no = 0
  stack_index = 0
  frame_index = -1
  for line in crash_stacktrace.splitlines():
    match = re.match(stack_trace_line_format, line)
    if match:
      frame_no = int(match.group(1))

      # This means we encountered another stack like free or alloc stack.
      if old_frame_no > frame_no:
        stack_index += 1
        frame_index = -1

      frame_index += 1
      old_frame_no = frame_no

      # We only care about highlighting the first two stacks.
      if stack_index <= 1 and frame_index >= match_index[stack_index]:
        line = '<b>%s</b>' % line

    highlighted_crash_stacktrace_lines.append(line)

  return '\n'.join(highlighted_crash_stacktrace_lines)


def filter_stacktrace(crash_stacktrace, crash_type, stack_clean_regex_lines,
                      revisions_dict):
  """Clean up and format a stack trace for display."""
  if not crash_stacktrace:
    return ''

  # Get stacktrace clean regex for filtering strings and even full lines.
  stack_clean_regex_list = filter(bool, stack_clean_regex_lines.splitlines())
  stack_clean_regex = (
      re.compile('(%s)' % '|'.join(stack_clean_regex_list))
      if stack_clean_regex_list else None)

  filtered_crash_lines = []
  for line in crash_stacktrace.splitlines():
    # Null out matched string from stacktrace clean regex.
    if stack_clean_regex:
      line = stack_clean_regex.sub('', line)
      if not line:
        continue

    # Html escape line content to prevent XSS.
    line = cgi.escape(line, quote=True)

    line = source_mapper.linkify_stack_frame(line, revisions_dict)

    filtered_crash_lines.append(line)

  filtered_crash_stacktrace = '\n'.join(filtered_crash_lines)

  if crash_type == leak_blacklist.DIRECT_LEAK_LABEL:
    return leak_blacklist.highlight_first_direct_leak(filtered_crash_stacktrace)

  return highlight_common_stack_frames(filtered_crash_stacktrace)


class Line(object):
  """Represent a stacktrace line."""

  def __init__(self, line_number, content, important):
    self.line_number = line_number
    self.content = content
    self.important = important

  def __str__(self):
    return 'Line(%d, "%s", %s)' % (self.line_number, self.content,
                                   self.important)

  def __eq__(self, other):
    return hash(self) == hash(other)

  def __hash__(self):
    return hash(self.__str__())

  def to_dict(self):
    return {
        'lineNumber': self.line_number,
        'content': self.content,
        'important': self.important,
        'type': 'Line'
    }


class Gap(object):
  """Represent a gap in a previewed stacktrace."""

  def __init__(self, size):
    self.size = size

  def __str__(self):
    return 'Gap(%d)' % self.size

  def __eq__(self, other):
    return hash(self) == hash(other)

  def __hash__(self):
    return hash(self.__str__())

  def to_dict(self):
    return {'type': 'Gap', 'size': self.size}


def _is_line_important(line_content, frames):
  """Check if the line contains a frame; it means the line is
     important."""
  for frame in frames:
    if frame in line_content:
      return True
  return False


def get_stack_frames(crash_state_lines):
  """Get the stack frames from the crash state. Sometimes the crash state
     contains a type of crash, e.g. 'Bad-cast to content::RenderWidget from
     content::RenderWidgetHostViewAura'. The stack frame is
     'content::RenderWidget'."""
  frames = []
  for line in crash_state_lines:
    added = False
    for regex in COMPILED_CRASH_STATE_REGEXES:
      matches = re.match(regex, line)
      if matches:
        frames.append(matches.group(1))
        added = True
        break

    if not added:
      frames.append(line)
  return frames


def convert_to_lines(raw_stacktrace, crash_state_lines, crash_type):
  """Convert an array of string to an array of Line."""
  if not raw_stacktrace or not raw_stacktrace.strip():
    return []

  raw_lines = raw_stacktrace.splitlines()

  frames = get_stack_frames(crash_state_lines)
  escaped_frames = [jinja2.escape(f) for f in frames]
  combined_frames = frames + escaped_frames

  # Certain crash types have their own customized frames that are not related to
  # the stacktrace. Therefore, we make our best effort to preview stacktrace
  # in a reasonable way; we preview around the the top of the stacktrace.
  for unique_type in data_types.CRASH_TYPES_WITH_UNIQUE_STATE:
    if crash_type.startswith(unique_type):
      combined_frames = ['ERROR']
      break

  lines = []
  for index, content in enumerate(raw_lines):
    important = _is_line_important(content, combined_frames)
    lines.append(Line(index + 1, content, important))
  return lines


def _preview_stacktrace(lines,
                        limit=MAX_PREVIEW_STACKTRACE_LINE_COUNT,
                        padding=7):
  """Preview stacktrace around crash_state."""
  preview_lines = set()
  length = len(lines)

  if length <= limit:
    return []

  for index, line in enumerate(lines):
    if line.important:
      this_preview_lines = set()

      for i in range(index - padding, index + padding + 1):
        if i < 0 or i >= length:
          continue
        this_preview_lines.add(lines[i])

      if (len(preview_lines | this_preview_lines)) <= limit:
        preview_lines |= this_preview_lines

  preview_lines = sorted(list(preview_lines), key=lambda l: l.line_number)
  preview_lines_with_gaps = []
  previous_line_number = 0

  for line in preview_lines:
    if (line.line_number - 1) > previous_line_number:
      preview_lines_with_gaps.append(
          Gap(line.line_number - previous_line_number - 1))

    preview_lines_with_gaps.append(line)
    previous_line_number = line.line_number

  if not preview_lines_with_gaps:
    return []

  if length > previous_line_number:
    preview_lines_with_gaps.append(Gap(length - previous_line_number))

  return preview_lines_with_gaps


def get_testcase_detail_by_id(testcase_id):
  """Get testcase detail for rendering the testcase detail page."""
  testcase = access.check_access_and_get_testcase(testcase_id)
  return get_testcase_detail(testcase)


def _get_revision_range_html_from_string(job_type, revision_range):
  """Return revision range html for a revision range and job type given a range
  string."""
  try:
    start_revision, end_revision = revision_range.split(':')
  except:
    return 'Bad revision range.'

  return _get_revision_range_html(job_type, start_revision, end_revision)


def _get_revision_range_html(job_type, start_revision, end_revision=None):
  """Return revision range html for a revision range and job type."""
  if end_revision is None:
    end_revision = start_revision

  component_rev_list = revisions.get_component_range_list(
      start_revision, end_revision, job_type)
  if not component_rev_list:
    return ('%s:%s (No component revisions found!)' % (start_revision,
                                                       end_revision))

  return revisions.format_revision_list(component_rev_list)


def _get_blob_size_string(blob_key):
  """Return blob size string."""
  if not blob_key or blob_key == 'NA':
    return ''

  try:
    blob_size = blobs.get_blob_size(blob_key)
    if blob_size is None:
      return ''
  except:
    return ''

  return utils.get_size_string(blob_size)


def get_testcase_detail(testcase):
  """Get testcase detail for rendering the testcase detail page."""
  config = db_config.get()
  crash_address = testcase.crash_address
  crash_state = testcase.crash_state
  crash_state_lines = crash_state.strip().splitlines()
  crash_type = data_handler.get_crash_type_string(testcase)
  reproduction_help_url = data_handler.get_reproduction_help_url(
      testcase, config)
  external_user = not access.has_access(job_type=testcase.job_type)
  issue_url = issue_tracker_utils.get_issue_url(testcase)
  metadata = testcase.get_metadata()
  original_testcase_size = _get_blob_size_string(testcase.fuzzed_keys)
  minimized_testcase_size = _get_blob_size_string(testcase.minimized_keys)
  stack_clean_regex_lines = config.stack_clean_regex
  has_issue_tracker = bool(data_handler.get_issue_tracker_name())

  if not testcase.regression:
    regression = 'Pending'
  elif testcase.regression == 'NA':
    regression = 'NA'
  else:
    regression = _get_revision_range_html_from_string(testcase.job_type,
                                                      testcase.regression)

  fixed_full = None
  if 'progression_pending' in metadata:
    fixed = 'Pending'
  elif not testcase.fixed:
    fixed = 'NO'
  elif testcase.fixed == 'NA':
    fixed = 'NA'
  elif testcase.fixed == 'Yes':
    fixed = 'YES'
  else:
    fixed = 'YES'
    fixed_full = _get_revision_range_html_from_string(testcase.job_type,
                                                      testcase.fixed)

  last_tested = None
  last_tested_revision = (
      metadata.get('last_tested_revision') or testcase.crash_revision)
  if last_tested_revision:
    last_tested = _get_revision_range_html(testcase.job_type,
                                           last_tested_revision)

  crash_revision = testcase.crash_revision
  crash_revisions_dict = revisions.get_component_revisions_dict(
      crash_revision, testcase.job_type)
  crash_stacktrace = data_handler.get_stacktrace(testcase)
  crash_stacktrace = filter_stacktrace(crash_stacktrace, testcase.crash_type,
                                       stack_clean_regex_lines,
                                       crash_revisions_dict)
  crash_stacktrace = convert_to_lines(crash_stacktrace, crash_state_lines,
                                      crash_type)
  crash_stacktrace_preview_lines = _preview_stacktrace(crash_stacktrace)

  second_crash_stacktrace_revision = metadata.get(
      'second_crash_stacktrace_revision')
  second_crash_stacktrace_revisions_dict = (
      revisions.get_component_revisions_dict(second_crash_stacktrace_revision,
                                             testcase.job_type))
  second_crash_stacktrace = data_handler.get_stacktrace(
      testcase, stack_attribute='second_crash_stacktrace')
  second_crash_stacktrace = filter_stacktrace(
      second_crash_stacktrace, testcase.crash_type, stack_clean_regex_lines,
      second_crash_stacktrace_revisions_dict)
  second_crash_stacktrace = convert_to_lines(second_crash_stacktrace,
                                             crash_state_lines, crash_type)
  second_crash_stacktrace_preview_lines = _preview_stacktrace(
      second_crash_stacktrace)

  last_tested_crash_revision = metadata.get('last_tested_crash_revision')
  last_tested_crash_revisions_dict = revisions.get_component_revisions_dict(
      last_tested_crash_revision, testcase.job_type)
  last_tested_crash_stacktrace = data_handler.get_stacktrace(
      testcase, stack_attribute='last_tested_crash_stacktrace')
  last_tested_crash_stacktrace = filter_stacktrace(
      last_tested_crash_stacktrace, testcase.crash_type,
      stack_clean_regex_lines, last_tested_crash_revisions_dict)
  last_tested_crash_stacktrace = convert_to_lines(last_tested_crash_stacktrace,
                                                  crash_state_lines, crash_type)
  last_tested_crash_stacktrace_preview_lines = _preview_stacktrace(
      last_tested_crash_stacktrace)

  privileged_user = access.has_access(need_privileged_access=True)

  # Fix build url link. |storage.cloud.google.com| takes care of using the
  # right set of authentication credentials needed to access the link.
  if 'build_url' in metadata:
    metadata['build_url'] = metadata['build_url'].replace(
        'gs://', 'https://storage.cloud.google.com/')

  pending_blame_task = (
      testcase.has_blame() and 'blame_pending' in metadata and
      metadata['blame_pending'])
  pending_impact_task = (
      testcase.has_impacts() and not testcase.is_impact_set_flag)
  pending_minimize_task = not testcase.minimized_keys
  pending_progression_task = ('progression_pending' in metadata and
                              metadata['progression_pending'])
  pending_regression_task = not testcase.regression
  pending_stack_task = testcase.last_tested_crash_stacktrace == 'Pending'
  needs_refresh = (
      testcase.status == 'Pending' or
      ((testcase.status == 'Processed' or testcase.status == 'Duplicate') and
       (pending_blame_task or pending_impact_task or pending_minimize_task or
        pending_progression_task or pending_regression_task or
        pending_stack_task)))

  if data_types.SecuritySeverity.is_valid(testcase.security_severity):
    security_severity = label_utils.severity_to_string(
        testcase.security_severity)
  else:
    security_severity = None

  auto_delete_timestamp = None
  auto_close_timestamp = None

  if testcase.one_time_crasher_flag:
    last_crash_time = (
        crash_stats.get_last_crash_time(testcase) or testcase.timestamp)

    # Set auto-delete timestamp for unreproducible testcases with
    # no associated bug.
    if not testcase.bug_information:
      auto_delete_timestamp = utils.utc_datetime_to_timestamp(
          last_crash_time + datetime.timedelta(
              days=data_types.UNREPRODUCIBLE_TESTCASE_NO_BUG_DEADLINE))

    # Set auto-close timestamp for unreproducible testcases with
    # an associated bug.
    if testcase.open and testcase.bug_information:
      auto_close_timestamp = utils.utc_datetime_to_timestamp(
          last_crash_time + datetime.timedelta(
              days=data_types.UNREPRODUCIBLE_TESTCASE_WITH_BUG_DEADLINE))

  memory_tool_display_string = environment.get_memory_tool_display_string(
      testcase.job_type)
  memory_tool_display_label = memory_tool_display_string.split(':')[0]
  memory_tool_display_value = memory_tool_display_string.split(':')[1].strip()

  helpers.log('Testcase %s' % testcase.key.id(), helpers.VIEW_OPERATION)
  return {
      'id': testcase.key.id(),
      'crash_type': crash_type,
      'crash_address': crash_address,
      'crash_state': crash_state,  # Used by reproduce tool.
      'crash_state_lines': crash_state_lines,
      'crash_revision': testcase.crash_revision,
      'csrf_token': form.generate_csrf_token(),
      'external_user': external_user,
      'footer': testcase.comments,
      'fixed': fixed,
      'fixed_full': fixed_full,
      'issue_url': issue_url,
      'is_admin': users.is_current_user_admin(),
      'metadata': metadata,
      'minimized_testcase_size': minimized_testcase_size,
      'needs_refresh': needs_refresh,
      'original_testcase_size': original_testcase_size,
      'privileged_user': privileged_user,
      'regression': regression,
      'crash_stacktrace': {
          'lines':
              crash_stacktrace,
          'preview_lines':
              crash_stacktrace_preview_lines,
          'revision':
              revisions.get_real_revision(
                  crash_revision, testcase.job_type, display=True)
      },
      'second_crash_stacktrace': {
          'lines':
              second_crash_stacktrace,
          'preview_lines':
              second_crash_stacktrace_preview_lines,
          'revision':
              revisions.get_real_revision(
                  second_crash_stacktrace_revision,
                  testcase.job_type,
                  display=True)
      },
      'last_tested_crash_stacktrace': {
          'lines':
              last_tested_crash_stacktrace,
          'preview_lines':
              last_tested_crash_stacktrace_preview_lines,
          'revision':
              revisions.get_real_revision(
                  last_tested_crash_revision, testcase.job_type, display=True)
      },
      'security_severity': security_severity,
      'security_severities': data_types.SecuritySeverity.list(),
      'stats': {
          'min_hour': crash_stats.get_min_hour(),
          'max_hour': crash_stats.get_max_hour(),
      },
      'suspected_cls': _parse_suspected_cls(metadata.get('predator_result')),
      'testcase': testcase,
      'timestamp': utils.utc_datetime_to_timestamp(testcase.timestamp),
      'show_blame': testcase.has_blame(),
      'show_impact': testcase.has_impacts(),
      'impacts_production': testcase.impacts_production(),
      'find_similar_issues_options': FIND_SIMILAR_ISSUES_OPTIONS,
      'auto_delete_timestamp': auto_delete_timestamp,
      'auto_close_timestamp': auto_close_timestamp,
      'memory_tool_display_label': memory_tool_display_label,
      'memory_tool_display_value': memory_tool_display_value,
      'last_tested': last_tested,
      'is_admin_or_not_oss_fuzz': is_admin_or_not_oss_fuzz(),
      'has_issue_tracker': has_issue_tracker,
      'reproduction_help_url': reproduction_help_url,
  }


def is_admin_or_not_oss_fuzz():
  """Return True if the current user is an admin or if this is not OSS-Fuzz."""
  return not utils.is_oss_fuzz() or users.is_current_user_admin()


class Handler(base_handler.Handler):
  """Handler that shows a testcase in detail."""

  def get(self, testcase_id):
    """Serve the testcase detail HTML page."""
    values = {'info': get_testcase_detail_by_id(testcase_id)}
    self.render('testcase-detail.html', values)


class DeprecatedHandler(base_handler.Handler):
  """Deprecated handler to show old style testcase link with key."""

  def get(self):
    """Serve the testcase details HTML page."""
    testcase_id = self.request.get('key')
    if not testcase_id:
      raise helpers.EarlyExitException('No testcase key provided.', 400)

    self.redirect('/testcase-detail/%s' % testcase_id)


class RefreshHandler(base_handler.Handler):
  """Handler that shows a testcase in detail through JSON."""

  @handler.post(handler.JSON, handler.JSON)
  @handler.oauth
  def post(self):
    """Serve the testcase detail HTML page."""
    testcase_id = self.request.get('testcaseId')
    self.render_json(get_testcase_detail_by_id(testcase_id))
