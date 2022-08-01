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
"""Find CLs suspected of introducing regressions."""

import json
import re

import six

from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

SRC_COMPONENT_OVERRIDES = {
    'https://chromium.googlesource.com/v8/v8': 'v8',
}

UNINTERESTING_LINES_REGEX = re.compile(r'.*:(VERBOSE\d|INFO|WARNING):')


def _compute_rolls(start_revisions_dict, end_revisions_dict):
  """Compute rolls between the start and end revision."""
  result = []
  for path, entry in six.iteritems(end_revisions_dict):
    url, end_sha = _extract_url_and_sha_from_deps_entry(entry)
    start_sha = None
    if path in start_revisions_dict:
      start_entry = start_revisions_dict[path]
      _, start_sha = _extract_url_and_sha_from_deps_entry(start_entry)

    # Skip adding dependencies that were unchanged between the two DEPS files.
    if start_sha == end_sha:
      continue

    current_roll = {
        'dep_path': path,
        'repo_url': url,
        'new_revision': end_sha,
    }

    # Unless this is new code, include the earlier revision as well.
    if start_sha:
      current_roll['old_revision'] = start_sha

    result.append(current_roll)

  return result


def _extract_url_and_sha_from_deps_entry(entry):
  """Split a DEPS file entry into a URL and git sha."""
  assert 'url' in entry and 'rev' in entry, 'Unexpected format: %s' % entry
  url = entry['url']
  sha = entry['rev']

  # Strip unnecessary ".git" from the URL where applicable.
  if url.endswith('.git'):
    url = url[:-len('.git')]

  return url, sha


def _format_component_revisions_for_predator(component_revisions):
  """Convert a dict of dependency rolls to the format Predator expects."""
  result = []
  for path, entry in six.iteritems(component_revisions):
    url, sha = _extract_url_and_sha_from_deps_entry(entry)
    result.append({
        'dep_path': path,
        'repo_url': url,
        'revision': sha,
    })

  return result


def _is_predator_testcase(testcase):
  """Return bool and error message for whether this testcase is applicable to
  predator or not."""
  if build_manager.is_custom_binary():
    return False, 'Not applicable to custom binaries.'

  if testcase.regression != 'NA':
    if not testcase.regression:
      return False, 'No regression range, wait for regression task to finish.'

    if ':' not in testcase.regression:
      return False, 'Invalid regression range %s.' % testcase.regression

  return True, None


def _filter_stacktrace(stacktrace):
  """Reduces noise from stacktrace and limit its size to avoid pubsub request
  limit of one megabyte."""
  filtered_stacktrace_size = 0
  filtered_stacktrace_lines = []

  for line in reversed(stacktrace.splitlines()):
    # Exclude uninteresting lines such as ones from verbose logging, info, etc.
    if UNINTERESTING_LINES_REGEX.match(line):
      continue

    new_size = filtered_stacktrace_size + len(line) + 1
    if new_size > data_types.PUBSUB_REQUEST_LIMIT:
      break

    filtered_stacktrace_lines.append(line)
    filtered_stacktrace_size = new_size

  return '\n'.join(reversed(filtered_stacktrace_lines))


def _prepare_component_revisions_dict(revision, job_type):
  """Get a component revisions dict and git sha for a revision and job type.

  Revision is expected to be a commit position."""
  revisions_dict = revisions.get_component_revisions_dict(revision, job_type)
  if not revisions_dict:
    return revisions_dict, None

  # Other code depends on the "/" prefix, but it doesn't match the DEPS format
  # that we would usually expect. Clean these values up before sending to
  # predator.
  revisions_dict['src'] = revisions_dict.pop('/src')
  return revisions_dict, revisions_dict['src']['rev']


def _set_predator_result_with_error(testcase, error_message):
  """Sets predator result with error."""
  predator_result = {
      'result': {
          'found': False,
          'project': '',
          'suspected_components': '',
          'suspected_cls': '',
          'feedback_url': '',
          'error_message': error_message,
      }
  }

  testcase = data_handler.get_testcase_by_id(testcase.key.id())
  testcase.set_metadata(
      'predator_result', predator_result, update_testcase=False)
  testcase.delete_metadata('blame_pending', update_testcase=False)
  testcase.put()


def _prepare_predator_message(testcase):
  """Prepare the json sent to the Predator service for the given test case."""
  result, error_message = _is_predator_testcase(testcase)
  if not result:
    _set_predator_result_with_error(testcase, error_message)
    return None

  crash_revisions_dict, crash_revision_hash = _prepare_component_revisions_dict(
      testcase.crash_revision, testcase.job_type)
  # Do a None check since we can return {} for revision = 0.
  if crash_revisions_dict is None:
    _set_predator_result_with_error(
        testcase, 'Failed to fetch component revisions for revision %s.' %
        testcase.crash_revision)
    return None

  dependency_rolls = []
  start_revision_hash = end_revision_hash = None
  if ':' in testcase.regression:
    regression_parts = testcase.regression.split(':', 1)
    start_revision = int(regression_parts[0])
    end_revision = int(regression_parts[1])

    start_revisions_dict, start_revision_hash = (
        _prepare_component_revisions_dict(start_revision, testcase.job_type))
    # Do a None check since we can return {} for revision = 0.
    if start_revisions_dict is None:
      _set_predator_result_with_error(
          testcase, 'Failed to fetch component revisions for revision %s.' %
          start_revision)
      return None

    end_revisions_dict, end_revision_hash = (
        _prepare_component_revisions_dict(end_revision, testcase.job_type))
    # Do a None check since we can return {} for revision = 0.
    if end_revisions_dict is None:
      _set_predator_result_with_error(
          testcase,
          'Failed to fetch component revisions for revision %s.' % end_revision)
      return None

    if start_revision != 0:
      dependency_rolls = _compute_rolls(start_revisions_dict,
                                        end_revisions_dict)

  # Put the current revisions dictionary in the format predator expects.
  crash_revision_component_revisions_list = (
      _format_component_revisions_for_predator(crash_revisions_dict))

  # In addition to the start and end revisions, Predator expects the regression
  # range to include the dependency path and repository URL in the same way that
  # they would be included in the dependency rolls. Note that we do not take
  # this from the rolls dict directly as it may not be available.
  src_entry = [
      entry for entry in crash_revision_component_revisions_list
      if entry['dep_path'] == 'src'
  ][0]

  # TODO(mbarbella): This is a hack since ClusterFuzz relies on "src" as a
  # special-cased path, but this is only going to be the correct repository
  # root path some of the time. For certain cases, we must update it.
  repo_url = src_entry['repo_url']
  real_dep_path = SRC_COMPONENT_OVERRIDES.get(repo_url, 'src')
  if real_dep_path != 'src':
    for dependency_list in [
        dependency_rolls, crash_revision_component_revisions_list
    ]:
      for entry in dependency_list:
        if entry['dep_path'] == 'src':
          entry['dep_path'] = real_dep_path
          break

  regression_range = {
      'dep_path': real_dep_path,
      'repo_url': repo_url,
      'old_revision': start_revision_hash,
      'new_revision': end_revision_hash,
  }

  crash_stacktrace = _filter_stacktrace(data_handler.get_stacktrace(testcase))

  return pubsub.Message(
      data=json.dumps({
          'stack_trace': crash_stacktrace,
          'crash_revision': crash_revision_hash,
          'customized_data': {
              'regression_range': regression_range,
              'dependency_rolls': dependency_rolls,
              'dependencies': crash_revision_component_revisions_list,
              'crash_type': testcase.crash_type,
              'crash_address': testcase.crash_address,
              'sanitizer': environment.get_memory_tool_name(testcase.job_type),
              'security_flag': testcase.security_flag,
              'job_type': testcase.job_type,
              'testcase_id': testcase.key.id()
          },
          'platform': testcase.platform,
          'client_id': 'clusterfuzz',
          'signature': testcase.crash_state,
      }).encode('utf-8'))


def _clear_blame_result_and_set_pending_flag(testcase):
  """Clear blame result and set pending bit."""
  testcase.set_metadata('blame_pending', True, update_testcase=False)
  testcase.set_metadata('predator_result', None, update_testcase=False)
  testcase.put()


def execute_task(testcase_id, _):
  """Attempt to find the CL introducing the bug associated with testcase_id."""
  # Locate the testcase associated with the id.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  if not testcase:
    return

  # Make sure that predator topic is configured. If not, nothing to do here.
  topic = db_config.get_value('predator_crash_topic')
  if not topic:
    logs.log('Predator is not configured, skipping blame task.')
    return

  data_handler.update_testcase_comment(testcase, data_types.TaskState.STARTED)

  # Prepare pubsub message to send to predator.
  message = _prepare_predator_message(testcase)
  if not message:
    testcase = data_handler.get_testcase_by_id(testcase_id)
    data_handler.update_testcase_comment(
        testcase, data_types.TaskState.ERROR,
        'Failed to generate request for Predator')
    return

  # Clear existing results and mark blame result as pending.
  testcase = data_handler.get_testcase_by_id(testcase_id)
  _clear_blame_result_and_set_pending_flag(testcase)

  # Post request to pub sub.
  client = pubsub.PubSubClient()
  message_ids = client.publish(topic, [message])
  logs.log('Successfully published testcase %s to Predator. Message IDs: %s.' %
           (testcase_id, message_ids))
  data_handler.update_testcase_comment(testcase, data_types.TaskState.FINISHED)
