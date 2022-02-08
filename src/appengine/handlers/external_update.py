# Copyright 2021 Google LLC
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
"""External reproduction updates."""
import json

from clusterfuzz._internal.crash_analysis import crash_analyzer
from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler
from libs import helpers


def _mark_as_fixed(testcase, revision):
  """Mark bug as fixed."""
  testcase.open = False
  # Bisection not available for external reproduction infrastructure. Assume
  # range (crash revision : current revision).
  testcase.fixed = f'{testcase.crash_revision}:{revision}'
  data_handler.update_progression_completion_metadata(
      testcase, revision, message=f'fixed in r{revision}')


def _mark_errored(testcase, revision, error):
  """Mark testcase as errored out."""
  message = 'Received error from external infra, marking testcase as NA.'
  logs.log_warn(message, error=error, testcase_id=testcase.key.id())

  testcase.fixed = 'NA'
  testcase.open = False
  data_handler.update_progression_completion_metadata(
      testcase, revision, message=message)


def handle_update(testcase, revision, stacktraces, error):
  """Handle update."""
  logs.log('Got external update for testcase.', testcase_id=testcase.key.id())
  if error:
    _mark_errored(testcase, revision, error)
    return

  last_tested_revision = (
      testcase.get_metadata('last_tested_revision') or testcase.crash_revision)

  if revision < last_tested_revision:
    logs.log_warn(f'Revision {revision} less than previously tested '
                  f'revision {last_tested_revision}.')
    return

  fuzz_target = testcase.get_fuzz_target()
  if fuzz_target:
    fuzz_target_name = fuzz_target.binary
  else:
    fuzz_target_name = None

  # Record use of fuzz target to avoid garbage collection (since fuzz_task does
  # not run).
  data_handler.record_fuzz_target(fuzz_target.engine, fuzz_target.binary,
                                  testcase.job_type)
  states = [
      stack_analyzer.get_crash_data(
          stacktrace,
          fuzz_target=fuzz_target_name,
          symbolize_flag=False,
          already_symbolized=True,
          detect_ooms_and_hangs=True)
      for stacktrace in stacktraces
  ]

  crash_comparers = [
      CrashComparer(state.crash_state, testcase.crash_state)
      for state in states
  ]
  all_not_similar = True
  similar_indices = set()
  for comparer_index, crash_comparer in enumerate(crash_comparers):
    if crash_comparer.is_similar():
      all_not_similar = False
      similar_indices.add(comparer_index)
  if all_not_similar:
    logs.log(f'State no longer similar ('
             f'testcase_id={testcase.key.id()}, '
             f'old_state={testcase.crash_state}, '
             f'new_state={states[-1].crash_state})')
    _mark_as_fixed(testcase, revision)
    return

  are_security_issues = [
      crash_analyzer.is_security_issue(
          state.crash_stacktrace, state.crash_type, state.crash_address)
      for state in states
  ]
  all_not_security_issue = True
  issue_indices = set()
  for issue_index, is_security_issue in enumerate(are_security_issues):
    if is_security_issue == testcase.security_flag:
      all_not_security_issue = False
      issue_indices.add(issue_index)
  if all_not_security_issue:
    logs.log(f'Security flag for {testcase.key.id()} no longer matches.')
    _mark_as_fixed(testcase, revision)
    return

  logs.log(f'{testcase.key.id()} still crashes.')
  testcase.last_tested_crash_stacktrace = [
      stacktraces[stacktrace_index]
      for stacktrace_index in similar_indices.intersection(issue_indices)][-1]
  data_handler.update_progression_completion_metadata(
      testcase, revision, is_crash=True)


class Handler(base_handler.Handler):
  """External reproduction update."""

  @handler.pubsub_push
  def post(self, message):
    """Handle a post request."""
    testcase_id = message.attributes.get('testcaseId')
    if not testcase_id:
      raise helpers.EarlyExitException('Missing testcaseId.', 400)

    revision = message.attributes.get('revision')
    if not revision or not revision.isdigit():
      raise helpers.EarlyExitException('Missing revision.', 400)

    revision = int(revision)
    testcase = data_handler.get_testcase_by_id(testcase_id)
    job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
    if not job or not job.is_external():
      raise helpers.EarlyExitException('Invalid job.', 400)

    if message.data:
      stacktrace = message.data.decode()
    else:
      logs.log(f'No stacktrace provided (testcase_id={testcase_id}).')
      stacktrace = ''

    try:
      # New: stacktrace is a JSON array.
      stacktraces = json.loads(stacktrace)
      logs.log(f'New format stacktrace JSON list provided '
               f'(testcase_id={testcase_id}).')
      if not stacktrace:
        logs.log_error(f'Empty JSON stacktrace list provided '
                       f'(testcase_id={testcase_id}).')
    except json.decoder.JSONDecodeError:
      # Old: stacktrace is a str.
      stacktraces = [stacktrace]
      logs.log(f'Old format stacktrace string provided '
               f'(testcase_id={testcase_id}).')

    error = message.attributes.get('error')
    handle_update(testcase, revision, stacktraces, error)
    return 'OK'