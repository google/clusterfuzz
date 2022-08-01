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

OLD_PROTOCOL = '1'  # Old message format: Data is a stacktrace.
NEW_PROTOCOL = '2'  # New message format: Data is a JSON array of stracktraces.


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


def handle_update(testcase, revision, stacktraces, error, protocol_version):
  """Handle update."""

  def is_still_crashing(st_index, stacktrace):
    """Check if the the given stackstrace indicates
      the testcase is still crashing"""
    state = stack_analyzer.get_crash_data(
        stacktrace,
        fuzz_target=fuzz_target_name,
        symbolize_flag=False,
        already_symbolized=True,
        detect_ooms_and_hangs=True)

    crash_comparer = CrashComparer(state.crash_state, testcase.crash_state)
    if not crash_comparer.is_similar():
      return False

    logs.log(f'State for trial {st_index} of {testcase_id} '
             f'remains similar'
             f'(old_state={testcase.crash_state}, '
             f'new_state={state.crash_state}).')

    is_security = crash_analyzer.is_security_issue(
        state.crash_stacktrace, state.crash_type, state.crash_address)
    if is_security != testcase.security_flag:
      return False

    logs.log(f'Security flag for trial {st_index} of {testcase_id} '
             f'still matches'
             f'({testcase.security_flag}).')
    return True

  testcase_id = testcase.key.id()
  logs.log('Got external update for testcase.', testcase_id=testcase_id)
  if error:
    _mark_errored(testcase, revision, error)
    return

  last_tested_revision = (
      testcase.get_metadata('last_tested_revision') or testcase.crash_revision)

  if revision < last_tested_revision:
    logs.log_warn(f'Revision {revision} less than previously tested '
                  f'revision {last_tested_revision}.')
    return

  if protocol_version not in [OLD_PROTOCOL, NEW_PROTOCOL]:
    logs.log_error(f'Invalid protocol_version provided: '
                   f'{protocol_version} '
                   f'is not one of {{{OLD_PROTOCOL, NEW_PROTOCOL}}} '
                   f'(testcase_id={testcase_id}).')
    return

  if not stacktraces:
    logs.log_error(f'Empty JSON stacktrace list provided '
                   f'(testcase_id={testcase_id}).')
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

  for st_index, stacktrace in enumerate(stacktraces):
    if is_still_crashing(st_index, stacktrace):
      logs.log(f'stacktrace {st_index} of {testcase_id} still crashes.')
      testcase.last_tested_crash_stacktrace = stacktrace
      data_handler.update_progression_completion_metadata(
          testcase, revision, is_crash=True)
      return

  # All trials resulted in a non-crash. Close the testcase.
  logs.log(f'No matching crash detected in {testcase_id} '
           f'over {len(stacktraces)} trials, marking as fixed.')
  _mark_as_fixed(testcase, revision)


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

    protocol_version = message.attributes.get('protocolVersion', OLD_PROTOCOL)
    if protocol_version == OLD_PROTOCOL:
      # Old: stacktrace is a str.
      stacktraces = [stacktrace]
      logs.log(f'Old format stacktrace string provided '
               f'(testcase_id={testcase_id}).')
    elif protocol_version == NEW_PROTOCOL:
      # New: stacktrace is a JSON array.
      stacktraces = json.loads(stacktrace)
      logs.log(f'New format stacktrace JSON list provided '
               f'(testcase_id={testcase_id}).')
    else:
      # Invalid: stacktrace is presumably ill-formed.
      stacktraces = []

    error = message.attributes.get('error')
    handle_update(testcase, revision, stacktraces, error, protocol_version)
    return 'OK'
