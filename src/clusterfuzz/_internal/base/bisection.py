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
"""Bisection infrastructure functions."""

from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.build_management import revisions
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.crash_analysis import severity_analyzer
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.system import environment


def _get_topic():
  """Get the Pub/Sub topic for publishing tasks."""
  return local_config.ProjectConfig().get('bisect_service.pubsub_topic')


def notify_bisection_invalid(testcase):
  """Notify the bisection infrastructure of a testcase getting into invalid
  state."""
  pubsub_topic = _get_topic()
  if not pubsub_topic:
    return

  pubsub_client = pubsub.PubSubClient()
  pubsub_client.publish(pubsub_topic, [
      pubsub.Message(b'', {
          'type': 'invalid',
          'testcase_id': str(testcase.key.id()),
      })
  ])


def request_bisection(testcase):
  """Request precise bisection."""
  pubsub_topic = _get_topic()
  if not pubsub_topic:
    return

  # Only request bisects for reproducible security bugs with a bug filed, found
  # by engine fuzzers.
  if not testcase.security_flag:
    return

  if testcase.fixed == 'NA':
    # Testcase got into an invalid state.
    notify_bisection_invalid(testcase)
    return

  if testcase.one_time_crasher_flag:
    return

  if not testcase.bug_information:
    return

  target = testcase.get_fuzz_target()
  if not target:
    return

  # Only make 1 request of each type per testcase.
  if (not testcase.get_metadata('requested_regressed_bisect') and
      _make_bisection_request(pubsub_topic, testcase, target, 'regressed')):
    testcase.set_metadata('requested_regressed_bisect', True)

  if (not testcase.get_metadata('requested_fixed_bisect') and
      _make_bisection_request(pubsub_topic, testcase, target, 'fixed')):
    testcase.set_metadata('requested_fixed_bisect', True)


def _check_commits(testcase, bisect_type, old_commit, new_commit):
  """Check old and new commit validity."""
  if old_commit != new_commit or build_manager.is_custom_binary():
    return old_commit, new_commit

  # Something went wrong during bisection for the same commit to be chosen for
  # both the start and end range.
  # Get the bisection infrastructure to re-bisect.
  if environment.is_running_on_app_engine():
    bucket_path = data_handler.get_value_from_job_definition(
        testcase.job_type, 'RELEASE_BUILD_BUCKET_PATH')
  else:
    bucket_path = build_manager.get_primary_bucket_path()
  revision_list = build_manager.get_revisions_list(bucket_path)

  last_tested_revision = testcase.get_metadata('last_tested_crash_revision')
  known_crash_revision = last_tested_revision or testcase.crash_revision

  if bisect_type == 'fixed':
    # Narrowest range: last crashing revision up to the latest build.
    return _get_commits(
        str(known_crash_revision) + ':' + str(revision_list[-1]),
        testcase.job_type)

  if bisect_type == 'regressed':
    # Narrowest range: first build to the first crashing revision.
    return _get_commits(
        str(revision_list[0]) + ':' + str(testcase.crash_revision),
        testcase.job_type)

  raise ValueError('Invalid bisection type: ' + bisect_type)


def _make_bisection_request(pubsub_topic, testcase, target, bisect_type):
  """Make a bisection request to the external bisection service. Returns whether
  or not a request was actually made."""
  if bisect_type == 'fixed':
    old_commit, new_commit = _get_commits(testcase.fixed, testcase.job_type)
  elif bisect_type == 'regressed':
    old_commit, new_commit = _get_commits(testcase.regression,
                                          testcase.job_type)
  else:
    raise ValueError('Invalid bisection type: ' + bisect_type)

  if not new_commit:
    # old_commit can be empty (i.e. '0' case), but new_commit should never be.
    return False

  old_commit, new_commit = _check_commits(testcase, bisect_type, old_commit,
                                          new_commit)

  reproducer = blobs.read_key(testcase.minimized_keys or testcase.fuzzed_keys)
  pubsub_client = pubsub.PubSubClient()
  pubsub_client.publish(pubsub_topic, [
      pubsub.Message(
          reproducer, {
              'type':
                  bisect_type,
              'project_name':
                  target.project,
              'sanitizer':
                  environment.SANITIZER_NAME_MAP[
                      environment.get_memory_tool_name(testcase.job_type)
                  ],
              'fuzz_target':
                  target.binary,
              'old_commit':
                  old_commit,
              'new_commit':
                  new_commit,
              'testcase_id':
                  str(testcase.key.id()),
              'issue_id':
                  testcase.bug_information,
              'crash_type':
                  testcase.crash_type,
              'crash_state':
                  testcase.crash_state,
              'security':
                  str(testcase.security_flag),
              'severity':
                  severity_analyzer.severity_to_string(
                      testcase.security_severity),
              'timestamp':
                  testcase.timestamp.isoformat(),
          })
  ])
  return True


def _get_commits(commit_range, job_type):
  """Get commits from range."""
  if not commit_range or commit_range == 'NA':
    return None, None

  start, end = revisions.get_start_and_end_revision(commit_range)
  components = revisions.get_component_range_list(start, end, job_type)
  if not components:
    return None, None

  commits = components[0]['link_text']

  if ':' not in commits:
    return commits, commits

  old_commit, new_commit = commits.split(':')
  if old_commit == '0':
    old_commit = ''

  return old_commit, new_commit
