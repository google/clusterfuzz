# Copyright 2025 Google LLC
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
"""Script to backfill existing open oss-fuzz issues with the project cc group.

Inspired by oss_fuzz_apply_ccs.
"""

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.issue_management import issue_tracker_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

CC_GROUP_SUFFIX = '-ccs'


def get_open_testcases_with_bugs():
  """Return iterator to open testcases with bugs."""
  return data_types.Testcase.query(
      ndb_utils.is_true(data_types.Testcase.open),
      data_types.Testcase.status == 'Processed',
      data_types.Testcase.bug_information != '').order(  # pylint: disable=g-explicit-bool-comparison
          data_types.Testcase.bug_information, data_types.Testcase.key)


def get_project_cc_group(project_name: str) -> str:
  """Return issue tracker CC group email for a project."""
  group_domain = 'oss-fuzz.com'
  return f'{project_name}{CC_GROUP_SUFFIX}@{group_domain}'


def execute(args):
  """Backfill existing open oss-fuzz issues with the cc group."""
  del args
  environment.set_bot_environment()
  logs.configure('run_bot')
  print()

  testcases_failed = []
  for testcase in get_open_testcases_with_bugs():
    issue_tracker = issue_tracker_utils.get_issue_tracker_for_testcase(testcase)
    if not issue_tracker:
      logs.error(f'Failed to get issue tracker manager for {testcase.key.id()}')
      testcases_failed.append(testcase.key.id())
      continue

    try:
      issue = issue_tracker.get_original_issue(testcase.bug_information)
    except Exception as e:
      logs.error('Error occurred when fetching issue '
                 f'{testcase.bug_information} from {testcase.key.id()}: {e}')
      testcases_failed.append(testcase.key.id())
      continue

    if not issue or not issue.is_open:
      continue

    project_name = data_handler.get_project_name(testcase.job_type)
    if not project_name:
      logs.error(f'Failed to get project name from {testcase.key.id()}')
      continue

    project_cc_group = get_project_cc_group(project_name)
    if project_cc_group in issue.ccs:
      continue

    logs.info(f'CCing {project_cc_group} on issue {issue.id}')
    issue.ccs.add(project_cc_group)

    try:
      issue.save(notify=False)
    except Exception as e:
      testcases_failed.append(testcase.key.id())
      logs.error(f'Failed to apply ccs for testcase {testcase.key.id()}: {e}')

  if testcases_failed:
    # logging.error('OSS fuzz apply ccs failed.')
    return False

  logs.info('OSS fuzz apply ccs succeeded.')
  return True
