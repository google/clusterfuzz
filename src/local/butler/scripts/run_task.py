# Copyright 2024 Google LLC
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
"""Run a task locally."""

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def execute(args):
  """Reset testcases' groups."""
  del args
  environment.set_bot_environment()
  logs.configure('run_bot')

  delete_groups = set()
  for testcase_id in data_handler.get_open_testcase_id_iterator():
    try:
      testcase = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      # Already deleted.
      continue

    if not testcase.group_id:
      continue

    delete_groups.add(testcase.group_id)

    # Reset group information. Follows the same behavior as in grouper when
    # a testcase is ungrouped due to its group only containing itself.
    testcase.group_id = 0
    testcase.group_bug_information = 0
    testcase.is_leader = True

    # Ensure that the testcase passes through the grouper again before triage.
    testcase.set_metadata('ran_grouper', False, update_testcase=False)

    testcase.put()
    logs.info(
        f'Ungrouped testcase {testcase.key.id()} during script to reset groups.'
    )

  for group_id in delete_groups:
    data_handler.delete_group(group_id, update_testcases=False)
    logs.info(f'Deleted group {group_id} during script to reset groups.')
