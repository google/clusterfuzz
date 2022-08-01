# Copyright 2022 Google LLC
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
"""backfiler.py queries past testcases of the given projects
  and filed them to the projects' GitHub repository."""

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from libs.issue_management import oss_fuzz_github


def execute(args):
  """Query Testcases of the given projects,
    and conditionally file them to the corresponding GitHub repo."""
  if not args.script_args:
    print('Need at least one project name (with -p) '
          'when running the backfiler.')
    return
  for project_name in args.script_args:
    print(f'Back filing project {project_name}')
    for testcase in data_types.Testcase.query(
        ndb_utils.is_true(data_types.Testcase.open),
        ndb_utils.is_false(data_types.Testcase.one_time_crasher_flag),
        data_types.Testcase.status == 'Processed',
        data_types.Testcase.project_name == project_name,
    ):
      if not testcase.bug_information:
        print(f'Skip testcase without bugs: {testcase.key.id()}')
        continue
      print(f'Back filing testcase id: {testcase.key.id()}')
      if args.non_dry_run:
        oss_fuzz_github.file_issue(testcase)
        testcase.put()
