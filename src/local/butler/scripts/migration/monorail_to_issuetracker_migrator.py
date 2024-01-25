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
"""Migrate Issue Ids from Monorail to Issue Tracker."""

import csv
import os

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types

DEFAULT_BATCH_SIZE = 500


def execute(args):
  """Query Testcases of a project, and update the bug_information
  and/or group_bug_information fields to reflect the Issue Tracker issue
  id rather than the Monorail issue id."""

  # Read the required enviroment variables.
  file_loc = os.environ.get('FILE_LOC')
  if not file_loc:
    raise ValueError('Must specify FILE_LOC env variable')
  project_name = os.environ.get('PROJECT_NAME')
  if not project_name:
    raise ValueError('Must specify PROJECT_NAME env variable')
  batch_size = int(os.environ.get('BATCH_SIZE', DEFAULT_BATCH_SIZE))
  roll_back = os.environ.get('ROLL_BACK') == 'True'

  issue_id_dict = get_monorail_issuetracker_issue_id_dictionary(
      file_loc, roll_back)

  testcases = []

  for testcase in data_types.Testcase.query(
      # only target testcases in single project
      data_types.Testcase.project_name == project_name,):
    testcase_updated = False
    if testcase.bug_information and issue_id_dict.get(testcase.bug_information):
      testcase.bug_information = issue_id_dict[testcase.bug_information]
      testcase_updated = True

    if testcase.group_bug_information and issue_id_dict.get(
        testcase.group_bug_information):
      testcase.group_bug_information = (
          issue_id_dict[testcase.group_bug_information])
      testcase_updated = True

    if testcase_updated:
      print(f'We will update testcase id: {testcase.key.id()}')
      testcases.append(testcase)

    if args.non_dry_run and len(testcases) >= batch_size:
      ndb.put_multi(testcases)
      print(f'Updated {len(testcases)}')
      testcases = []

  if args.non_dry_run and len(testcases) > 0:
    ndb.put_multi(testcases)
    print(f'Updated {len(testcases)}')


def get_monorail_issuetracker_issue_id_dictionary(file_loc, roll_back):
  """Creates a mapping of monorail/issuetracker issue ids."""

  issue_id_dictionary = {}
  # csv should be structured with no headers and contain two columns:
  # a monorail issue id, and a issuetracker issue id
  # (ex. row: "600469, 40003765")
  with open(file_loc, 'r') as csvfile:
    reader = csv.reader(csvfile)
    for monorail_id, issuetracker_id in reader:
      if roll_back:
        issue_id_dictionary[issuetracker_id] = monorail_id
      else:
        issue_id_dictionary[monorail_id] = issuetracker_id

  return issue_id_dictionary
