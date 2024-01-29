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
"""Migrate Issue Ids from Monorail to Issue Tracker.

Run locally with this command:

PROJECT_NAME=chromium [BATCH_SIZE=100] FILE_LOC=${mapping_file_location} \
    python butler.py run -c ${internal_config_dir} [--non-dry-run]  \
    migration.monorail_to_issuetracker_migrator

The mapping_file_location must point to a CSV file containing
"monorail_id,buganizer_id" in each line.
"""

import csv
import os

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types

# Values more than 100 resulted in this error:
# 400 Request payload size exceeds the limit: 11534336 bytes.
DEFAULT_BATCH_SIZE = 100

# Error returned by ndb when we go past the allowable datastore transaction
# limit.
PAYLOAD_SIZE_ERROR = '400 Request payload size exceeds the limit'


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
  print(f'Size of issue_id_dict: {len(issue_id_dict)}')

  testcases = []
  count_of_updated = 0

  for testcase in data_types.Testcase.query(
      # only target testcases in single project
      data_types.Testcase.project_name == project_name,):
    testcase_updated = False
    if testcase.bug_information and issue_id_dict.get(testcase.bug_information):
      testcase.bug_information = issue_id_dict[testcase.bug_information]
      testcase_updated = True

    if testcase.group_bug_information and issue_id_dict.get(
        str(testcase.group_bug_information)):
      # group_bug_information is an int unlike bug_information which is a str.
      testcase.group_bug_information = int(issue_id_dict[str(
          testcase.group_bug_information)])
      testcase_updated = True

    if testcase_updated:
      print(f'We will update testcase id: {testcase.key.id()}')
      testcases.append(testcase)

    if args.non_dry_run and len(testcases) >= batch_size:
      put_multi(testcases)
      count_of_updated += len(testcases)
      print(f'Updated {len(testcases)}. Total {count_of_updated}')
      testcases = []

  if args.non_dry_run and len(testcases) > 0:
    put_multi(testcases)
    count_of_updated += len(testcases)
    print(f'Updated {len(testcases)}. Total {count_of_updated}')


def put_multi(testcases):
  """Attempts to batch put the specified slice of testcases.

  If there is a 'payload size exceeds the limit' error then it will halve the
  testcases and try again. If that does not work then will go into a debugger.
  """
  try:
    ndb.put_multi(testcases)
  except Exception as e:
    if PAYLOAD_SIZE_ERROR in str(e) and len(testcases) > 1:
      half_batch_size = len(testcases) // 2
      print('Reached payload size limit. Retrying batch put with half the '
            f'specified batch size: {half_batch_size}')
      try:
        ndb.put_multi(testcases[:half_batch_size])
        ndb.put_multi(testcases[half_batch_size:])
      except Exception as ie:
        if PAYLOAD_SIZE_ERROR in str(ie):
          print(f'Got exception: {e}')
          print('Opening debugger to investigate further:')
          # pylint: disable=forgotten-debug-statement
          import pdb
          pdb.set_trace()
        raise
    else:
      raise


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
