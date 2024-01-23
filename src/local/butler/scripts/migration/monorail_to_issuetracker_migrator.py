# Copyright 2023 Google LLC
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

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types


def execute(args):
  """Query Testcases of a project, and update the bug_information
  and/or group_bug_information fields to reflect the Issue Tracker issue
  id rather than the Monorail issue id."""

  issue_id_dict = get_monorail_issuetracker_issue_id_dictionary()

  testcases = []

  for testcase in data_types.Testcase.query(
      # only target testcases in single project
      data_types.Testcase.project_name == args.project_name,):
    if testcase.bug_information and issue_id_dict.get(testcase.bug_information):
      testcase.bug_information = ndb.StringProperty(
          issue_id_dict[testcase.bug_information])

    if testcase.group_bug_information and issue_id_dict.get(
        testcase.group_bug_information):
      testcase.group_bug_information = ndb.IntegerProperty(
          issue_id_dict[testcase.group_bug_information])

    testcases.append(testcase)

    if args.non_dry_run and len(testcases) > 499:  # maximum batch size is 500
      ndb.put_multi(testcases)
      testcases = []

  if args.non_dry_run and len(testcases) > 0:
    ndb.put_multi(testcases)


def get_monorail_issuetracker_issue_id_dictionary(file_loc):
  """Creates a mapping of monorail/issuetracker issue ids."""

  issue_id_dictionary = {}
  # csv should be structured with no headers and contain two columns:
  # a monorail issue id, and a issuetracker issue id
  # (ex. row: "600469, 40003765")
  with open(file_loc, 'r') as csvfile:
    reader = csv.reader(csvfile)
    fieldnames = ['monorail_id', 'issuetracker_id']
    reader = csv.DictReader(csvfile, fieldnames=fieldnames)
    for row in reader:
      monorail_issue_id = row[fieldnames[0]]
      issuetracker_issue_id = row[fieldnames[1]]
      issue_id_dictionary[monorail_issue_id] = issuetracker_issue_id

  return issue_id_dictionary  # { monorail_issue_id: issuetracker_issue_id }
