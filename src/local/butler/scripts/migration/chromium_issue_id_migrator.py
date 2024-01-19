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
"""Migrate Chromium Issue Ids from Monorail to Buganizer."""

import csv

from google.cloud import ndb
from clusterfuzz._internal.datastore import data_types

# project_name = 'cluster-fuzz'

def execute(args):
  """Query Testcases of a project, and update the bug_information
  or group_bug_information fields to reflect the Buganizer issue
  id rather than the Monorail issue id."""
  
  issue_id_dict = get_monorail_buganizer_issue_id_dictionary()

  for testcase in data_types.Testcase.query(
      # only target testcases in single project
      data_types.Testcase.project_name == args.project_name,
  ):
    if testcase.bug_information:
      testcase.bug_information = ndb.StringProperty(issue_id_dict[testcase.bug_information])
    
    if testcase.group_bug_information:
      testcase.group_bug_information = ndb.IntegerProperty(issue_id_dict[testcase.group_bug_information])

    if args.non_dry_run:
      testcase.put()

"""Creates a mapping of monorail/buganiser issue ids

@type file_loc: str
@param file_loc: The file location of the csv to be converted into a dict
@rtype: dictionary
@returns: a dictionary where the key is a numeric monorail id
  and the value is a numeric buganizer id ({ monorail_id: buganizer_id })
"""
def get_monorail_buganizer_issue_id_dictionary(csv_filename):
  dict = {}
  # csv should be structured with no headers and contain two columns:
  # a monorail issue id, and a buganizer issue id (ex. row: "600469, 40003765")
  with open(csv_filename, 'r') as csvfile:
    reader = csv.reader(csvfile)
    fieldnames = ['monorail_id', 'buganizer_id']
    reader = csv.DictReader(csvfile, fieldnames=fieldnames)
    for row in reader:
      monorail_issue_id = row[fieldnames[0]]
      buganizer_issue_id = fieldnames[1]
      dict[monorail_issue_id] = row[buganizer_issue_id]

  return dict # { monorail_issue_id: buganizer_issue_id }
