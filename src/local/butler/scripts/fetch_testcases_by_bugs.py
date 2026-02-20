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
"""Fetch testcase IDs and timestamps from a list of bug IDs."""

import datetime
import json

from google.cloud import logging_v2

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils

bug_ids = [
    # 465902246,
    # 470163132,
    # 470405788,
    # 470447384,
    # 470593434,
    # 470610847,
    # 470800149,
    # 462921633,
    # 468430931,
    # 469977238,
    # 469996501,
    # 471001617,
    # 463709024,
    # 464828655,
    # 470442877,
    470621268,
    466561208,
    468768496,
    468920034,
    468138858,
    465192418,
    467517001,
    468760722,
    464099297,
    468765773,
    468829814,
    462557018,
    464965414,
    461314338,
    462331852,
    463497493,
    465184691,
    464471792,
    465611539,
    465623742,
    462549625,
    465802762,
    464819642,
    461821168,
    463046295,
    463119552,
    462828531,
    462673447,
    462782602,
    462549749,
    460575093,
    460333808,
    457877056,
    445773944,
    458105571,
    457027251,
    456979388,
    455006343,
    454944849,
    448211547,
    447580454,
    451655450,
    445845228,
    446027676,
    446057759,
    449549597,
    444537258,
]


def execute(args):
  """Fetch testcase IDs from bugs and download progreesion logs..."""

  task_name = 'progression'
  project_id = utils.get_logging_cloud_project_id()
  client = logging_v2.Client(project=project_id)
  start_time = utils.utcnow() - datetime.timedelta(days=31)

  for bug_id in bug_ids:
    query = data_types.Testcase.query(
        data_types.Testcase.bug_information == str(bug_id))
    testcases = list(ndb_utils.get_all_from_query(query))

    if not testcases:
      print(f'No testcase found for bug {bug_id}')
      continue
    testcase = testcases[0]

    testcase_id = str(testcase.key.id())
    print(
        f'Bug ID: {bug_id}, Testcase ID: {testcase_id}, Created: {testcase.timestamp}'
    )

    filter_str = (f'jsonPayload.extras.testcase_id="{testcase_id}" AND '
                  f'jsonPayload.extras.task_name="{task_name}"')
    filter_str += f' AND timestamp >= "{start_time.isoformat()}Z"'

    entries = client.list_entries(
        filter_=filter_str, max_results=500, order_by=logging_v2.DESCENDING)

    log_entries = [entry.to_api_repr() for entry in reversed(list(entries))]
    if not log_entries:
      print(f'\tNo logs found for bug.')
      continue
    output_filename = f'bug_{bug_id}_testcase_{testcase_id}.json'
    with open(f'{output_filename}', 'w') as f:
      json.dump(log_entries, f, indent=2)
    print(f'\tSaved logs to {output_filename}')
