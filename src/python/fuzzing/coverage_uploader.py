# Copyright 2019 Google LLC
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
"""Uploads test cases from blackbox fuzzers for coverage collection."""

import os

from base import utils
from config import local_config
from google_cloud_utils import gsutil
from google_cloud_utils import storage
from metrics import logs
from system import environment
from system import shell

LIST_FILE_BASENAME = 'file_list.txt'
MAX_TESTCASE_DIRECTORY_SIZE = 1 * 1000 * 1000 * 1000  # 1 GB
TESTCASES_PER_DAY = 1000


def upload_testcases_if_needed(fuzzer_name, testcase_list, testcase_directory):
  """Upload test cases from the list to a cloud storage bucket."""
  bucket_name = local_config.ProjectConfig().get(
      'coverage.fuzzer-testcases.bucket')
  if not bucket_name:
    return

  # Only consider test cases in the output directory. We might upload too much
  # if we search the data directory as well, or have missing resources.
  # TODO(mbarbella): Support resources in data bundles.
  testcase_list = [
      os.path.relpath(testcase, testcase_directory)
      for testcase in testcase_list
      if testcase.startswith(testcase_directory)
  ]
  if not testcase_list:
    return

  # Bail out if this batch of test cases is too large.
  directory_size = shell.get_directory_size(testcase_directory)
  if directory_size >= MAX_TESTCASE_DIRECTORY_SIZE:
    return

  formatted_date = str(utils.utcnow().date())
  gcs_base_url = 'gs://{bucket_name}/{date}/{fuzzer_name}/'.format(
      bucket_name=bucket_name, date=formatted_date, fuzzer_name=fuzzer_name)

  runner = gsutil.GSUtilRunner()
  batch_directory_blobs = storage.list_blobs(gcs_base_url)
  total_testcases = 0
  for blob in batch_directory_blobs:
    if not blob.endswith(LIST_FILE_BASENAME):
      continue

    list_gcs_url = 'gs://{bucket}/{blob}'.format(bucket=bucket_name, blob=blob)
    data = storage.read_data(list_gcs_url)
    if not data:
      logs.log_error('Read no data from test case list at {gcs_url}'.format(
          gcs_url=list_gcs_url))
      continue

    total_testcases += len(data.splitlines())

    # If we've already uploaded enough test cases for this fuzzer today, return.
    if total_testcases >= TESTCASES_PER_DAY:
      return

  # Upload each batch of tests to its own unique sub-bucket.
  identifier = environment.get_value('BOT_NAME') + str(utils.utcnow())
  gcs_base_url += utils.string_hash(identifier)

  list_gcs_url = gcs_base_url + '/' + LIST_FILE_BASENAME
  if not storage.write_data('\n'.join(testcase_list), list_gcs_url):
    return

  runner.rsync(testcase_directory, gcs_base_url)
  logs.log('Synced {count} test cases to {gcs_url}'.format(
      count=len(testcase_list), gcs_url=gcs_base_url))
