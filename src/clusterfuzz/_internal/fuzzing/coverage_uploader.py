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

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.fuzzers import builtin_fuzzers
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.google_cloud_utils import gsutil
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment

LIST_FILE_BASENAME = 'file_list.txt'
TESTCASES_PER_DAY = 1000


def upload_testcases_if_needed(fuzzer_name, testcase_list, testcase_directory,
                               data_directory):
  """Upload test cases from the list to a cloud storage bucket."""
  # Since builtin fuzzers have a coverage minimized corpus, no need to upload
  # test case samples for them.
  if fuzzer_name in builtin_fuzzers.BUILTIN_FUZZERS:
    return

  bucket_name = local_config.ProjectConfig().get(
      'coverage.fuzzer-testcases.bucket')
  if not bucket_name:
    return

  files_list = []
  has_testcases_in_testcase_directory = False
  has_testcases_in_data_directory = False
  for testcase_path in testcase_list:
    if testcase_path.startswith(testcase_directory):
      files_list.append(os.path.relpath(testcase_path, testcase_directory))
      has_testcases_in_testcase_directory = True
    elif testcase_path.startswith(data_directory):
      files_list.append(os.path.relpath(testcase_path, data_directory))
      has_testcases_in_data_directory = True
  if not files_list:
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

    list_gcs_url = storage.get_cloud_storage_file_path(bucket_name, blob)
    data = storage.read_data(list_gcs_url)
    if not data:
      logs.log_error('Read no data from test case list at {gcs_url}'.format(
          gcs_url=list_gcs_url))
      continue

    total_testcases += len(data.splitlines())

    # If we've already uploaded enough test cases for this fuzzer today, return.
    if total_testcases >= TESTCASES_PER_DAY:
      return

  # Cap the number of files.
  testcases_limit = min(len(files_list), TESTCASES_PER_DAY - total_testcases)
  files_list = files_list[:testcases_limit]

  # Upload each batch of tests to its own unique sub-bucket.
  identifier = environment.get_value('BOT_NAME') + str(utils.utcnow())
  gcs_base_url += utils.string_hash(identifier)

  list_gcs_url = gcs_base_url + '/' + LIST_FILE_BASENAME
  if not storage.write_data('\n'.join(files_list).encode('utf-8'),
                            list_gcs_url):
    return

  if has_testcases_in_testcase_directory:
    # Sync everything in |testcase_directory| since it is fuzzer-generated.
    runner.rsync(testcase_directory, gcs_base_url)

  if has_testcases_in_data_directory:
    # Sync all fuzzer generated testcase in data bundle directory.
    runner.rsync(
        data_directory,
        gcs_base_url,
        exclusion_pattern=('(?!.*{fuzz_prefix})'.format(
            fuzz_prefix=testcase_manager.FUZZ_PREFIX)))

    # Sync all possible resource dependencies as a best effort. It matches
    # |resources-| prefix that a fuzzer can use to indicate resources. Also, it
    # matches resources directory that Chromium web_tests use for dependencies.
    runner.rsync(
        data_directory, gcs_base_url, exclusion_pattern='(?!.*resource)')

  logs.log('Synced {count} test cases to {gcs_url}.'.format(
      count=len(files_list), gcs_url=gcs_base_url))
