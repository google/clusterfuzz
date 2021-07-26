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
"""Report upload task."""

import time

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.chrome import crash_uploader
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment


def execute_task(*_):
  """Execute the report uploads."""
  logs.log('Uploading pending reports.')

  # Get metadata for reports requiring upload.
  reports_metadata = ndb_utils.get_all_from_query(
      data_types.ReportMetadata.query(
          ndb_utils.is_false(data_types.ReportMetadata.is_uploaded)))
  reports_metadata = list(reports_metadata)
  if not reports_metadata:
    logs.log('No reports that need upload found.')
    return

  environment.set_value('UPLOAD_MODE', 'prod')

  # Otherwise, upload corresponding reports.
  logs.log('Uploading reports for testcases: %s' % str(
      [report.testcase_id for report in reports_metadata]))

  report_metadata_to_delete = []
  for report_metadata in reports_metadata:
    # Convert metadata back into actual report.
    crash_info = crash_uploader.crash_report_info_from_metadata(report_metadata)
    testcase_id = report_metadata.testcase_id

    try:
      _ = data_handler.get_testcase_by_id(testcase_id)
    except errors.InvalidTestcaseError:
      logs.log_warn('Could not find testcase %s.' % testcase_id)
      report_metadata_to_delete.append(report_metadata.key)
      continue

    # Upload the report and update the corresponding testcase info.
    logs.log('Processing testcase %s for crash upload.' % testcase_id)
    crash_report_id = crash_info.upload()
    if crash_report_id is None:
      logs.log_error(
          'Crash upload for testcase %s failed, retry later.' % testcase_id)
      continue

    # Update the report metadata to indicate successful upload.
    report_metadata.crash_report_id = crash_report_id
    report_metadata.is_uploaded = True
    report_metadata.put()

    logs.log('Uploaded testcase %s to crash, got back report id %s.' %
             (testcase_id, crash_report_id))
    time.sleep(1)

  # Delete report metadata entries where testcase does not exist anymore or
  # upload is not supported.
  if report_metadata_to_delete:
    ndb_utils.delete_multi(report_metadata_to_delete)

  # Log done with uploads.
  # Deletion happens in batches in cleanup_task, so that in case of error there
  # is some buffer for looking at stored ReportMetadata in the meantime.
  logs.log('Finished uploading crash reports.')
