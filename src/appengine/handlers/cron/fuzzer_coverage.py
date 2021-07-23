# Copyright 2020 Google LLC
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
"""Cron job to get the latest code coverage stats and HTML reports."""

import datetime
import json
import os

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler


def _latest_report_info_dir(bucket):
  """Returns a GCS URL to the latest report info for the given bucket."""
  return 'gs://{0}/latest_report_info/'.format(bucket)


def _basename(gcs_path):
  """Returns the basename for the given path without file extension."""
  return os.path.splitext(os.path.basename(gcs_path))[0]


def _read_json(url):
  """Returns a JSON obejct loaded from the given GCS url."""
  data = storage.read_data(url)

  result = None
  try:
    result = json.loads(data)
  except Exception as e:
    logs.log_warn(
        'Empty or malformed code coverage JSON (%s): %s.' % (url, str(e)))

  return result


def _coverage_information(summary_path, name, report_info):
  """Returns a CoverageInformation entity with coverage stats populated."""
  date = datetime.datetime.strptime(
      report_info['report_date'],
      data_types.COVERAGE_INFORMATION_DATE_FORMAT).date()

  # |name| can be either a project qualified fuzz target name or a project name.
  cov_info = data_handler.get_coverage_information(
      name, date, create_if_needed=True)
  cov_info.fuzzer = name
  cov_info.date = date

  # Link to a per project report as long as we don't have per fuzzer reports.
  cov_info.html_report_url = report_info['html_report_url']

  summary = _read_json(summary_path)
  if not summary:
    # We can encounter empty JSON files for broken fuzz targets.
    return cov_info

  total_stats = summary['data'][0]['totals']
  cov_info.functions_covered = total_stats['functions']['covered']
  cov_info.functions_total = total_stats['functions']['count']
  cov_info.edges_covered = total_stats['regions']['covered']
  cov_info.edges_total = total_stats['regions']['count']

  return cov_info


def _process_fuzzer_stats(fuzzer, project_info, project_name, bucket):
  """Processes coverage stats for a single fuzz target."""
  fuzzer_name = data_types.fuzz_target_project_qualified_name(
      project_name, _basename(fuzzer))
  fuzzer_info_path = storage.get_cloud_storage_file_path(bucket, fuzzer)
  logs.log(
      'Processing fuzzer stats for %s (%s).' % (fuzzer_name, fuzzer_info_path))
  return _coverage_information(fuzzer_info_path, fuzzer_name, project_info)


def _process_project_stats(project_info, project_name):
  """Processes coverage stats for a single project."""
  summary_path = project_info['report_summary_path']
  logs.log('Processing total stats for %s project (%s).' % (project_name,
                                                            summary_path))
  return _coverage_information(summary_path, project_name, project_info)


def _process_project(project, bucket):
  """Collects coverage information for all fuzz targets in the given project and
  the total stats for the project."""
  project_name = _basename(project)
  logs.log('Processing coverage for %s project.' % project_name)
  report_path = storage.get_cloud_storage_file_path(bucket, project)
  report_info = _read_json(report_path)
  if not report_info:
    logs.log_warn('Skipping code coverage for %s project.' % project_name)
    return

  # Iterate through report_info['fuzzer_stats_dir'] and prepare
  # CoverageInformation entities for invididual fuzz targets.
  entities = []
  for fuzzer in storage.list_blobs(
      report_info['fuzzer_stats_dir'], recursive=False):
    entities.append(
        _process_fuzzer_stats(fuzzer, report_info, project_name, bucket))

  logs.log('Processed coverage for %d targets in %s project.' % (len(entities),
                                                                 project_name))

  # Prepare CoverageInformation entity for the total project stats.
  entities.append(_process_project_stats(report_info, project_name))

  ndb_utils.put_multi(entities)


def collect_fuzzer_coverage(bucket):
  """Actual implementation of the fuzzer coverage task."""
  url = _latest_report_info_dir(bucket)
  for project in storage.list_blobs(url, recursive=False):
    _process_project(project, bucket)


class Handler(base_handler.Handler):
  """Collects the latest code coverage stats and links to reports."""

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    # The task is supposed to be super reliable and never fail. If anything goes
    # wrong, we just fail with the exception going straight into StackDriver.
    logs.log('FuzzerCoverage task started.')
    bucket = local_config.ProjectConfig().get('coverage.reports.bucket')
    if not bucket:
      logs.log(
          'Coverage bucket is not specified. Skipping FuzzerCoverage task.')
      return

    collect_fuzzer_coverage(bucket)
    logs.log('FuzzerCoverage task finished successfully.')
