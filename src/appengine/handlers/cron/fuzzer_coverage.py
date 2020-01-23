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

from config import local_config
from datastore import data_handler
from datastore import data_types
from datastore import ndb
from google_cloud_utils import storage
from handlers import base_handler
from libs import handler
from metrics import logs

_GCS_PROVIDER = storage.GcsProvider()


def _latest_report_info_dir(bucket):
  """Returns a GCS URL to the latest report info for the given bucket."""
  return 'gs://{0}/latest_report_info/'.format(bucket)


def _basename(gcs_path):
  """Returns the basename for the given path without file extension."""
  return os.path.splitext(os.path.basename(gcs_path))[0]


def _gcs_path(gcs_object):
  """Returns a GCS URL for the given GCS object."""
  return storage.get_cloud_storage_file_path(gcs_object['bucket'],
                                             gcs_object['name'])


def _read_json(url):
  """Returns a JSON obejct loaded from the given GCS url."""
  data = _GCS_PROVIDER.read_data(url)
  return json.loads(data)


def _coverage_information(summary_path, name, report_info):
  """Returns a CoverageInformation entity with coverage stats populated."""
  summary = _read_json(summary_path)
  date = datetime.datetime.strptime(
      report_info['report_date'], data_types.COVERAGE_INFORMATION_DATE_FORMAT).date()

  # |name| can be either a project qualified fuzz target name or a project name.
  cov_info = data_handler.get_coverage_information(
      name, date, create_if_needed=True)
  cov_info.fuzzer = name
  cov_info.date = date
  cov_info.functions_covered = summary['data'][0]['totals']['functions'][
      'covered']
  cov_info.functions_total = summary['data'][0]['totals']['functions']['count']
  cov_info.edges_covered = summary['data'][0]['totals']['regions']['covered']
  cov_info.edges_total = summary['data'][0]['totals']['regions']['count']

  # Link to a per project report as long as we don't have per fuzzer reports.
  cov_info.html_report_url = report_info['html_report_url']
  return cov_info


def _process_fuzzer_stats(fuzzer, project_info, project_name):
  """Processes coverage stats for a single fuzz target."""
  fuzzer_name = data_types.fuzz_target_project_qualified_name(
      project_name, _basename(fuzzer['name']))
  fuzzer_info_path = _gcs_path(fuzzer)
  logs.log(
      'Processing fuzzer stats for %s (%s).' % (fuzzer_name, fuzzer_info_path))
  return _coverage_information(fuzzer_info_path, fuzzer_name, project_info)


def _process_project_stats(project_info, project_name):
  """Processes coverage stats for a single project."""
  summary_path = project_info['report_summary_path']
  logs.log("Processing total stats for %s project (%s).",
           (project_name, summary_path))
  return _coverage_information(summary_path, project_name, project_info)


def _process_project(project):
  """Collects coverage information for all fuzz targets in the given project and
  the total stats for the project."""
  project_name = _basename(project['name'])
  logs.log('Processing coverage for %s project.' % project_name)
  report_info = _read_json(_gcs_path(project))

  # Iterate through report_info['fuzzer_stats_dir'] and prepare
  # CoverageInformation entities for invididual fuzz targets.
  entities = []
  for fuzzer in _GCS_PROVIDER.list_blobs(
      report_info['fuzzer_stats_dir'], recursive=False):
    entities.append(_process_fuzzer_stats(fuzzer, report_info, project_name))

  logs.log("Processed coverage for %d targets in %s project." % (len(entities),
                                                                 project_name))

  # Prepare CoverageInformation entity for the total project stats.
  entities.append(_process_project_stats(report_info, project_name))

  ndb.put_multi(entities)


def collect_fuzzer_coverage(bucket):
  """Actual implementation of the fuzzer coverage task."""
  url = _latest_report_info_dir(bucket)
  for project in _GCS_PROVIDER.list_blobs(url, recursive=False):
    _process_project(project)


class Handler(base_handler.Handler):
  """Collects the latest code coverage stats and links to reports."""

  @handler.check_cron()
  def get(self):
    """Handle a GET request."""
    try:
      logs.log('FuzzerCoverage task started.')
      config = local_config.GAEConfig()
      bucket = config.get('coverage.reports.bucket')
      collect_fuzzer_coverage(bucket)
      logs.log('FuzzerCoverage task finished successfully.')
    except:
      logs.log_error('FuzzerCoverage task failed.')
      raise
