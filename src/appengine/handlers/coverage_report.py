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
"""Coverage Report viewer."""

import datetime
import re

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import fuzzer_stats
from handlers import base_handler
from libs import handler
from libs import helpers

VALID_DATE_REGEX = re.compile(r'^([0-9\-]+|latest)$')


def _get_project_report_url(job, date):
  """Return url for the report requested."""
  project = data_handler.get_project_name(job)
  if not project:
    return None

  if date == 'latest':
    date = None
  else:
    try:
      date = datetime.datetime.strptime(date, '%Y-%m-%d').date()
    except:
      raise helpers.EarlyExitException('Invalid date.', 400)

  info = fuzzer_stats.get_coverage_info(project, date)
  if not info:
    return None

  return info.html_report_url


def get_report_url(report_type, argument, date):
  """Get report url for a redirect from the coverage report handler."""
  # It's very easy to add support for per fuzzer reports, but we don't need it.
  if report_type != 'job':
    raise helpers.EarlyExitException('Invalid report type.', 400)

  job = argument
  if not job:
    raise helpers.EarlyExitException('Job name cannot be empty.', 400)

  if not data_types.Job.VALID_NAME_REGEX.match(job):
    raise helpers.EarlyExitException('Invalid job name.', 400)

  if not date or not VALID_DATE_REGEX.match(date):
    raise helpers.EarlyExitException('Invalid date.', 400)

  return _get_project_report_url(job, date)


class Handler(base_handler.Handler):
  """Coverage Report Handler."""

  # pylint: disable=unused-argument
  @handler.get(handler.HTML)
  def get(self, report_type=None, argument=None, date=None, extra=None):
    """Handle a get request."""
    report_url = get_report_url(report_type, argument, date)
    if report_url:
      return self.redirect(report_url)
    raise helpers.EarlyExitException('Failed to get coverage report.', 400)
