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
"""Tests for coverage report."""
import datetime
import unittest

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import coverage_report


@test_utils.with_cloud_emulators('datastore')
class CoverageReportTest(unittest.TestCase):
  """Tests for coverage_report handler."""

  def setUp(self):
    helpers.patch_environ(self)

    self.today = datetime.datetime.utcnow().date()
    self.today_minus_2 = self.today - datetime.timedelta(days=2)

    job_info = data_types.Job(
        name='job1', environment_string='PROJECT_NAME = xyz_name')
    job_info.put()

    cov_info = data_types.CoverageInformation(
        fuzzer='xyz_name', date=self.today_minus_2)
    cov_info.html_report_url = 'https://report_for_xyz/20161019/index.html'
    cov_info.put()

    cov_info = data_types.CoverageInformation(
        fuzzer='xyz_name', date=self.today)
    cov_info.html_report_url = 'https://report_for_xyz/20161021/index.html'
    cov_info.put()

  def test_get_by_date(self):
    """Tests getting coverage report by date."""
    report_url = coverage_report.get_report_url('job', 'job1',
                                                self.today_minus_2.isoformat())
    expected_url = 'https://report_for_xyz/20161019/index.html'
    self.assertEqual(expected_url, report_url)

  def test_get_latest(self):
    """Tests getting latest coverage report."""
    report_url = coverage_report.get_report_url('job', 'job1', 'latest')
    expected_url = 'https://report_for_xyz/20161021/index.html'
    self.assertEqual(expected_url, report_url)

  def test_get_none(self):
    """Tests getting non-existant coverage report."""
    report_url = coverage_report.get_report_url('job', 'fake_job', 'latest')
    expected_url = None
    self.assertEqual(expected_url, report_url)


class HandlerAccessTest(unittest.TestCase):
  """Ensure the Handler enforces an access check before resolving the URL."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'libs.access.has_access',
        'handlers.coverage_report._get_project_report_url',
    ])

    self.flaskapp = flask.Flask('testflask')
    self.flaskapp.add_url_rule(
        '/coverage-report/<report_type>/<argument>/<date>',
        view_func=coverage_report.Handler.as_view('/coverage-report/'))
    self.app = webtest.TestApp(self.flaskapp)

  def test_access_check_runs_before_resolving_url(self):
    """Access denied returns 403, the URL is never resolved."""
    self.mock.has_access.return_value = False

    response = self.app.get(
        '/coverage-report/job/job1/latest',
        headers={'Accept': 'application/json'},
        expect_errors=True)

    self.assertEqual(403, response.status_int)
    self.mock.has_access.assert_called_once_with(job_type='job1')
    self.mock._get_project_report_url.assert_not_called()

  def test_access_granted_resolves_url(self):
    """Access granted forwards to the URL resolver."""
    self.mock.has_access.return_value = True
    self.mock._get_project_report_url.return_value = (
        'https://report.example/index.html')

    response = self.app.get('/coverage-report/job/job1/latest')

    self.assertEqual(302, response.status_int)
    self.assertEqual('https://report.example/index.html',
                     response.headers['Location'])
    self.mock.has_access.assert_called_once_with(job_type='job1')

  def test_invalid_job_name_rejected_before_access_check(self):
    """Invalid job names return 400 without invoking the access check."""
    response = self.app.get(
        '/coverage-report/job/bad name!/latest',
        headers={'Accept': 'application/json'},
        expect_errors=True)

    self.assertEqual(400, response.status_int)
    self.mock.has_access.assert_not_called()

  def test_invalid_report_type_rejected(self):
    """Non-job report types return 400."""
    response = self.app.get(
        '/coverage-report/fuzzer/job1/latest',
        headers={'Accept': 'application/json'},
        expect_errors=True)

    self.assertEqual(400, response.status_int)
    self.mock.has_access.assert_not_called()
