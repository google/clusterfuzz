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
