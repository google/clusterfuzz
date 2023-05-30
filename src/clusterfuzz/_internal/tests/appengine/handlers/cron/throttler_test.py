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
# pylint: disable=protected-access
"""Tests for bug throttling."""

import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from src.appengine.handlers.cron.Throttler import Throttler

@test_utils.with_cloud_emulators('datastore')
class ThrottleBugTest(unittest.TestCase):
  """Tests for _throttle_bug."""

  def setUp(self):
    self.testcase = test_utils.create_generic_testcase()
    self.throttler = Throttler()
    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.IssueTrackerConfig.get',
        'clusterfuzz._internal.datastore.data_handler.get_issue_tracker_name',
        'clusterfuzz._internal.datastore.data_handler.get_project_name'
    ])
    self.mock.get_issue_tracker_name.return_value = 'project'
    self.mock.get_project_name.return_value = self.testcase.project_name
    data_types.Job(
        name=self.testcase.job_type,
        environment_string='MAX_BUGS_PER_24HRS = 2').put()
    self.mock.get.return_value = {'max_bugs_per_project_per_24hrs': 5}

  def test_throttle_bug_with_job_limit(self):
    """Tests the throttling bug with a job limit."""
    # The current count does not include bugs over 24 hours.
    data_types.FiledBug(
        project_name=self.testcase.project_name,
        job_type=self.testcase.job_type,
        timestamp=datetime.datetime.now() - datetime.timedelta(hours=30)).put()
    data_types.FiledBug(
        project_name=self.testcase.project_name,
        job_type=self.testcase.job_type,
        timestamp=datetime.datetime.now()).put()
    self.assertEqual(
        2,
        self.throttler._get_job_bugs_filing_max(self.testcase.job_type))
    self.assertFalse(
        self.throttler.should_throttle(self.testcase))
    self.assertTrue(
        self.throttler.should_throttle(self.testcase))

  def test_throttle_bug_with_project_limit(self):
    """Tests the throttling bug with a project limit."""
    testcase = test_utils.create_generic_testcase_variant()
    testcase.project_name = 'test_project'
    testcase.job_type = 'test_job_without_limit'
    self.mock.get_project_name.return_value = testcase.project_name
    data_types.FiledBug(
        project_name=testcase.project_name,
        job_type='test_job_without_limit',
        timestamp=datetime.datetime.now()).put()
    self.throttler._get_project_bugs_filing_max(testcase.job_type )
    self.assertEqual(
        5,
        self.throttler._get_project_bugs_filing_max(testcase.job_type))
    for _ in range(4):
      self.assertFalse(
          self.throttler.should_throttle(testcase))
    self.assertTrue(
        self.throttler.should_throttle(testcase))
