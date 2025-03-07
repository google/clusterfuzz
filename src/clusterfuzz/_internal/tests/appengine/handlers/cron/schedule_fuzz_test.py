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
"""Tests for schedule_fuzz.py"""

import unittest

from clusterfuzz._internal.cron import schedule_fuzz
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import credentials
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

# pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class OssfuzzFuzzTaskScheduler(unittest.TestCase):
  """Tests for OssfuzzFuzzTaskScheduler."""

  def setUp(self):
    self.maxDiff = None

  def test_get_fuzz_tasks(self):
    """"Tests that get_fuzz_tasks uses weights as intended."""
    # A lot of set up.
    job_name = 'myjob'
    project_name = 'myproject'
    dead_job = data_types.Job(
        name='dead_job',
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
    )
    dead_job.put()
    job = data_types.Job(
        name=job_name,
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
    )
    job.put()

    dead_project_job = data_types.Job(
        name='dead_project_job',
        environment_string='PROJECT_NAME = dead_project',
        platform='LINUX',
    )
    dead_project_job.put()

    dead_job = data_types.FuzzerJob(
        job='dead_job', weight=0.0, platform='LINUX', fuzzer='libFuzzer')
    dead_job.put()
    job = data_types.FuzzerJob(
        job=job_name, platform='LINUX', fuzzer='libFuzzer')
    job.put()
    dead_project_job = data_types.FuzzerJob(
        job='dead_project_job', platform='LINUX', fuzzer='libFuzzer')
    dead_project_job.put()
    data_types.OssFuzzProject(name=project_name).put()
    data_types.OssFuzzProject(name='dead_project', cpu_weight=0.0).put()

    num_cpus = 10
    scheduler = schedule_fuzz.OssfuzzFuzzTaskScheduler(num_cpus)
    tasks = scheduler.get_fuzz_tasks()
    comparable_results = []
    for task in tasks:
      comparable_results.append((task.command, task.argument, task.job))

    expected_results = [('fuzz', 'libFuzzer', 'myjob')] * 5
    self.assertListEqual(comparable_results, expected_results)


class TestGetCpuUsage(unittest.TestCase):
  """Tests for get_cpu_limit_for_regions."""

  def setUp(self):
    test_helpers.patch(self,
                       ['clusterfuzz._internal.cron.schedule_fuzz._get_quotas'])
    self.creds = credentials.get_default()

  def test_usage(self):
    """Tests that get_cpu_limit_for_regions handles usage properly."""
    self.mock._get_quotas.return_value = [{
        'metric': 'PREEMPTIBLE_CPUS',
        'limit': 5,
        'usage': 2
    }]
    self.assertEqual(
        schedule_fuzz.get_cpu_usage(self.creds, 'project', 'region'), (5, 2))

  def test_cpus_and_preemptible_cpus(self):
    """Tests that get_cpu_limit_for_regions handles usage properly."""
    self.mock._get_quotas.return_value = [{
        'metric': 'PREEMPTIBLE_CPUS',
        'limit': 5,
        'usage': 0
    }, {
        'metric': 'CPUS',
        'limit': 5,
        'usage': 5
    }]
    self.assertEqual(
        schedule_fuzz.get_cpu_usage(self.creds, 'region', 'project'), (5, 0))
