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
from clusterfuzz._internal.tests.test_libs.helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.datastore import data_types

# pylint: disable=protected-access

@test_utils.with_cloud_emulators('datastore')
class OssfuzzFuzzTaskScheduler(unittest.TestCase):
  def setUp(self):
    self.job_name = 'myjob'
    project_name = 'myproject'
    dead_job = data_types.Job(name='dead_job', environment_string=f'PROJECT_NAME = {self.project_name}', 
                         )
    dead_job.put()
    job = data_types.Job(name=self.job_name, environment_string=f'PROJECT_NAME = {self.project_name}', 
)
    job.put()

    dead_project_job = data_types.Job(name='dead_project_job', environment_string=f'PROJECT_NAME = dead_project', 
                         )
    dead_project_job.put()
  
    dead_job = data_types.FuzzerJob(name='dead_job', weight=0.0, platform='LINUX')
    dead_job.put()
    job = data_types.FuzzerJob(self.job_name, platform='LINUX')
    job.put()
    dead_project_job = data_types.FuzzerJob('dead_project_job', platform='LINUX')
    dead_project_job.put()
    data_types.OssFuzzProject(name=self.project_name).put()
    data_types.OssFuzzProject(name='dead_project', cpu_weight=0.0).put()

    self.num_cpus = 10
    self.scheduler = schedule_fuzz.OssfuzzFuzzTaskScheduler(self.num_cpus)
    

  def test_get_fuzz_tasks(self):
    self.assertEqual(self.scheduler.get_fuzz_tasks(), [])


@test_utils.with_cloud_emulators('datastore')
class TestGetJobToOssfuzzProjectMapping(unittest.TestCase):
  def test_get_job_to_oss_fuzz_project_mapping(self):
    job = data_types.Job(name='job', environment_string='PROJECT_NAME = myproject')
    job.put()
    mapping = schedule_fuzz._get_job_to_oss_fuzz_project_mapping()
    self.assertDictEqual(mapping, {'job': 'myproject'})

      
  
class TestGetAvailableCpus(unittest.TestCase):
  """Tests for get_available_cpus."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.cron.schedule_fuzz._get_quotas'
    ])

  def test_usage(self):
    """Tests that get_available_cpus handles usage properly."""
    self.mock._get_quotas.return_value = [
      {'metric': 'PREEMPTIBLE_CPUS', 'limit': 5, 'usage': 2}
    ]
    self.assertEqual(schedule_fuzz.get_available_cpus('project', 'region'), 3)

  def test_cpus_and_preemptible_cpus(self):
    """Tests that get_available_cpus handles usage properly."""
    self.mock._get_quotas.return_value = [
      {'metric': 'PREEMPTIBLE_CPUS', 'limit': 5, 'usage': 0},
      {'metric': 'CPUS', 'limit': 5, 'usage': 5}
    ]
    self.assertEqual(schedule_fuzz.get_available_cpus('region', 'project'), 5)