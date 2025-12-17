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

  def test_os_version_precedence_project_over_job(self):
    """Tests that project version is prioritized over job version."""
    job_name = 'myjob'
    project_name = 'myproject'
    data_types.Job(
        name='dead_job',
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
    ).put()
    data_types.Job(
        name=job_name,
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
        base_os_version='job-version',
    ).put()
    data_types.Job(
        name='dead_project_job',
        environment_string='PROJECT_NAME = dead_project',
        platform='LINUX',
    ).put()

    data_types.FuzzerJob(
        job='dead_job', weight=0.0, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job=job_name, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job='dead_project_job', platform='LINUX', fuzzer='libFuzzer').put()

    data_types.OssFuzzProject(
        name=project_name, base_os_version='project-version').put()
    data_types.OssFuzzProject(name='dead_project', cpu_weight=0.0).put()

    scheduler = schedule_fuzz.OssfuzzFuzzTaskScheduler(num_cpus=2)
    tasks = scheduler.get_fuzz_tasks()
    self.assertEqual(len(tasks), 1)
    task = tasks[0]

    self.assertEqual(task.job, job_name)
    self.assertEqual(task.extra_info.get('base_os_version'), 'project-version')

  def test_os_version_fallback_to_job(self):
    """Tests that job version is used as a fallback."""
    job_name = 'myjob'
    project_name = 'myproject'
    data_types.Job(
        name='dead_job',
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
    ).put()
    data_types.Job(
        name=job_name,
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
        base_os_version='job-version',
    ).put()
    data_types.Job(
        name='dead_project_job',
        environment_string='PROJECT_NAME = dead_project',
        platform='LINUX',
    ).put()

    data_types.FuzzerJob(
        job='dead_job', weight=0.0, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job=job_name, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job='dead_project_job', platform='LINUX', fuzzer='libFuzzer').put()

    data_types.OssFuzzProject(name=project_name).put()
    data_types.OssFuzzProject(name='dead_project', cpu_weight=0.0).put()

    scheduler = schedule_fuzz.OssfuzzFuzzTaskScheduler(num_cpus=2)
    tasks = scheduler.get_fuzz_tasks()
    self.assertEqual(len(tasks), 1)
    task = tasks[0]

    self.assertEqual(task.job, job_name)
    self.assertEqual(task.extra_info.get('base_os_version'), 'job-version')

  def test_os_version_no_version(self):
    """Tests that no os version is set when neither project nor job has one."""
    job_name = 'myjob'
    project_name = 'myproject'
    data_types.Job(
        name='dead_job',
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
    ).put()
    data_types.Job(
        name=job_name,
        environment_string=f'PROJECT_NAME = {project_name}',
        platform='LINUX',
        base_os_version=None,
    ).put()
    data_types.Job(
        name='dead_project_job',
        environment_string='PROJECT_NAME = dead_project',
        platform='LINUX',
    ).put()

    data_types.FuzzerJob(
        job='dead_job', weight=0.0, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job=job_name, platform='LINUX', fuzzer='libFuzzer').put()
    data_types.FuzzerJob(
        job='dead_project_job', platform='LINUX', fuzzer='libFuzzer').put()

    data_types.OssFuzzProject(name=project_name).put()
    data_types.OssFuzzProject(name='dead_project', cpu_weight=0.0).put()

    scheduler = schedule_fuzz.OssfuzzFuzzTaskScheduler(num_cpus=2)
    tasks = scheduler.get_fuzz_tasks()
    self.assertEqual(len(tasks), 1)
    task = tasks[0]

    self.assertEqual(task.job, job_name)
    self.assertIsNone(task.extra_info.get('base_os_version'))


@test_utils.with_cloud_emulators('datastore')
class ChromeFuzzTaskSchedulerTest(unittest.TestCase):
  """Tests for ChromeFuzzTaskScheduler."""

  def setUp(self):
    self.maxDiff = None
    self.job_name = 'myjob'

  def _setup_chrome_entities(self, job_os_version=None):
    """Set up entities for Chrome tests."""
    data_types.Job(
        name=self.job_name,
        project='chrome',
        platform='LINUX',
        base_os_version=job_os_version).put()
    data_types.FuzzerJob(
        job=self.job_name, platform='LINUX', fuzzer='libFuzzer',
        weight=1.0).put()

  def _run_and_get_task(self):
    """Runs the scheduler and returns the single task created."""
    scheduler = schedule_fuzz.ChromeFuzzTaskScheduler(num_cpus=2)
    tasks = scheduler.get_fuzz_tasks()
    self.assertEqual(len(tasks), 1)
    return tasks[0]

  def test_os_version_from_job(self):
    """Tests that the os version is correctly read from the job."""
    self._setup_chrome_entities(job_os_version='job-version')
    task = self._run_and_get_task()
    self.assertEqual(task.extra_info.get('base_os_version'), 'job-version')

  def test_os_version_job_without_version(self):
    """Tests that no os version is set when the job has none."""
    self._setup_chrome_entities()
    task = self._run_and_get_task()
    self.assertIsNone(task.extra_info.get('base_os_version'))


class TestGetCpuUsage(unittest.TestCase):
  """Tests for get_cpu_limit_for_regions."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.cron.schedule_fuzz._get_quotas',
        'clusterfuzz._internal.config.local_config.ProjectConfig.get'
    ])
    self.creds = credentials.get_default()

  def test_usage(self):
    """Tests that get_cpu_limit_for_regions handles usage properly."""
    self.mock.get.return_value = 100_000
    self.mock._get_quotas.return_value = [{
        'metric': 'PREEMPTIBLE_CPUS',
        'limit': 5,
        'usage': 2
    }]
    self.assertEqual(
        schedule_fuzz.get_cpu_usage(self.creds, 'project', 'region'), (5, 2))

  def test_cpus_and_preemptible_cpus(self):
    """Tests that get_cpu_limit_for_regions handles usage properly."""
    self.mock.get.return_value = 100_000
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

  def test_config_limit(self):
    """Tests that the config limit is used."""
    self.mock.get.return_value = 2
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
        schedule_fuzz.get_cpu_usage(self.creds, 'region', 'project'), (2, 0))


@test_utils.with_cloud_emulators('datastore')
class ScheduleFuzzTasksTest(unittest.TestCase):
  """Tests for schedule_fuzz_tasks."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.cron.schedule_fuzz.get_available_cpus',
        'clusterfuzz._internal.cron.schedule_fuzz.get_fuzz_tasks',
        'clusterfuzz._internal.cron.schedule_fuzz.get_batch_regions',
        'clusterfuzz._internal.google_cloud_utils.batch.check_congestion_jobs',
        'clusterfuzz._internal.google_cloud_utils.batch.create_congestion_job',
        'clusterfuzz._internal.base.tasks.bulk_add_tasks',
    ])
    self.mock.get_batch_regions.return_value = ['us-central1']
    mock_job = unittest.mock.Mock()
    mock_job.name = 'congestion-job'
    self.mock.create_congestion_job.return_value = mock_job

  def test_is_congested_true(self):
    """Tests that scheduling stops when congested."""
    # Create 3 congestion jobs.
    for i in range(3):
      data_types.CongestionJob(job_id=f'job-{i}', region='us-central1').put()

    # Mock check_congestion_jobs to return 0 completed.
    self.mock.check_congestion_jobs.return_value = 0
    # Mock get_fuzz_tasks to return empty list (simulating no CPUs or other issues)
    self.mock.get_fuzz_tasks.return_value = []

    self.assertTrue(schedule_fuzz.schedule_fuzz_tasks())

    self.mock.get_fuzz_tasks.assert_called()
    # Verify called with empty regions list (2nd argument)
    # Args are (project, regions)
    call_args = self.mock.get_fuzz_tasks.call_args[0]
    self.assertEqual(call_args[1], [])

  def test_is_congested_false(self):
    """Tests that scheduling proceeds when not congested."""
    # Create 3 congestion jobs.
    for i in range(3):
      data_types.CongestionJob(job_id=f'job-{i}', region='us-central1').put()

    # Mock check_congestion_jobs to return 3 completed.
    self.mock.check_congestion_jobs.return_value = 3
    mock_task = unittest.mock.Mock()
    mock_task.job = 'job1'
    self.mock.get_fuzz_tasks.return_value = [mock_task]

    self.assertTrue(schedule_fuzz.schedule_fuzz_tasks())
    self.mock.get_fuzz_tasks.assert_called()

  def test_no_congestion_job_if_no_tasks(self):
    """Tests that no congestion job is scheduled if no fuzz tasks."""
    self.mock.get_fuzz_tasks.return_value = []

    self.assertTrue(schedule_fuzz.schedule_fuzz_tasks())
    self.mock.create_congestion_job.assert_not_called()

  def test_congestion_job_scheduled(self):
    """Tests that a congestion job is scheduled when fuzz tasks are."""
    mock_task = unittest.mock.Mock()
    mock_task.job = 'job1'
    self.mock.get_fuzz_tasks.return_value = [mock_task]

    self.assertTrue(schedule_fuzz.schedule_fuzz_tasks())
    self.mock.create_congestion_job.assert_called_with(
        'job1', gce_region='us-central1')
