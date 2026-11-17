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
from unittest import mock

from clusterfuzz._internal.cron import schedule_fuzz
from clusterfuzz._internal.datastore import data_types
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

    num_tasks = 5
    provider = schedule_fuzz.OssfuzzFuzzTaskProvider()
    tasks = provider.get_fuzz_tasks(num_tasks)
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

    provider = schedule_fuzz.OssfuzzFuzzTaskProvider()
    tasks = provider.get_fuzz_tasks(num_tasks=1)
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

    provider = schedule_fuzz.OssfuzzFuzzTaskProvider()
    tasks = provider.get_fuzz_tasks(num_tasks=1)
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

    provider = schedule_fuzz.OssfuzzFuzzTaskProvider()
    tasks = provider.get_fuzz_tasks(num_tasks=1)
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
    jobs = list(data_types.Job.query())
    provider = schedule_fuzz.ChromeFuzzTaskProvider(jobs)
    tasks = provider.get_fuzz_tasks(num_tasks=1)
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


class GetQueueSizeTest(unittest.TestCase):
  """Tests for get_queue_size."""

  def setUp(self):
    patcher = mock.patch('google.cloud.monitoring_v3.MetricServiceClient')
    self.mock_monitoring = patcher.start()
    self.addCleanup(patcher.stop)

  def test_filters_by_project(self):
    """Tests that the query only matches subscriptions in the given project,
    since the metrics scope can include other projects."""
    mock_point = mock.Mock()
    mock_point.value.int64_value = 42
    mock_series = mock.Mock()
    mock_series.points = [mock_point]
    mock_client = self.mock_monitoring.return_value
    mock_client.list_time_series.return_value = [mock_series]

    size = schedule_fuzz.get_queue_size(
        mock.Mock(),
        'test-project',
        'preprocess-swarming',
        __memoize_force__=True)

    self.assertEqual(size, 42)
    request = mock_client.list_time_series.call_args[1]['request']
    self.assertEqual(request['name'], 'projects/test-project')
    self.assertIn('resource.labels.project_id="test-project"',
                  request['filter'])
    self.assertIn('resource.labels.subscription_id="preprocess-swarming"',
                  request['filter'])


@test_utils.with_cloud_emulators('datastore')
class ScheduleChromeFuzzTasksSwarmingTest(unittest.TestCase):
  """Tests for per-platform Swarming queue routing in schedule_fuzz."""

  def setUp(self):
    data_types.FeatureFlag(id='swarming_remote_execution', enabled=True).put()
    data_types.Job(
        name='linux_batch_job', project='chromium', platform='LINUX').put()
    data_types.Job(
        name='mac_legacy_intel_job', project='chromium', platform='MAC').put()
    data_types.Job(
        name='android_emu_swarming_job',
        project='chromium',
        platform='ANDROID_EMULATOR',
        environment_string='IS_SWARMING_JOB = True').put()
    data_types.Job(
        name='mac_arm64_swarming_job',
        project='chromium',
        platform='MAC_ARM64',
        environment_string='IS_SWARMING_JOB = True').put()

    for job_name, platform in [
        ('linux_batch_job', 'LINUX'),
        ('mac_legacy_intel_job', 'MAC'),
        ('android_emu_swarming_job', 'ANDROID_EMULATOR'),
        ('mac_arm64_swarming_job', 'MAC_ARM64'),
    ]:
      data_types.FuzzerJob(
          job=job_name, platform=platform, fuzzer='libFuzzer',
          weight=1.0).put()

  @mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
  @mock.patch(
      'clusterfuzz._internal.cron.schedule_fuzz.get_queue_size', return_value=0)
  @mock.patch(
      'clusterfuzz._internal.google_cloud_utils.credentials.get_default',
      return_value=(mock.Mock(), 'test-project'))
  def test_schedules_swarming_jobs_into_isolated_platform_queues(
      self, unused_mock_creds, unused_mock_queue_size, mock_bulk_add):
    """Tests that MAC_ARM64 fuzz tasks publish to preprocess-swarming-mac-arm64
    while ANDROID_EMULATOR fuzz tasks publish to preprocess-swarming, and legacy
    MAC jobs are untouched."""
    schedule_fuzz.schedule_chrome_fuzz_tasks()

    jobs_by_queue = {}
    for call in mock_bulk_add.call_args_list:
      scheduled_tasks = call.args[0]
      queue_name = call.kwargs['queue']
      jobs_by_queue[queue_name] = {task.job for task in scheduled_tasks}

    self.assertEqual(jobs_by_queue['preprocess'], {'linux_batch_job'})
    self.assertEqual(jobs_by_queue['preprocess-swarming'],
                     {'android_emu_swarming_job'})
    self.assertEqual(jobs_by_queue['preprocess-swarming-mac-arm64'],
                     {'mac_arm64_swarming_job'})

  @mock.patch('clusterfuzz._internal.base.tasks.bulk_add_tasks')
  @mock.patch(
      'clusterfuzz._internal.cron.schedule_fuzz.get_queue_size', return_value=0)
  @mock.patch(
      'clusterfuzz._internal.google_cloud_utils.credentials.get_default',
      return_value=(mock.Mock(), 'test-project'))
  def test_mac_arm64_zero_flag_halts_only_mac_arm64_scheduling(
      self, unused_mock_creds, unused_mock_queue_size, mock_bulk_add):
    """Tests that setting swarming_preprocess_queue_size_limit_mac_arm64=0
    stops MAC_ARM64 fuzz scheduling without impacting preprocess-swarming."""
    data_types.FeatureFlag(
        id='swarming_preprocess_queue_size_limit_mac_arm64',
        enabled=True,
        value=0.0).put()

    schedule_fuzz.schedule_chrome_fuzz_tasks()

    scheduled_queues = {
        call.kwargs['queue'] for call in mock_bulk_add.call_args_list
    }
    self.assertIn('preprocess', scheduled_queues)
    self.assertIn('preprocess-swarming', scheduled_queues)
    self.assertNotIn('preprocess-swarming-mac-arm64', scheduled_queues)
