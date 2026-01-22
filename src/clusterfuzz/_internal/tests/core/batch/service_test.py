# Copyright 2025 Google LLC
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
"""Tests for the batch service."""
import datetime
import unittest
from unittest import mock
import uuid

from google.cloud import batch_v1 as batch

from clusterfuzz._internal.batch import data_structures
from clusterfuzz._internal.batch import gcp
from clusterfuzz._internal.batch import service
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

# pylint: disable=protected-access,too-many-locals

UUIDS = [f'00000000-0000-0000-0000-{str(i).zfill(12)}' for i in range(100)]


def _get_expected_task_spec(batch_workload_spec):
  """Gets the task spec based on the batch workload spec."""
  runnable = batch.Runnable()
  runnable.container = batch.Runnable.Container()
  runnable.container.image_uri = batch_workload_spec.docker_image
  clusterfuzz_release = batch_workload_spec.clusterfuzz_release
  runnable.container.options = (
      '--memory-swappiness=40 --shm-size=1.9g --rm --net=host '
      '-e HOST_UID=1337 -P --privileged --cap-add=all '
      f'-e CLUSTERFUZZ_RELEASE={clusterfuzz_release} '
      '--name=clusterfuzz -e UNTRUSTED_WORKER=False -e UWORKER=True '
      '-e USE_GCLOUD_STORAGE_RSYNC=1 '
      '-e UWORKER_INPUT_DOWNLOAD_URL')
  runnable.container.volumes = ['/var/scratch0:/mnt/scratch0']
  task_spec = batch.TaskSpec()
  task_spec.runnables = [runnable]
  if batch_workload_spec.retry:
    task_spec.max_retry_count = 4
  else:
    task_spec.max_retry_count = gcp.DEFAULT_RETRY_COUNT
  task_spec.max_run_duration = datetime.timedelta(
      seconds=int(batch_workload_spec.max_run_duration[:-1]))

  return task_spec


def _set_preemptible(instance_policy, batch_workload_spec) -> None:
  """Sets the provisioning model for an instance policy based on whether the
  batch workload is preemptible."""
  if batch_workload_spec.preemptible:
    instance_policy.provisioning_model = (
        batch.AllocationPolicy.ProvisioningModel.PREEMPTIBLE)
  else:
    instance_policy.provisioning_model = (
        batch.AllocationPolicy.ProvisioningModel.STANDARD)


def _get_expected_allocation_policy(spec):
  """Returns the allocation policy for a BatchWorkloadSpec.

  This function constructs and returns a `batch.AllocationPolicy` object
  based on the provided `BatchWorkloadSpec`. The policy defines the
  configuration for the VM instances that will run the batch job, including
  the machine type, disk size, network settings, and service account.
  """
  disk = batch.AllocationPolicy.Disk()
  disk.image = 'batch-cos'
  disk.size_gb = spec.disk_size_gb
  disk.type = spec.disk_type
  instance_policy = batch.AllocationPolicy.InstancePolicy()
  instance_policy.boot_disk = disk
  instance_policy.machine_type = spec.machine_type
  _set_preemptible(instance_policy, spec)
  instances = batch.AllocationPolicy.InstancePolicyOrTemplate()
  instances.policy = instance_policy

  network_interface = batch.AllocationPolicy.NetworkInterface()
  network_interface.no_external_ip_address = True
  network_interface.network = spec.network
  network_interface.subnetwork = spec.subnetwork
  network_interfaces = [network_interface]
  network_policy = batch.AllocationPolicy.NetworkPolicy()
  network_policy.network_interfaces = network_interfaces

  allocation_policy = batch.AllocationPolicy()
  allocation_policy.instances = [instances]
  allocation_policy.network = network_policy
  service_account = batch.ServiceAccount(email=spec.service_account_email)  # pylint: disable=no-member
  allocation_policy.service_account = service_account
  return allocation_policy


def _get_expected_create_request(job_name_uuid, spec, input_urls):
  """Constructs and returns a `batch.CreateJobRequest` object.

  This function builds a complete `CreateJobRequest` for the GCP Batch service,
  incorporating the job name, project ID, region, task specifications (including
  docker image, options, and duration), allocation policy (VM type, disk, network,
  and service account), and a list of input URLs for task environments.
  """
  job_name = f'j-{job_name_uuid}'
  project_id = spec.project
  parent = f'projects/{project_id}/locations/{spec.gce_region}'

  task_spec = _get_expected_task_spec(spec)

  task_environments = [
      batch.Environment(variables={'UWORKER_INPUT_DOWNLOAD_URL': url})
      for url in input_urls
  ]

  task_group = batch.TaskGroup()
  task_group.task_count = len(input_urls)
  task_group.task_environments = task_environments
  task_group.task_spec = task_spec
  task_group.task_count_per_node = gcp.TASK_COUNT_PER_NODE

  job = batch.Job()
  job.task_groups = [task_group]
  job.allocation_policy = _get_expected_allocation_policy(spec)
  job.logs_policy = batch.LogsPolicy()
  job.logs_policy.destination = batch.LogsPolicy.Destination.CLOUD_LOGGING
  job.priority = spec.priority

  create_request = batch.CreateJobRequest()
  create_request.job = job
  create_request.job_id = job_name
  create_request.parent = parent
  return create_request


@test_utils.with_cloud_emulators('datastore')
class BatchServiceTest(unittest.TestCase):
  """Tests for BatchService."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.batch.gcp._batch_client',
        'clusterfuzz._internal.base.tasks.task_utils.get_command_from_module',
        'uuid.uuid4',
    ])
    self.mock.GcpBatchClient = mock.Mock(
    )  # Still need this for BatchService constructor
    self.mock_batch_client_instance = mock.Mock()
    self.mock._batch_client.return_value = self.mock_batch_client_instance
    self.batch_service = service.BatchService()
    self.mock.uuid4.side_effect = [uuid.UUID(u) for u in UUIDS]

  def test_create_uworker_main_batch_jobs(self):
    """Tests that create_uworker_main_batch_jobs works as expected."""
    # Create mock data.
    spec1 = service.BatchWorkloadSpec(
        clusterfuzz_release='release1',
        disk_size_gb=10,
        disk_type='type1',
        docker_image='image1',
        user_data='user_data1',
        service_account_email='email1',
        subnetwork='subnetwork1',
        preemptible=True,
        project='project1',
        machine_type='machine1',
        network='network1',
        gce_region='region1',
        priority=1,
        max_run_duration='1s',
        retry=False)
    spec2 = service.BatchWorkloadSpec(
        clusterfuzz_release='release2',
        disk_size_gb=20,
        disk_type='type2',
        docker_image='image2',
        user_data='user_data2',
        service_account_email='email2',
        subnetwork='subnetwork2',
        preemptible=False,
        project='project2',
        machine_type='machine2',
        network='network2',
        gce_region='region2',
        priority=0,
        max_run_duration='2s',
        retry=True)
    with mock.patch('clusterfuzz._internal.batch.service._get_specs_from_config'
                   ) as mock_get_specs_from_config:
      mock_get_specs_from_config.return_value = {
          ('command1', 'job1'): spec1,
          ('command2', 'job2'): spec2,
      }
      tasks = [
          data_structures.BatchTask('command1', 'job1', 'url1'),
          data_structures.BatchTask('command1', 'job1', 'url2'),
          data_structures.BatchTask('command2', 'job2', 'url3'),
      ]

      # Call the function.
      self.batch_service.create_uworker_main_batch_jobs(tasks)

      # Assert that create_job was called with the correct arguments.
      expected_create_request_1 = _get_expected_create_request(
          UUIDS[0], spec1, ['url1', 'url2'])
      expected_create_request_2 = _get_expected_create_request(
          UUIDS[1], spec2, ['url3'])
      self.mock_batch_client_instance.create_job.assert_has_calls([
          mock.call(expected_create_request_1),
          mock.call(expected_create_request_2),
      ])

  def test_create_uworker_main_batch_job(self):
    """Tests that create_uworker_main_batch_job works as expected."""
    # Create mock data.
    spec1 = service.BatchWorkloadSpec(
        clusterfuzz_release='release1',
        disk_size_gb=10,
        disk_type='type1',
        docker_image='image1',
        user_data='user_data1',
        service_account_email='email1',
        subnetwork='subnetwork1',
        preemptible=True,
        project='project1',
        machine_type='machine1',
        network='network1',
        gce_region='region1',
        priority=1,
        max_run_duration='1s',
        retry=False)
    with mock.patch('clusterfuzz._internal.batch.service._get_specs_from_config'
                   ) as mock_get_specs_from_config:
      mock_get_specs_from_config.return_value = {
          ('fuzz', 'job1'): spec1,
      }
      self.mock_batch_client_instance.create_job.return_value = 'job'
      self.mock.get_command_from_module.return_value = 'fuzz'

      # Call the function.
      result = self.batch_service.create_uworker_main_batch_job(
          'fuzz', 'job1', 'url1')

      # Assert that create_job was called with the correct arguments.
      expected_create_request = _get_expected_create_request(
          UUIDS[0], spec1, ['url1'])
      self.mock_batch_client_instance.create_job.assert_called_with(
          expected_create_request)
      self.assertEqual(result, 'job')


@test_utils.with_cloud_emulators('datastore')
class IsRemoteTaskTest(unittest.TestCase):
  """Tests for is_remote_task functionality."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.batch.service._get_specs_from_config',
    ])
    data_types.Job(name='job', platform='LINUX').put()

  def test_is_remote_task(self):
    """Tests that is_remote_task works as expected."""
    # Test when it is a remote task.
    self.mock._get_specs_from_config.return_value = {('fuzz', 'job'): True}
    self.assertTrue(service.is_remote_task('fuzz', 'job'))

    # Test when it is not a remote task.
    self.mock._get_specs_from_config.side_effect = ValueError
    self.assertFalse(service.is_remote_task('progression', 'job'))


if __name__ == '__main__':
  unittest.main()

# pylint: disable=protected-access


@test_utils.with_cloud_emulators('datastore')
class GetSpecsFromConfigTest(unittest.TestCase):
  """Tests for _get_specs_from_config."""

  def setUp(self):
    self.maxDiff = None
    self.job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    self.job.put()
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.random_weighted_choice',
    ])
    self.mock.random_weighted_choice.return_value = service.WeightedSubconfig(
        name='east4-network2',
        weight=1,
    )

  def test_nonpreemptible(self):
    """Tests that _get_specs_from_config works for non-preemptibles as
        expected."""
    spec = _get_spec_from_config('analyze', self.job.name)
    expected_spec = service.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=110,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/project_name/regions/us-east4/subnetworks/subnetworkname2',
        network='projects/project_name/global/networks/networkname2',
        gce_region='us-east4',
        project='test-clusterfuzz',
        preemptible=False,
        machine_type='n1-standard-1',
        priority=1,
        retry=True,
        max_run_duration='21600s',
    )

    self.assertCountEqual(spec, expected_spec)

  def test_fuzz_get_specs_from_config(self):
    """Tests that _get_specs_from_config works for fuzz tasks as expected."""
    job = data_types.Job(name='libfuzzer_chrome_asan', platform='LINUX')
    job.put()
    spec = _get_spec_from_config('fuzz', job.name)
    expected_spec = service.BatchWorkloadSpec(
        clusterfuzz_release='prod',
        docker_image='gcr.io/clusterfuzz-images/base:a2f4dd6-202202070654',
        user_data='file://linux-init.yaml',
        disk_size_gb=75,
        disk_type='pd-standard',
        service_account_email='test-unpriv-clusterfuzz-service-account-email',
        subnetwork=
        'projects/project_name/regions/us-east4/subnetworks/subnetworkname2',
        network='projects/project_name/global/networks/networkname2',
        gce_region='us-east4',
        project='test-clusterfuzz',
        preemptible=True,
        machine_type='n1-standard-1',
        priority=0,
        retry=False,
        max_run_duration='21600s',
    )

    self.assertCountEqual(spec, expected_spec)

  def test_corpus_pruning(self):
    """Tests that corpus pruning uses a spec of 24 hours and a different one
        than normal."""
    pruning_spec = _get_spec_from_config('corpus_pruning', self.job.name)
    self.assertEqual(pruning_spec.max_run_duration, f'{24 * 60 * 60}s')
    normal_spec = _get_spec_from_config('analyze', self.job.name)
    self.assertNotEqual(pruning_spec, normal_spec)
    job = data_types.Job(name='libfuzzer_chrome_msan', platform='LINUX')
    job.put()
    # This behavior is important for grouping batch alike tasks into a single
    # batch job.
    pruning_spec2 = _get_spec_from_config('corpus_pruning', job.name)
    self.assertEqual(pruning_spec, pruning_spec2)

  def test_get_specs_from_config_disk_size(self):
    """Tests that DISK_SIZE_GB is respected."""
    size = 500
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {size}\n',
        platform='LINUX',
        name='libfuzzer_asan_test').put()

    spec = service._get_specs_from_config(
        [service.BatchTask('fuzz', 'libfuzzer_asan_test', None)])
    self.assertEqual(spec['fuzz', 'libfuzzer_asan_test'].disk_size_gb, size)

  def test_get_specs_from_config_no_disk_size(self):
    """Test that disk_size_gb isn't mandatory."""
    data_types.Job(platform='LINUX', name='libfuzzer_asan_test').put()
    spec = service._get_specs_from_config(
        [service.BatchTask('fuzz', 'libfuzzer_asan_test', None)])
    conf = service._get_batch_config()
    expected_size = (
        conf.get('mapping')['LINUX-PREEMPTIBLE-UNPRIVILEGED']['disk_size_gb'])
    self.assertEqual(spec['fuzz', 'libfuzzer_asan_test'].disk_size_gb,
                     expected_size)

  def test_get_specs_from_config_with_disk_size_override(self):
    """Tests that disk_size_gb can be overridden by the job environment."""
    job_name = 'libfuzzer_asan_test'
    original_size = 75
    overridden_size = 200
    # First, create a job with the original disk size
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {original_size}\n',
        platform='LINUX',
        name=job_name).put()

    # Then override it by creating a new job with a larger disk size
    data_types.Job(
        environment_string=f'DISK_SIZE_GB = {overridden_size}\n',
        platform='LINUX',
        name=job_name).put()

    spec = service._get_specs_from_config(
        [service.BatchTask('fuzz', job_name, None)])
    self.assertEqual(spec['fuzz', job_name].disk_size_gb, overridden_size)

  @mock.patch('clusterfuzz._internal.batch.service.utils.is_oss_fuzz')
  @mock.patch('clusterfuzz._internal.datastore.data_types.OssFuzzProject.query')
  @mock.patch('clusterfuzz._internal.datastore.ndb_utils.get_all_from_query')
  def test_get_config_names_os_version(self, mock_get_all_from_query,
                                       mock_oss_fuzz_project_query,
                                       mock_is_oss_fuzz):
    """Test the hierarchical logic for determining base_os_version."""
    # Test Case 1: Internal project, job-level OS version is used.
    mock_is_oss_fuzz.return_value = False
    job1 = data_types.Job(
        name='job1', platform='LINUX', base_os_version='job-os-ubuntu-20')
    mock_get_all_from_query.return_value = [job1]
    config_map = service._get_config_names(
        [service.BatchTask('fuzz', 'job1', None)])
    self.assertEqual(config_map[('fuzz', 'job1')][2], 'job-os-ubuntu-20')

    # Test Case 2: OSS-Fuzz project, project-level version overrides job-level.
    mock_is_oss_fuzz.return_value = True
    job2 = data_types.Job(
        name='job2',
        project='my-project',
        platform='LINUX',
        base_os_version='job-os-ubuntu-20')
    project = data_types.OssFuzzProject(
        name='my-project', base_os_version='project-os-ubuntu-24')
    mock_get_all_from_query.return_value = [job2]
    mock_oss_fuzz_project_query.return_value.get.return_value = project
    config_map = service._get_config_names(
        [service.BatchTask('fuzz', 'job2', None)])
    self.assertEqual(config_map[('fuzz', 'job2')][2], 'project-os-ubuntu-24')

    # Test Case 3: OSS-Fuzz project, only project-level version exists.
    job3 = data_types.Job(name='job3', project='my-project', platform='LINUX')
    mock_get_all_from_query.return_value = [job3]
    mock_oss_fuzz_project_query.return_value.get.return_value = project
    config_map = service._get_config_names(
        [service.BatchTask('fuzz', 'job3', None)])
    self.assertEqual(config_map[('fuzz', 'job3')][2], 'project-os-ubuntu-24')

    # Test Case 4: Internal project, no version is set, should be None.
    mock_is_oss_fuzz.return_value = False
    job4 = data_types.Job(name='job4', platform='LINUX')
    mock_get_all_from_query.return_value = [job4]
    config_map = service._get_config_names(
        [service.BatchTask('fuzz', 'job4', None)])
    self.assertIsNone(config_map[('fuzz', 'job4')][2])

    # Test Case 5: OSS-Fuzz project, but no versions are set anywhere.
    mock_is_oss_fuzz.return_value = True
    job5 = data_types.Job(
        name='job5', project='my-project-no-version', platform='LINUX')
    project_no_version = data_types.OssFuzzProject(name='my-project-no-version')
    mock_get_all_from_query.return_value = [job5]
    mock_oss_fuzz_project_query.return_value.get.return_value = project_no_version
    config_map = service._get_config_names(
        [service.BatchTask('fuzz', 'job5', None)])
    self.assertIsNone(config_map[('fuzz', 'job5')][2])


def _get_spec_from_config(command, job_name):
  return list(
      service._get_specs_from_config(
          [service.BatchTask(command, job_name, None)]).values())[0]
