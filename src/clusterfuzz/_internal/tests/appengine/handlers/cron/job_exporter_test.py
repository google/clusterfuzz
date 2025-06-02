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
# pylint: disable=protected-access
"""Tests for the job exporter cronjob."""

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.cron import job_exporter
from clusterfuzz._internal.tests.test_libs import test_utils
import unittest
import os
import shutil
from clusterfuzz._internal.google_cloud_utils import storage
import tempfile
from clusterfuzz._internal.tests.test_libs import helpers

@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterDataBundleIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.mock_bucket = 'MOCK_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    storage._provider().create_bucket(self.mock_bucket, None, None, None)

  def tearDown(self):
    shutil.rmtree(self.local_gcs_buckets_path, ignore_errors=True)

  def _sample_data_bundle(self):
    bundle_name = 'some-bundle'
    return data_types.DataBundle(
      name = bundle_name,
      bucket_name = bundle_name,
    )
  
  def _assert_data_bundles_equal(self, bundle, another_bundle):
    self.assertEqual(bundle.name, another_bundle.name)
    self.assertEqual(bundle.bucket_name, another_bundle.bucket_name)

  def test_data_bundle_serializes_and_deserializes_correctly(self):
    """Test data_types.JobTemplate serialization/deserialization."""
    data_bundle = self._sample_data_bundle()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle')
  
    serialized_data_bundle = entity_migrator._serialize(data_bundle)
    deserialized_data_bundle = entity_migrator._deserialize(serialized_data_bundle)

    self._assert_data_bundles_equal(data_bundle, deserialized_data_bundle)

  def test_data_bundle_proto_is_uploaded_to_gcs(self):
    data_bundle = self._sample_data_bundle()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle')
    expected_path = f'gs://{self.mock_bucket}/bundle.proto'
    entity_migrator._serialize_entity_to_gcs(data_bundle, expected_path)
    deserialized_data_bundle = entity_migrator._deserialize_entity_from_gcs(expected_path)
    self._assert_data_bundles_equal(data_bundle, deserialized_data_bundle)

  def test_data_bundle_contents_are_rsynced_correctly(self):
    data_bundle = self._sample_data_bundle()
    file_contents = b'some_data'
    data_bundle_bucket = data_bundle.bucket_name
    data_bundle_file_path = f'{data_bundle_bucket}/some_file'

    rsync_client = job_exporter.StorageRSync()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle', rsync_client)

    storage.create_bucket_if_needed(data_bundle_bucket)
    entity_migrator._upload_bytes_to_gcs(file_contents, f'gs://{data_bundle_file_path}')

    target_bucket = 'migrated-bundle'
    expected_path = f'{target_bucket}/contents/some_file'
    
    storage.create_bucket_if_needed(target_bucket)
    entity_migrator._export_data_bundle_contents_if_applicable(data_bundle, target_bucket)
    rsynced_file_contents = entity_migrator._download_bytes_from_gcs(f'gs://{expected_path}')
    target_blobs = [blob for blob in storage.list_blobs(f'gs://{target_bucket}')]
    self.assertEqual(1, len(target_blobs))
    print(target_blobs)
    self.assertTrue('contents/some_file' in target_blobs)
    self.assertEquals(file_contents, rsynced_file_contents)

@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterJobTemplateIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.mock_bucket = 'MOCK_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    storage._provider().create_bucket(self.mock_bucket, None, None, None)

  def tearDown(self):
    pass

  def _sample_job_template(self):
    return data_types.JobTemplate(
      name = 'some-job',
      environment_string = 'some-env',
    )
  
  def _assert_job_templates_equal(self, template, another_template):
    self.assertEqual(template.name, another_template.name)
    self.assertEqual(template.environment_string,
                      another_template.environment_string)

  def test_jobs_serializes_and_deserializes_correctly(self):
    """Test data_types.JobTemplate serialization/deserialization."""
    job_template = self._sample_job_template()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.JobTemplate, [], 'jobtemplate')
  
    serialized_job_template = entity_migrator._serialize(job_template)
    deserialized_job_template = entity_migrator._deserialize(serialized_job_template)

    self._assert_job_templates_equal(job_template, deserialized_job_template)


@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterFuzzerIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.mock_bucket = 'MOCK_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    storage._provider().create_bucket(self.mock_bucket, None, None, None)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.get_gcs_path',
    ])

  def tearDown(self):
    pass

  def _sample_job(self):
    return data_types.Job(
      name = 'some-job',
      custom_binary_key = 'some-key',
      platform = 'some-platform'
    )
  
  def _assert_jobs_equal(self, job, another_job):
    self.assertEqual(job.name, another_job.name)
    self.assertEqual(job.custom_binary_key, another_job.custom_binary_key)
    self.assertEqual(job.platform, another_job.platform)

  def test_jobs_serializes_and_deserializes_correctly(self):
    """Test data_types.Job serialization/deserialization."""
    job = self._sample_job()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Job, ['custom_binary_key'], 'job')
  
    serialized_job = entity_migrator._serialize(job)
    deserialized_job = entity_migrator._deserialize(serialized_job)

    self._assert_jobs_equal(job, deserialized_job)

  def test_custom_binary_key_is_copied_correctly(self):
    job = self._sample_job()
    original_blob_location = f'{self.mock_bucket}/original_blob'
    original_blob_contents = b'some data'
    expected_target_location = f'{self.mock_bucket}/custom_binary_key'
    self.mock.get_gcs_path.return_value = f'gs://{original_blob_location}'
    entity_migrator = job_exporter.EntityMigrator(data_types.Job, ['custom_binary_key'], 'job')

    entity_migrator._upload_bytes_to_gcs(original_blob_contents, f'gs://{original_blob_location}')
    entity_migrator._export_blobs(job, f'gs://{self.mock_bucket}')

    retrieved_blob = entity_migrator._download_bytes_from_gcs(f'gs://{expected_target_location}')
    self.assertEqual(original_blob_contents, retrieved_blob)

@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterJobIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Job entitites."""

  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.mock_bucket = 'MOCK_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    storage._provider().create_bucket(self.mock_bucket, None, None, None)

  def tearDown(self):
    pass

  def _sample_fuzzer(self):
    return data_types.Fuzzer(
      name = 'some-fuzzer',
      data_bundle_name = 'some-data-bundle',
      jobs = ['some-job', 'another-job'],
      blobstore_key = 'some-blob-key'
    )
  
  def _assert_fuzzers_equal(self, fuzzer, another_fuzzer):
    self.assertEqual(fuzzer.name, another_fuzzer.name)
    self.assertEqual(fuzzer.data_bundle_name, another_fuzzer.data_bundle_name)
    self.assertEqual(fuzzer.jobs, another_fuzzer.jobs)
    self.assertEqual(fuzzer.blobstore_key, another_fuzzer.blobstore_key)

  def test_fuzzer_serializes_and_deserializes_correctly(self):
    """Test data_types.Fuzzer serialization/deserialization."""
    fuzzer = self._sample_fuzzer()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Fuzzer, ['blobstore_key'], 'fuzzer')

    serialized_fuzzer = entity_migrator._serialize(fuzzer)
    deserialized_fuzzer = entity_migrator._deserialize(serialized_fuzzer)

    self._assert_fuzzers_equal(fuzzer, deserialized_fuzzer)
