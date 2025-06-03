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

def _sample_data_bundle(name='some_bundle', bucket_name='some-data-bundle-bucket'):
  return data_types.DataBundle(
    name = name,
    bucket_name = bucket_name,
  )

def _data_bundles_equal(bundle, another_bundle):
  return bundle.name == another_bundle.name and bundle.bucket_name, another_bundle.bucket_name

def _sample_job_template(name='some-job', environment_string='some-env'):
  return data_types.JobTemplate(
    name = name,
    environment_string = environment_string,
  )

def _job_templates_equal(template, another_template):
  return template.name == another_template.name and template.environment_string == another_template.environment_string


def _sample_job(name='some-job', custom_binary_key='some-key', platform='some-platform'):
  return data_types.Job(
    name = name,
    custom_binary_key = custom_binary_key,
    platform = platform,
  )

def _jobs_equal(job, another_job):
  return job.name == another_job.name and job.custom_binary_key == another_job.custom_binary_key and job.platform == another_job.platform

def _sample_fuzzer(name='some-fuzzer', data_bundle_name='some-data-bundle', jobs=['some-job'], blobstore_key='some-key'):
  return data_types.Fuzzer(
    name = name,
    data_bundle_name = data_bundle_name,
    jobs = jobs,
    blobstore_key = blobstore_key,
  )

def _fuzzers_equal(fuzzer, another_fuzzer):
  return fuzzer.name == another_fuzzer.name and fuzzer.data_bundle_name == another_fuzzer.data_bundle_name and fuzzer.jobs == another_fuzzer.jobs and fuzzer.blobstore_key, another_fuzzer.blobstore_key

def _blob_is_present_in_gcs(blob_path):
  return storage.get(blob_path) is not None

def _blob_content_is_equal(blob_path, data):
  fetched_data = storage.read_data(blob_path)
  return data == fetched_data

@test_utils.with_cloud_emulators('datastore')
class TestEntitySerializationAndDeserializastion(unittest.TestCase):
  """Test the serialization and deserialization of entities."""

  def test_data_bundle_serializes_and_deserializes_correctly(self):
    """Test data_types.JobTemplate serialization/deserialization."""
    data_bundle = _sample_data_bundle()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle', None, None)
  
    serialized_data_bundle = entity_migrator._serialize(data_bundle)
    deserialized_data_bundle = entity_migrator._deserialize(serialized_data_bundle)

    self.assertTrue(_data_bundles_equal(data_bundle, deserialized_data_bundle))

  def test_jobs_serializes_and_deserializes_correctly(self):
    """Test data_types.JobTemplate serialization/deserialization."""
    job_template = _sample_job_template()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.JobTemplate, [], 'jobtemplate', None, None)
  
    serialized_job_template = entity_migrator._serialize(job_template)
    deserialized_job_template = entity_migrator._deserialize(serialized_job_template)

    self.assertTrue(_jobs_equal(job_template, deserialized_job_template))

  def test_jobs_serializes_and_deserializes_correctly(self):
    """Test data_types.Job serialization/deserialization."""
    job = _sample_job()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Job, ['custom_binary_key'], 'job', None, None)
  
    serialized_job = entity_migrator._serialize(job)
    deserialized_job = entity_migrator._deserialize(serialized_job)

    self.assertTrue(_jobs_equal(job, deserialized_job))

  def test_fuzzer_serializes_and_deserializes_correctly(self):
    """Test data_types.Fuzzer serialization/deserialization."""
    fuzzer = _sample_fuzzer()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Fuzzer, ['blobstore_key'], 'fuzzer', None, None)

    serialized_fuzzer = entity_migrator._serialize(fuzzer)
    deserialized_fuzzer = entity_migrator._deserialize(serialized_fuzzer)

    self.assertTrue(_fuzzers_equal(fuzzer, deserialized_fuzzer))

@test_utils.with_cloud_emulators('datastore')
class TestEntitiesAreCorrectlyExported(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.blobs_bucket = 'BLOBS_BUCKET'
    self.target_bucket = 'TARGET_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    os.environ['EXPORT_BUCKET'] = self.target_bucket
    storage.create_bucket_if_needed(self.blobs_bucket)
    storage.create_bucket_if_needed(self.target_bucket)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.get_gcs_path',
    ])

  def tearDown(self):
    shutil.rmtree(self.local_gcs_buckets_path, ignore_errors=True)

  def test_fuzzers_are_correctly_exported(self):
    fuzzer = _sample_fuzzer(
      name='some-fuzzer',
      data_bundle_name='some-bundle',
      jobs=['some-job'],
      blobstore_key='some-key')
    another_fuzzer = _sample_fuzzer(
      name='another-fuzzer',
      data_bundle_name='another-bundle',
      jobs=['another-job'],
      blobstore_key=None)
    fuzzer.put()
    another_fuzzer.put()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Fuzzer,
      ['blobstore_key'],
      'fuzzer',
      job_exporter.StorageRSync(),
      self.target_bucket)
    fuzzer_blob_data = b'some-data'
    fuzzer_blob_id = 'some-blob'
    fuzzer_proto_location = f'gs://{self.target_bucket}/fuzzer/{fuzzer.name}/entity.proto'
    blob_location = f'gs://{self.blobs_bucket}/{fuzzer_blob_id}'    
    another_fuzzer_proto_location = f'gs://{self.target_bucket}/fuzzer/{fuzzer.name}/entity.proto'
    anoter_fuzzer_blob_location = f'gs://{self.target_bucket}/fuzzer/{another_fuzzer.name}/blobstore_key'
    storage.write_data(fuzzer_blob_data, blob_location)

    self.mock.get_gcs_path.return_value = blob_location
    entity_migrator.export_entities()

    self.assertTrue(_blob_is_present_in_gcs(fuzzer_proto_location))
    serialized_fuzzer_proto = storage.read_data(fuzzer_proto_location)
    deserialized_fuzzer_proto = entity_migrator._deserialize(serialized_fuzzer_proto)
    self.assertTrue(_fuzzers_equal(fuzzer, deserialized_fuzzer_proto))
    
    self.assertTrue(_blob_is_present_in_gcs(blob_location))
    self.assertTrue(_blob_content_is_equal(blob_location, fuzzer_blob_data))

    self.assertTrue(_blob_is_present_in_gcs(another_fuzzer_proto_location))
    serialized_another_fuzzer_proto = storage.read_data(another_fuzzer_proto_location)
    deserialized_another_fuzzer_proto = entity_migrator._deserialize(serialized_another_fuzzer_proto)
    self.assertTrue(_fuzzers_equal(another_fuzzer, deserialized_another_fuzzer_proto))

    self.assertFalse(_blob_is_present_in_gcs(anoter_fuzzer_blob_location))

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

  def test_data_bundle_proto_is_uploaded_to_gcs(self):
    data_bundle = _sample_data_bundle()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle', job_exporter.StorageRSync(), self.mock_bucket)
    expected_path = f'gs://{self.mock_bucket}/bundle.proto'
    entity_migrator._serialize_entity_to_gcs(data_bundle, expected_path)
    deserialized_data_bundle = entity_migrator._deserialize_entity_from_gcs(expected_path)
    self.assertTrue(_data_bundles_equal(data_bundle, deserialized_data_bundle))

  def test_data_bundle_contents_are_rsynced_correctly(self):
    data_bundle = _sample_data_bundle()
    file_contents = b'some_data'
    data_bundle_bucket = data_bundle.bucket_name
    data_bundle_file_path = f'{data_bundle_bucket}/some_file'

    rsync_client = job_exporter.StorageRSync()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.DataBundle, [], 'databundle', rsync_client, self.mock_bucket)

    storage.create_bucket_if_needed(data_bundle_bucket)
    storage.write_data(file_contents, f'gs://{data_bundle_file_path}')

    target_bucket = 'migrated-bundle'
    expected_path = f'{target_bucket}/contents/some_file'
    
    storage.create_bucket_if_needed(target_bucket)
    entity_migrator._export_data_bundle_contents_if_applicable(data_bundle, target_bucket)
    rsynced_file_contents = storage.read_data(f'gs://{expected_path}')
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


@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterJobIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Job entitites."""

  def setUp(self):
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    self.mock_bucket = 'MOCK_BUCKET'
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    storage._provider().create_bucket(self.mock_bucket, None, None, None)
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.blobs.get_gcs_path',
    ])

  def test_fuzzer_proto_is_uploaded_to_gcs(self):
    fuzzer = _sample_fuzzer()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.Fuzzer, ['blobstore_key'], 'fuzzer', job_exporter.StorageRSync(), self.mock_bucket)
    expected_path = f'gs://{self.mock_bucket}/fuzzer.proto'
    entity_migrator._serialize_entity_to_gcs(fuzzer, expected_path)
    deserialized_fuzzer = entity_migrator._deserialize_entity_from_gcs(expected_path)
    self.assertTrue(_fuzzers_equal(fuzzer, deserialized_fuzzer))

  def test_blobstore_key_is_copied_correctly(self):
    fuzzer = _sample_fuzzer()
    original_blob_location = f'{self.mock_bucket}/original_blob'
    original_blob_contents = b'some data'
    expected_target_location = f'{self.mock_bucket}/blobstore_key'
    self.mock.get_gcs_path.return_value = f'gs://{original_blob_location}'
    entity_migrator = job_exporter.EntityMigrator(data_types.Fuzzer, ['blobstore_key'], 'fuzzer', job_exporter.StorageRSync(), self.mock_bucket)

    storage.write_data(original_blob_contents, f'gs://{original_blob_location}')
    entity_migrator._export_blobs(fuzzer, f'gs://{self.mock_bucket}')

    retrieved_blob = storage.read_data(f'gs://{expected_target_location}')
    self.assertEqual(original_blob_contents, retrieved_blob)