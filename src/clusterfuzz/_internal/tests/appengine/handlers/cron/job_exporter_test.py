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

import os
import shutil
import tempfile
import unittest

from clusterfuzz._internal.cron import job_exporter
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


def _sample_data_bundle(name='some_bundle',
                        bucket_name='some-data-bundle-bucket'):
  return data_types.DataBundle(
      name=name,
      bucket_name=bucket_name,
  )


def _data_bundles_equal(bundle, another_bundle):
  return (bundle.name == another_bundle.name and bundle.bucket_name,
          another_bundle.bucket_name)


def _sample_job_template(name='some-job', environment_string='some-env'):
  return data_types.JobTemplate(
      name=name,
      environment_string=environment_string,
  )


def _job_templates_equal(template, another_template):
  return (template.name == another_template.name and
          template.environment_string == another_template.environment_string)


def _sample_job(name='some-job',
                custom_binary_key='some-key',
                platform='some-platform'):
  return data_types.Job(
      name=name,
      custom_binary_key=custom_binary_key,
      platform=platform,
  )


def _jobs_equal(job, another_job):
  return (job.name == another_job.name and
          job.custom_binary_key == another_job.custom_binary_key and
          job.platform == another_job.platform)


def _sample_fuzzer(  # pylint: disable=dangerous-default-value
    name='some-fuzzer',
    data_bundle_name='some-data-bundle',
    jobs=['some-job'],
    blobstore_key='some-key',
    sample_testcase='some-testcase-key'):
  return data_types.Fuzzer(
      name=name,
      data_bundle_name=data_bundle_name,
      jobs=jobs,
      blobstore_key=blobstore_key,
      sample_testcase=sample_testcase,
  )


def _fuzzers_equal(fuzzer, another_fuzzer):
  return (fuzzer.name == another_fuzzer.name and
          fuzzer.data_bundle_name == another_fuzzer.data_bundle_name and
          fuzzer.jobs == another_fuzzer.jobs and
          fuzzer.blobstore_key == another_fuzzer.blobstore_key and
          fuzzer.sample_testcase == another_fuzzer.sample_testcase)


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
    entity_migrator = job_exporter.EntityMigrator(data_types.DataBundle, [],
                                                  'databundle', None, None)

    serialized_data_bundle = entity_migrator._serialize(data_bundle)
    deserialized_data_bundle = entity_migrator._deserialize(
        serialized_data_bundle)

    self.assertTrue(_data_bundles_equal(data_bundle, deserialized_data_bundle))

  def test_job_template_serializes_and_deserializes_correctly(self):
    """Test data_types.JobTemplate serialization/deserialization."""
    job_template = _sample_job_template()
    entity_migrator = job_exporter.EntityMigrator(data_types.JobTemplate, [],
                                                  'jobtemplate', None, None)

    serialized_job_template = entity_migrator._serialize(job_template)
    deserialized_job_template = entity_migrator._deserialize(
        serialized_job_template)

    self.assertTrue(
        _job_templates_equal(job_template, deserialized_job_template))

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
        data_types.Fuzzer, ['blobstore_key', 'sample_testcase'], 'fuzzer', None,
        None)

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
    """Verifies fuzzer protos and blobs are uploaded. If no blobstore
        key is present, no blob is uploaded."""
    blobstore_key = 'blobstore-key'
    sample_testcase_key = 'some-blobstore-key'

    fuzzer = _sample_fuzzer(
        name='some-fuzzer',
        data_bundle_name='some-bundle',
        jobs=['some-job'],
        blobstore_key=blobstore_key,
        sample_testcase=sample_testcase_key)
    another_fuzzer = _sample_fuzzer(
        name='another-fuzzer',
        data_bundle_name='another-bundle',
        jobs=['another-job'],
        blobstore_key=None,
        sample_testcase=None)
    fuzzer.put()
    another_fuzzer.put()
    entity_migrator = job_exporter.EntityMigrator(
        data_types.Fuzzer, ['blobstore_key', 'sample_testcase'], 'fuzzer',
        job_exporter.StorageRSync(), self.target_bucket)

    blob_id = 'some-blob-id'
    sample_testcase_blob_id = 'some-testcase-blob-id'
    blob_data = b'some-blob-data'
    sample_testcase_blob_data = b'some-sample-testcase-data'
    blobstore_key_location = f'gs://{self.blobs_bucket}/{blob_id}'
    sample_testcase_location = f'gs://{self.blobs_bucket}/{sample_testcase_blob_id}'
    storage.write_data(blob_data, blobstore_key_location)
    storage.write_data(sample_testcase_blob_data, sample_testcase_location)

    fuzzer_gcs_prefix = f'gs://{self.target_bucket}/fuzzer/{fuzzer.name}'
    fuzzer_proto_location = f'{fuzzer_gcs_prefix}/entity.proto'
    fuzzer_blob_location = f'{fuzzer_gcs_prefix}/blobstore_key'
    fuzzer_testcase_location = f'{fuzzer_gcs_prefix}/sample_testcase'

    another_fuzzer_gcs_prefix = f'gs://{self.target_bucket}/fuzzer/{another_fuzzer.name}'
    another_fuzzer_proto_location = f'{another_fuzzer_gcs_prefix}/entity.proto'
    another_fuzzer_blob_location = f'{another_fuzzer_gcs_prefix}/blobstore_key'
    another_fuzzer_testcase_location = f'{another_fuzzer_gcs_prefix}/sample_testcase'

    def get_gcs_key_mock_override(blob_key: str):
      bucket_prefix = f'gs://{self.blobs_bucket}'
      return_values = {
          blobstore_key: f'{bucket_prefix}/{blob_id}',
          sample_testcase_key: f'{bucket_prefix}/{sample_testcase_blob_id}',
      }
      return return_values.get(blob_key, None)

    self.mock.get_gcs_path.side_effect = get_gcs_key_mock_override
    entity_migrator.export_entities()

    self.assertTrue(_blob_is_present_in_gcs(fuzzer_proto_location))
    serialized_fuzzer_proto = storage.read_data(fuzzer_proto_location)
    deserialized_fuzzer_proto = entity_migrator._deserialize(
        serialized_fuzzer_proto)
    self.assertTrue(_fuzzers_equal(fuzzer, deserialized_fuzzer_proto))

    self.assertTrue(_blob_is_present_in_gcs(fuzzer_blob_location))
    self.assertTrue(_blob_content_is_equal(fuzzer_blob_location, blob_data))
    self.assertTrue(_blob_is_present_in_gcs(fuzzer_testcase_location))
    self.assertTrue(
        _blob_content_is_equal(fuzzer_testcase_location,
                               sample_testcase_blob_data))

    self.assertTrue(_blob_is_present_in_gcs(another_fuzzer_proto_location))
    serialized_another_fuzzer_proto = storage.read_data(
        another_fuzzer_proto_location)
    deserialized_another_fuzzer_proto = entity_migrator._deserialize(
        serialized_another_fuzzer_proto)
    self.assertTrue(
        _fuzzers_equal(another_fuzzer, deserialized_another_fuzzer_proto))

    self.assertFalse(_blob_is_present_in_gcs(another_fuzzer_blob_location))
    self.assertFalse(_blob_is_present_in_gcs(another_fuzzer_testcase_location))

  def test_jobs_are_correctly_exported(self):
    """Verifies job protos and custom binary blobs are uploaded. If no custom
        binary key is present, no blob is uploaded."""
    job = _sample_job(
        name='some-job', custom_binary_key='some-key', platform='some-platform')
    another_job = _sample_job(
        name='another-job',
        custom_binary_key='another-key',
        platform='another-platform')
    job.put()
    another_job.put()
    entity_migrator = job_exporter.EntityMigrator(data_types.Job,
                                                  ['custom_binary_key'], 'job',
                                                  job_exporter.StorageRSync(),
                                                  self.target_bucket)
    job_blob_data = b'some-data'
    job_blob_id = 'some-blob'
    job_proto_location = f'gs://{self.target_bucket}/job/{job.name}/entity.proto'
    blob_location = f'gs://{self.blobs_bucket}/{job_blob_id}'
    another_job_proto_location = (f'gs://{self.target_bucket}/'
                                  f'job/{another_job.name}/'
                                  f'entity.proto')
    another_job_blob_location = (f'gs://{self.target_bucket}/'
                                 f'job/{another_job.name}/'
                                 f'blobstore_key')
    storage.write_data(job_blob_data, blob_location)

    self.mock.get_gcs_path.return_value = blob_location
    entity_migrator.export_entities()

    self.assertTrue(_blob_is_present_in_gcs(job_proto_location))
    serialized_job_proto = storage.read_data(job_proto_location)
    deserialized_job_proto = entity_migrator._deserialize(serialized_job_proto)
    self.assertTrue(_jobs_equal(job, deserialized_job_proto))

    self.assertTrue(_blob_is_present_in_gcs(blob_location))
    self.assertTrue(_blob_content_is_equal(blob_location, job_blob_data))

    self.assertTrue(_blob_is_present_in_gcs(another_job_proto_location))
    serialized_another_job_proto = storage.read_data(another_job_proto_location)
    deserialized_another_job_proto = entity_migrator._deserialize(
        serialized_another_job_proto)
    self.assertTrue(_jobs_equal(another_job, deserialized_another_job_proto))

    self.assertFalse(_blob_is_present_in_gcs(another_job_blob_location))

  def test_job_templates_are_correctly_exported(self):
    """Verifies job template proto is correctly uploaded."""
    template = _sample_job_template(
        name='some-job-template', environment_string='some-env-string')
    template.put()
    entity_migrator = job_exporter.EntityMigrator(data_types.JobTemplate, [],
                                                  'jobtemplate',
                                                  job_exporter.StorageRSync(),
                                                  self.target_bucket)
    template_proto_location = (f'gs://{self.target_bucket}/'
                               f'jobtemplate/{template.name}/'
                               f'entity.proto')
    entity_migrator.export_entities()

    self.assertTrue(_blob_is_present_in_gcs(template_proto_location))
    serialized_template_proto = storage.read_data(template_proto_location)
    deserialized_template_proto = entity_migrator._deserialize(
        serialized_template_proto)
    self.assertTrue(_job_templates_equal(template, deserialized_template_proto))

  def test_data_bundles_are_correctly_exported(self):
    """Verifies the proto is uploaded and blobs are rsynced correctly."""
    data_bundle = _sample_data_bundle(
        name='some-data-bundle',
        bucket_name='some-data-bundle-bucket',
    )
    data_bundle.put()
    entity_migrator = job_exporter.EntityMigrator(data_types.DataBundle, [],
                                                  'databundle',
                                                  job_exporter.StorageRSync(),
                                                  self.target_bucket)

    blob_data = b'some data'
    storage.create_bucket_if_needed(data_bundle.bucket_name)
    storage.write_data(blob_data, f'gs://{data_bundle.bucket_name}/blob')

    entity_migrator.export_entities()
    bundle_proto_location = (f'gs://{self.target_bucket}/'
                             f'databundle/{data_bundle.name}/'
                             f'entity.proto')
    bundle_contents_location = (f'gs://{self.target_bucket}/'
                                f'databundle/{data_bundle.name}/'
                                f'contents/blob')
    self.assertTrue(_blob_is_present_in_gcs(bundle_proto_location))
    serialized_bundle_proto = storage.read_data(bundle_proto_location)
    deserialized_bundle_proto = entity_migrator._deserialize(
        serialized_bundle_proto)
    self.assertTrue(_data_bundles_equal(data_bundle, deserialized_bundle_proto))

    self.assertTrue(_blob_is_present_in_gcs(bundle_proto_location))
    self.assertTrue(_blob_content_is_equal(bundle_contents_location, blob_data))
