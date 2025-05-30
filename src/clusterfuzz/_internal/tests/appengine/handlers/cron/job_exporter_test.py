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

@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterJobTemplateIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    pass

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
    job = self._sample_job_template()
    entity_migrator = job_exporter.EntityMigrator(
      data_types.JobTemplate, ['custom_binary_key'], 'jobtemplate')
  
    serialized_job = entity_migrator._serialize(job)
    deserialized_job = entity_migrator._deserialize(serialized_job)

    self._assert_job_templates_equal(job, deserialized_job)


@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterFuzzerIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Fuzzer entitites."""
  def setUp(self):
    pass

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


@test_utils.with_cloud_emulators('datastore')
class TestJobsExporterJobIntegrationTests(unittest.TestCase):
  """Test the job exporter job with Job entitites."""

  def setUp(self):
    pass

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
