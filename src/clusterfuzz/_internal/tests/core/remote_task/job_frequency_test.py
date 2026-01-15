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
"""Tests for the remote task job frequency module."""
import unittest
from unittest import mock

from clusterfuzz._internal.remote_task import RemoteTaskGate
from clusterfuzz._internal.tests.core.datastore import ds_test_utils
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class GetJobFrequencyTest(unittest.TestCase):
  """Tests for the get_job_frequency function."""

  def setUp(self):
    mock.patch(
        'clusterfuzz._internal.k8s.service.KubernetesService._load_gke_credentials'
    ).start()
    self.gate = RemoteTaskGate()

  def test_get_job_frequency_defaults(self):
    """Tests that the default frequencies are returned when no feature flags
    are set."""

    frequencies = self.gate.get_job_frequency()
    self.assertEqual(frequencies['kubernetes'], 0.0)
    self.assertEqual(frequencies['gcp_batch'], 1.0)
    self.assertEqual(sum(frequencies.values()), 1.0)

  @ds_test_utils.with_flags(k8s_jobs_frequency=0.3)
  def test_get_job_frequency_with_k8s_flag(self):
    """Tests that the frequencies are correctly calculated when the
    k8s_jobs_frequency flag is set."""

    frequencies = self.gate.get_job_frequency()
    self.assertEqual(frequencies['kubernetes'], 0.3)
    self.assertEqual(frequencies['gcp_batch'], 0.7)
    self.assertEqual(sum(frequencies.values()), 1.0)

  @ds_test_utils.with_flags(k8s_jobs_frequency=1.0)
  def test_get_job_frequency_with_k8s_flag_full(self):
    """Tests that the frequencies are correctly calculated when the
    k8s_jobs_frequency flag is set to 1.0."""

    frequencies = self.gate.get_job_frequency()
    self.assertEqual(frequencies['kubernetes'], 1.0)
    self.assertEqual(frequencies['gcp_batch'], 0.0)
    self.assertEqual(sum(frequencies.values()), 1.0)

  @ds_test_utils.with_flags(k8s_jobs_frequency=0.0)
  def test_get_job_frequency_with_k8s_flag_zero(self):
    """Tests that the frequencies are correctly calculated when the
    k8s_jobs_frequency flag is set to 0.0."""

    frequencies = self.gate.get_job_frequency()
    self.assertEqual(frequencies['kubernetes'], 0.0)
    self.assertEqual(frequencies['gcp_batch'], 1.0)
    self.assertEqual(sum(frequencies.values()), 1.0)

  @ds_test_utils.with_flags(k8s_jobs_frequency=0.5)
  def test_get_job_frequency_sum_is_one(self):
    """Tests that the sum of the frequencies is always 1.0."""

    frequencies = self.gate.get_job_frequency()
    self.assertEqual(sum(frequencies.values()), 1.0)
