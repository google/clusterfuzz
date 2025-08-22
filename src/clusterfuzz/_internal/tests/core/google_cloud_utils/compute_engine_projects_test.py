# Copyright 2019 Google LLC
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
"""Tests for compute_engine_projects."""

import unittest

from clusterfuzz._internal.google_cloud_utils import compute_engine_projects


class LoadProjectTest(unittest.TestCase):
  """Tests load_project."""

  def test_load_test_project(self):
    """Test that test config (project test-clusterfuzz) loads without any
    exceptions."""
    project = compute_engine_projects.load_project('test-clusterfuzz')
    self.assertIsNotNone(project)

    self.assertEqual(project.project_id, 'test-clusterfuzz')
    self.assertEqual(project.clusters, [
        compute_engine_projects.Cluster(
            name='clusterfuzz-linux',
            gce_zone='gce-zone',
            instance_count=1,
            instance_template='clusterfuzz-linux',
            distribute=False,
            worker=False,
            high_end=False,
            auto_healing_policy=None,
        ),
        compute_engine_projects.Cluster(
            name='clusterfuzz-linux-pre',
            gce_zone='gce-zone',
            instance_count=2,
            instance_template='clusterfuzz-linux-pre',
            distribute=False,
            worker=False,
            high_end=False,
            auto_healing_policy=compute_engine_projects.AutoHealingPolicy(
                health_check='https://www.googleapis.com/compute/v1/projects/' +
                'test-clusterfuzz/global/healthChecks/test-check',
                initial_delay_sec=300,
            ),
        ),
    ])
