# Copyright 2026 Google LLC
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
"""Tests for the batch load balancing logic."""
import json
import unittest
from unittest import mock

from clusterfuzz._internal.batch import service
from clusterfuzz._internal.tests.test_libs import helpers


class GetRegionLoadTest(unittest.TestCase):
  """Tests for get_region_load."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.credentials.get_default',
        'urllib.request.urlopen',
        'google.auth.transport.requests.Request',
    ])
    self.mock_creds = mock.Mock()
    self.mock_creds.token = 'fake-token'
    self.mock_creds.valid = True
    self.mock.get_default.return_value = (self.mock_creds, 'project')

  def test_get_region_load_success(self):
    """Tests get_region_load with a successful API response."""
    mock_response = mock.Mock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({
        'jobCounts': [
            {'state': 'QUEUED', 'count': '10'},
            {'state': 'SCHEDULED', 'count': '5'}
        ]
    }).encode('utf-8')
    self.mock.urlopen.return_value.__enter__.return_value = mock_response

    load = service.get_region_load('project', 'us-central1')
    self.assertEqual(load, 15)

  def test_get_region_load_empty(self):
    """Tests get_region_load with an empty response."""
    mock_response = mock.Mock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({'jobCounts': []}).encode('utf-8')
    self.mock.urlopen.return_value.__enter__.return_value = mock_response

    load = service.get_region_load('project', 'us-central1')
    self.assertEqual(load, 0)

  def test_get_region_load_error(self):
    """Tests get_region_load with an API error."""
    mock_response = mock.Mock()
    mock_response.status = 500
    self.mock.urlopen.return_value.__enter__.return_value = mock_response

    load = service.get_region_load('project', 'us-central1')
    self.assertEqual(load, 0)


class GetSubconfigLoadBalancingTest(unittest.TestCase):
  """Tests for load balancing in _get_subconfig."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.batch.service.get_region_load',
        'clusterfuzz._internal.batch.service.random.choice',
        'clusterfuzz._internal.base.utils.random_weighted_choice',
    ])
    self.batch_config = {
        'project': 'test-project',
        'queue_check_regions': ['us-central1', 'us-east4'],
        'subconfigs': {
            'central1': {'region': 'us-central1', 'network': 'n1'},
            'east4': {'region': 'us-east4', 'network': 'n2'},
            'west1': {'region': 'us-west1', 'network': 'n3'},
        }
    }
    self.instance_spec = {
        'subconfigs': [
            {'name': 'central1', 'weight': 1},
            {'name': 'east4', 'weight': 1},
        ]
    }

  def test_all_regions_healthy(self):
    """Tests that a region is picked when all are healthy."""
    self.mock.get_region_load.return_value = 2  # Total load 2 < 50
    self.mock.choice.side_effect = lambda x: x[0]
    
    subconfig = service._get_subconfig(self.batch_config, self.instance_spec)
    self.assertEqual(subconfig['region'], 'us-central1')

  def test_one_region_overloaded(self):
    """Tests that overloaded regions are skipped."""
    # us-central1 (load 60) is overloaded, us-east4 (load 2) is healthy.
    self.mock.get_region_load.side_effect = [
        60, # us-central1
        2, # us-east4
    ]
    # random.choice should only see ['east4']
    def mock_choice(items):
      self.assertEqual(items, ['east4'])
      return items[0]
    self.mock.choice.side_effect = mock_choice

    subconfig = service._get_subconfig(self.batch_config, self.instance_spec)
    self.assertEqual(subconfig['region'], 'us-east4')

  def test_all_regions_overloaded(self):
    """Tests that AllRegionsOverloadedError is raised when no healthy regions exist."""
    self.mock.get_region_load.return_value = 50 # Load 50 is threshold for "overloaded"
    
    with self.assertRaises(service.AllRegionsOverloadedError):
      service._get_subconfig(self.batch_config, self.instance_spec)

  def test_skip_load_check_if_not_in_config(self):
    """Tests that load check is skipped for regions not in queue_check_regions."""
    instance_spec = {
        'subconfigs': [
            {'name': 'central1', 'weight': 1},
        ]
    }
    self.batch_config['queue_check_regions'] = [] # Empty list, so central1 is not checked
    self.mock.random_weighted_choice.return_value = mock.Mock(name='central1')
    self.mock.random_weighted_choice.return_value.name = 'central1'
    
    subconfig = service._get_subconfig(self.batch_config, instance_spec)
    self.assertEqual(subconfig['region'], 'us-central1')
    self.assertFalse(self.mock.get_region_load.called)

  def test_skip_load_check_if_disabled(self):
    """Tests that load check is skipped if queue_check_regions is missing."""
    del self.batch_config['queue_check_regions']
    self.mock.random_weighted_choice.return_value = mock.Mock(name='central1')
    self.mock.random_weighted_choice.return_value.name = 'central1'
    
    subconfig = service._get_subconfig(self.batch_config, self.instance_spec)
    self.assertEqual(subconfig['region'], 'us-central1')
    self.assertFalse(self.mock.get_region_load.called)
