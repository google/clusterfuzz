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
"""Tests for bot_manager."""

import getpass
import unittest

from handlers.cron.helpers import bot_manager
from handlers.cron.helpers.bot_manager import OperationError

TEST_PROJECT = 'clusterfuzz-testing'
TEST_ZONE = 'us-central1-b'
TEST_INSTANCE_TEMPLATE = 'instance-template-'
TEST_INSTANCE_GROUP = 'instance-group-'


def test_template():
  return {
      'name': test_instance_template_name(),
      'description': 'test',
      'properties': {
          'machineType':
              'n1-standard-1',
          'disks': [{
              'boot': True,
              'initializeParams': {
                  'sourceImage': ('projects/cos-cloud/global/images/family/'
                                  'cos-stable'),
                  'diskSizeGb':
                      10,
                  'diskType':
                      'pd-standard'
              }
          }],
          'networkInterfaces': [{
              'network': 'global/networks/default',
          }]
      }
  }


def test_instance_group_name():
  return TEST_INSTANCE_GROUP + getpass.getuser()


def test_instance_template_name():
  return TEST_INSTANCE_TEMPLATE + getpass.getuser()


def cleanup_resources():
  """Clean up resources."""
  manager = bot_manager.BotManager(TEST_PROJECT, TEST_ZONE)
  try:
    manager.instance_group(test_instance_group_name()).delete()
  except bot_manager.NotFoundError:
    pass

  try:
    manager.instance_template(test_instance_template_name()).delete()
  except bot_manager.NotFoundError:
    pass


@unittest.skip('Slow integration test')
class BotManagerTest(unittest.TestCase):
  """Tests for bot_manager."""

  def setUp(self):
    cleanup_resources()
    self.manager = bot_manager.BotManager(TEST_PROJECT, TEST_ZONE)

  def tearDown(self):
    cleanup_resources()

  def test_templates(self):
    """Test instance templates."""
    template = self.manager.instance_template(test_instance_template_name())
    self.assertFalse(template.exists())
    with self.assertRaises(bot_manager.NotFoundError):
      template.get()

    expected_properties = {
        'disks': [{
            'boot': True,
            'deviceName': 'persistent-disk-0',
            'index': 0,
            'initializeParams': {
                'diskSizeGb':
                    '10',
                'diskType':
                    'pd-standard',
                'sourceImage': ('projects/cos-cloud/global/images/family/'
                                'cos-stable')
            },
            'kind': 'compute#attachedDisk',
            'mode': 'READ_WRITE',
            'type': 'PERSISTENT'
        }],
        'machineType':
            'n1-standard-1',
        'networkInterfaces': [{
            'kind':
                'compute#networkInterface',
            'name':
                'nic0',
            'network': ('https://www.googleapis.com/compute/v1/projects/'
                        '%s/global/networks/default' % TEST_PROJECT),
        }],
    }

    template.create(test_template())
    self.assertTrue(template.exists())

    body = template.get()
    self.assertEqual(body['name'], test_instance_template_name())
    self.assertEqual(body['description'], 'test')
    self.assertDictEqual(expected_properties, body['properties'])

    template.delete()
    self.assertFalse(template.exists())

  def test_instance_groups(self):
    """Test instance groups."""
    template = self.manager.instance_template(test_instance_template_name())
    template.create(test_template())

    group = self.manager.instance_group(test_instance_group_name())

    self.assertFalse(group.exists())
    with self.assertRaises(bot_manager.NotFoundError):
      group.get()

    group.create(test_instance_group_name(), template.name, 1)
    self.assertTrue(group.exists())

    body = group.get()
    self.assertEqual(
        'https://www.googleapis.com/compute/v1/projects/'
        '%s/global/instanceTemplates/%s' % (TEST_PROJECT,
                                            test_instance_template_name()),
        body['instanceTemplate'])
    self.assertEqual(1, body['targetSize'])

    managed_instances = list(group.list_managed_instances())
    self.assertEqual(1, len(managed_instances))
    self.assertEqual('RUNNING', managed_instances[0]['instanceStatus'])
    self.assertEqual('NONE', managed_instances[0]['currentAction'])
    self.assertTrue(managed_instances[0]['instance'].startswith(
        'https://www.googleapis.com/compute/v1/projects/'
        '%s/zones/%s/instances/%s' % (TEST_PROJECT, TEST_ZONE,
                                      test_instance_group_name())))

    group.resize(2)
    body = group.get()
    self.assertEqual(2, body['targetSize'])
    managed_instances = list(group.list_managed_instances())
    self.assertEqual(2, len(managed_instances))

    group.delete()
    self.assertFalse(group.exists())

  def test_auto_healing_policy(self):
    """Test if the autoHealingPolicies are correctly sent and enforced."""
    template = self.manager.instance_template(test_instance_template_name())
    template.create(test_template())

    group = self.manager.instance_group(test_instance_group_name())

    auto_healing_policies = [{
        'healthCheck': 'global/healthChecks/running-check',
        'initialDelaySec': 300
    }]

    with self.assertRaises(OperationError) as op_error:
      group.create(test_instance_group_name(), template.name, 1,
                   auto_healing_policies)
      expected_op_error = [{
          'errors': [{
              'code': 'WAITING_FOR_HEALTHY_TIMEOUT_EXCEEDED',
              'message': 'Waiting for HEALTHY state timed out '
                         '(autohealingPolicy.initialDelay=300 sec) '
                         'for instance '
                         'projects/clusterfuzz-testing/'
                         'zones/us-central1-b/'
                         'instances/instance-group-donggeliu-1l11 '
                         'and health check '
                         'projects/clusterfuzz-testing/'
                         'global/healthChecks/running-check.'
          }]
      }]
      self.assertEqual(expected_op_error, str(op_error))

    actual_message = group.get()['autoHealingPolicies']
    expected_message = [{
        'healthCheck': ('https://www.googleapis.com/compute/v1/projects/'
                        f'{TEST_PROJECT}/'
                        f'{auto_healing_policies[0]["healthCheck"]}'),
        'initialDelaySec':
            auto_healing_policies[0]['initialDelaySec']
    }]

    self.assertEqual(expected_message, actual_message)

    auto_healing_policies = [{
        'healthCheck': 'global/healthChecks/running-check',
        'initialDelaySec': 180
    }]

    with self.assertRaises(OperationError) as op_error:
      group.patch_auto_healing_policies(auto_healing_policies)
      expected_op_error = [{
          'errors': [{
              'code': 'WAITING_FOR_HEALTHY_TIMEOUT_EXCEEDED',
              'message': 'Waiting for HEALTHY state timed out '
                         '(autohealingPolicy.initialDelay=300 sec) '
                         'for instance '
                         'projects/clusterfuzz-testing/'
                         'zones/us-central1-b/'
                         'instances/instance-group-donggeliu-1l11 '
                         'and health check '
                         'projects/clusterfuzz-testing/'
                         'global/healthChecks/running-check.'
          }]
      }]
      self.assertEqual(expected_op_error, str(op_error))

    actual_message = group.get()['autoHealingPolicies']
    expected_message = [{
        'healthCheck': ('https://www.googleapis.com/compute/v1/projects/'
                        f'{TEST_PROJECT}/'
                        f'{auto_healing_policies[0]["healthCheck"]}'),
        'initialDelaySec':
            auto_healing_policies[0]['initialDelaySec']
    }]

    self.assertEqual(expected_message, actual_message)
