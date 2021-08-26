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
"""manage_vms tests."""

import copy
import functools
import unittest

from google.cloud import ndb
import mock
import six

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import compute_engine_projects
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import manage_vms
from handlers.cron.helpers import bot_manager

INSTANCE_GROUPS = {
    'oss-fuzz-linux-zone2-pre-proj2': {
        'targetSize': 1,
    },
    'oss-fuzz-linux-zone2-pre-proj3': {
        'targetSize': 499,
    },
    'oss-fuzz-linux-zone2-pre-proj4': {
        'targetSize': 99,
    },
    'oss-fuzz-linux-zone2-pre-proj5': {
        'targetSize': 99,
    }
}

INSTANCE_TEMPLATES = {
    'oss-fuzz-linux-zone2-pre-proj2': {
        'description': '{"version": 1}',
        'properties': {
            'metadata': {
                'items': [],
            },
            'disks': [{
                'initializeParams': {
                    'diskSizeGb': '30',
                },
            }],
            'serviceAccounts': [{
                'email':
                    'email',
                'scopes': [
                    'https://www.googleapis.com/auth/'
                    'devstorage.full_control',
                    'https://www.googleapis.com/auth/logging.write',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/appengine.apis',
                    'https://www.googleapis.com/auth/prodxmon',
                    'https://www.googleapis.com/auth/bigquery',
                ]
            }],
        }
    },
    'oss-fuzz-linux-zone2-pre-proj3': {
        'description': '{"version": 1}',
        'properties': {
            'metadata': {
                'items': [],
            },
            'disks': [{
                'initializeParams': {
                    'diskSizeGb': '30',
                },
            }],
            'serviceAccounts': [{
                'email':
                    'email',
                'scopes': [
                    'https://www.googleapis.com/auth/'
                    'devstorage.full_control',
                    'https://www.googleapis.com/auth/logging.write',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/appengine.apis',
                    'https://www.googleapis.com/auth/prodxmon',
                    'https://www.googleapis.com/auth/bigquery',
                ]
            }],
        }
    },
    'oss-fuzz-linux-zone2-pre-proj4': {
        'description': '{"version": 0}',
        'properties': {
            'metadata': {
                'items': [],
            },
            'disks': [{
                'initializeParams': {
                    'diskSizeGb': '30',
                },
            }],
            'serviceAccounts': [{
                'email':
                    'email',
                'scopes': [
                    'https://www.googleapis.com/auth/'
                    'devstorage.full_control',
                    'https://www.googleapis.com/auth/logging.write',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/appengine.apis',
                    'https://www.googleapis.com/auth/prodxmon',
                    'https://www.googleapis.com/auth/bigquery',
                ]
            }],
        }
    },
    'oss-fuzz-linux-zone2-pre-proj5': {
        'description': '{"version": 1}',
        'properties': {
            'metadata': {
                'items': [],
            },
            'disks': [{
                'initializeParams': {
                    'diskSizeGb': '30',
                },
            }],
            'serviceAccounts': [{
                'email':
                    'email',
                'scopes': [
                    'https://www.googleapis.com/auth/'
                    'devstorage.full_control',
                    'https://www.googleapis.com/auth/logging.write',
                    'https://www.googleapis.com/auth/userinfo.email',
                    'https://www.googleapis.com/auth/appengine.apis',
                    'https://www.googleapis.com/auth/prodxmon',
                    'https://www.googleapis.com/auth/bigquery',
                ]
            }],
        }
    }
}

INSTANCES = {
    'oss-fuzz-linux-zone3-host': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-host-abcd',
    }, {
        'instance': 'https://blah/oss-fuzz-linux-zone3-host-efgh',
    }],
    'oss-fuzz-linux-zone3-worker-proj1': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-worker-proj1-%04d' % i
    } for i in range(1, 2)],
    'oss-fuzz-linux-zone3-worker-proj2': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-worker-proj2-%04d' % i
    } for i in range(1, 5)],
    'oss-fuzz-linux-zone3-worker-proj3': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-worker-proj3-%04d' % i
    } for i in range(1, 10)],
    'oss-fuzz-linux-zone3-worker-proj4': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-worker-proj4-%04d' % i
    } for i in range(1, 2)],
    'oss-fuzz-linux-zone3-worker-proj5': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-worker-proj5-%04d' % i
    } for i in range(1, 2)],
    'oss-fuzz-linux-zone3-host-high-end': [{
        'instance': 'https://blah/oss-fuzz-linux-zone3-host-high-end-1'
    }],
    'oss-fuzz-linux-zone3-worker-high-end-proj6': [{
        'instance': ('https://blah/'
                     'oss-fuzz-linux-zone3-worker-high-end-proj6-%04d' % i)
    } for i in range(1, 3)],
}

OSS_FUZZ_CLUSTERS = compute_engine_projects.Project(
    project_id='clusterfuzz-external',
    clusters=[
        compute_engine_projects.Cluster(
            name='oss-fuzz-linux-zone2-pre',
            gce_zone='us-east2-a',
            instance_count=997,
            instance_template='external-pre-zone2',
            distribute=True,
            worker=False,
            high_end=False),
        compute_engine_projects.Cluster(
            name='oss-fuzz-linux-zone3-host',
            gce_zone='us-central1-d',
            instance_count=2,
            instance_template='host-zone3',
            distribute=False,
            worker=False,
            high_end=False),
        compute_engine_projects.Cluster(
            name='oss-fuzz-linux-zone3-worker',
            gce_zone='us-central1-d',
            instance_count=16,
            instance_template='worker-zone3',
            distribute=True,
            worker=True,
            high_end=False),
        compute_engine_projects.Cluster(
            name='oss-fuzz-linux-zone3-host-high-end',
            gce_zone='us-central1-d',
            instance_count=1,
            instance_template='host-high-end-zone3',
            distribute=False,
            worker=False,
            high_end=True),
        compute_engine_projects.Cluster(
            name='oss-fuzz-linux-zone3-worker-high-end',
            gce_zone='us-central1-d',
            instance_count=2,
            instance_template='worker-zone3',
            distribute=True,
            worker=True,
            high_end=True),
    ],
    instance_templates=[
        {
            'name': 'external-pre-zone2',
            'description': '{"version": 1}',
            'properties': {
                'metadata': {
                    'items': [],
                },
                'disks': [{
                    'initializeParams': {
                        'diskSizeGb': 30,
                    },
                }],
                'serviceAccounts': [{
                    'email':
                        'email',
                    'scopes': [
                        'https://www.googleapis.com/auth/'
                        'devstorage.full_control',
                        'https://www.googleapis.com/auth/logging.write',
                        'https://www.googleapis.com/auth/userinfo.email',
                        'https://www.googleapis.com/auth/appengine.apis',
                        'https://www.googleapis.com/auth/prodxmon',
                        'https://www.googleapis.com/auth/bigquery',
                    ]
                }],
            }
        },
        {
            'name': 'host-zone3',
            'description': '{"version": 1}',
            'properties': {
                'metadata': {
                    'items': [],
                },
                'disks': [{
                    'initializeParams': {
                        'diskSizeGb': 30,
                    },
                }],
                'serviceAccounts': [{
                    'email':
                        'email',
                    'scopes': [
                        'https://www.googleapis.com/auth/'
                        'devstorage.full_control',
                        'https://www.googleapis.com/auth/logging.write',
                        'https://www.googleapis.com/auth/userinfo.email',
                        'https://www.googleapis.com/auth/appengine.apis',
                        'https://www.googleapis.com/auth/prodxmon',
                        'https://www.googleapis.com/auth/bigquery',
                    ]
                }],
            }
        },
        {
            'name': 'worker-zone3',
            'description': '{"version": 1}',
            'properties': {
                'metadata': {
                    'items': [],
                },
                'disks': [{
                    'initializeParams': {
                        'diskSizeGb': 30,
                    },
                }],
                'serviceAccounts': [{
                    'email':
                        'email',
                    'scopes': [
                        'https://www.googleapis.com/auth/'
                        'devstorage.full_control',
                        'https://www.googleapis.com/auth/logging.write',
                        'https://www.googleapis.com/auth/userinfo.email',
                        'https://www.googleapis.com/auth/prodxmon',
                    ]
                }],
            }
        },
        {
            'name': 'host-high-end-zone3',
            'description': '{"version": 1}',
            'properties': {
                'metadata': {
                    'items': [],
                },
                'disks': [{
                    'initializeParams': {
                        'diskSizeGb': 100,
                    },
                }],
                'serviceAccounts': [{
                    'email':
                        'email',
                    'scopes': [
                        'https://www.googleapis.com/auth/'
                        'devstorage.full_control',
                        'https://www.googleapis.com/auth/logging.write',
                        'https://www.googleapis.com/auth/userinfo.email',
                        'https://www.googleapis.com/auth/prodxmon',
                    ]
                }],
            }
        },
    ],
    host_worker_assignments=[
        compute_engine_projects.HostWorkerAssignment(
            host='oss-fuzz-linux-zone3-host',
            worker='oss-fuzz-linux-zone3-worker',
            workers_per_host=8),
        compute_engine_projects.HostWorkerAssignment(
            host='oss-fuzz-linux-zone3-host-high-end',
            worker='oss-fuzz-linux-zone3-worker-high-end',
            workers_per_host=2),
    ])


def mock_resource(spec):
  """Mock resource."""
  resource = mock.Mock(spec=spec)
  resource.created = False
  resource.body = None

  def create(*args, **kwargs):  # pylint: disable=unused-argument
    if resource.created:
      raise bot_manager.AlreadyExistsError

    resource.created = True

  def get():
    if resource.created:
      return resource.body

    raise bot_manager.NotFoundError

  def exists():
    return resource.created

  def delete():
    if not resource.created:
      raise bot_manager.NotFoundError

    resource.created = False

  resource.create.side_effect = create
  resource.get.side_effect = get
  resource.exists.side_effect = exists
  resource.delete.side_effect = delete

  return resource


class MockBotManager(object):
  """Mock BotManager."""

  def __init__(self, project_id, zone, instance_groups, instance_templates):
    self.project_id = project_id
    self.zone = zone
    self.instance_groups = instance_groups
    self.instance_templates = instance_templates

  def _get_resource(self, name, cache, values, spec):
    """Get resource."""
    if name in cache:
      return cache[name]

    resource = mock_resource(spec=spec)
    if name in values:
      resource.created = True
      resource.body = values[name]

    cache[name] = resource
    return resource

  def instance_group(self, name):
    """Get an InstanceGroup resource with the given name."""
    resource = self._get_resource(name, self.instance_groups, INSTANCE_GROUPS,
                                  bot_manager.InstanceGroup)

    if name in INSTANCES:
      resource.list_managed_instances.return_value = INSTANCES[name]

    return resource

  def instance_template(self, name):
    """Get an InstanceTemplate resource with the given name."""
    return self._get_resource(name, self.instance_templates, INSTANCE_TEMPLATES,
                              bot_manager.InstanceTemplate)


def expected_instance_template(gce_project_name,
                               name,
                               project_name,
                               disk_size_gb=None,
                               service_account=None,
                               tls_cert=False):
  """Get the expected instance template for a project."""
  gce_project = compute_engine_projects.load_project(gce_project_name)
  expected = copy.deepcopy(gce_project.get_instance_template(name))
  expected['properties']['metadata']['items'].append({
      'key': 'task-tag',
      'value': project_name,
  })

  if disk_size_gb:
    disk = expected['properties']['disks'][0]
    disk['initializeParams']['diskSizeGb'] = disk_size_gb

  if service_account:
    expected['properties']['serviceAccounts'][0]['email'] = service_account

  if tls_cert:
    expected['properties']['metadata']['items'].extend([{
        'key': 'tls-cert',
        'value': project_name + '_cert',
    }, {
        'key': 'tls-key',
        'value': project_name + '_key',
    }])

  return expected


def expected_host_instance_template(gce_project_name, name):
  """Get the expected instance template for a project."""
  gce_project = compute_engine_projects.load_project(gce_project_name)
  return copy.deepcopy(gce_project.get_instance_template(name))


@test_utils.with_cloud_emulators('datastore')
class CronTest(unittest.TestCase):
  """Test manage_vms cron."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'handlers.cron.helpers.bot_manager.BotManager',
        'clusterfuzz._internal.system.environment.is_running_on_app_engine',
        'clusterfuzz._internal.google_cloud_utils.compute_engine_projects.load_project',
    ])

    self.mock.is_oss_fuzz.return_value = True
    self.mock.is_running_on_app_engine.return_value = True
    self.mock.load_project.return_value = OSS_FUZZ_CLUSTERS

    data_types.OssFuzzProject(
        id='proj1',
        name='proj1',
        cpu_weight=1.0,
        service_account='proj1@serviceaccount.com').put()

    data_types.OssFuzzProject(
        id='proj2',
        name='proj2',
        cpu_weight=2.0,
        service_account='proj2@serviceaccount.com').put()

    data_types.OssFuzzProject(
        id='proj3',
        name='proj3',
        cpu_weight=5.0,
        service_account='proj3@serviceaccount.com').put()

    data_types.OssFuzzProject(
        id='proj4',
        name='proj4',
        cpu_weight=1.0,
        service_account='proj4@serviceaccount.com').put()

    data_types.OssFuzzProject(
        id='proj5',
        name='proj5',
        cpu_weight=1.0,
        service_account='proj5@serviceaccount.com',
        disk_size_gb=10).put()

    data_types.OssFuzzProject(
        id='proj6',
        name='proj6',
        cpu_weight=1.0,
        service_account='proj6@serviceaccount.com',
        high_end=True).put()

    for j in range(1, 7):
      project_name = 'proj%d' % j
      data_types.WorkerTlsCert(
          id=project_name,
          project_name=project_name,
          cert_contents=project_name.encode() + b'_cert',
          key_contents=project_name.encode() + b'_key').put()

    data_types.OssFuzzProjectInfo(id='old_proj', name='old_proj').put()

    data_types.OssFuzzProjectInfo(
        id='proj2',
        name='proj2',
        clusters=[
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='oss-fuzz-linux-zone2-pre',
                gce_zone='us-east2-a',
                cpu_count=1,
            ),
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='old-cluster',
                gce_zone='us-east2-a',
                cpu_count=1,
            ),
        ]).put()

    data_types.OssFuzzProjectInfo(
        id='proj3',
        name='proj3',
        clusters=[
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='oss-fuzz-linux-zone2-pre',
                gce_zone='us-east2-a',
                cpu_count=499,
            )
        ]).put()

    data_types.OssFuzzProjectInfo(
        id='proj4',
        name='proj4',
        clusters=[
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='oss-fuzz-linux-zone2-pre',
                gce_zone='us-east2-a',
                cpu_count=99,
            )
        ]).put()

    data_types.OssFuzzProjectInfo(
        id='proj5',
        name='proj5',
        clusters=[
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='oss-fuzz-linux-zone2-pre',
                gce_zone='us-east2-a',
                cpu_count=99,
            )
        ]).put()

    data_types.OssFuzzProjectInfo(
        id='old_proj',
        name='old_proj',
        clusters=[
            data_types.OssFuzzProjectInfo.ClusterInfo(
                cluster='oss-fuzz-linux-zone2-pre',
                gce_zone='us-east2-a',
                cpu_count=5,
            )
        ]).put()

    data_types.HostWorkerAssignment(
        id='old-host-0',
        host_name='old-host',
        worker_name='worker',
        instance_num=0).put()

    instance_groups = {}
    instance_templates = {}
    self.mock.BotManager.side_effect = functools.partial(
        MockBotManager,
        instance_groups=instance_groups,
        instance_templates=instance_templates)

  def test_update_cpus(self):
    """Tests CPU distribution cron."""
    self.maxDiff = None  # pylint: disable=invalid-name
    manager = manage_vms.OssFuzzClustersManager('clusterfuzz-external')
    manager.update_clusters()

    proj1 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj1').get()
    self.assertIsNotNone(proj1)
    self.assertDictEqual({
        'name':
            'proj1',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone2-pre',
            'cpu_count': 100,
            'gce_zone': 'us-east2-a',
        }, {
            'cluster': 'oss-fuzz-linux-zone3-worker',
            'cpu_count': 1,
            'gce_zone': 'us-central1-d',
        }],
    }, proj1.to_dict())

    proj2 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj2').get()
    self.assertIsNotNone(proj2)
    self.assertDictEqual({
        'name':
            'proj2',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone2-pre',
            'cpu_count': 200,
            'gce_zone': 'us-east2-a',
        }, {
            'cluster': 'oss-fuzz-linux-zone3-worker',
            'cpu_count': 4,
            'gce_zone': 'us-central1-d',
        }],
    }, proj2.to_dict())

    proj3 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj3').get()
    self.assertIsNotNone(proj3)
    self.assertDictEqual({
        'name':
            'proj3',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone2-pre',
            'cpu_count': 499,
            'gce_zone': 'us-east2-a',
        }, {
            'cluster': 'oss-fuzz-linux-zone3-worker',
            'cpu_count': 9,
            'gce_zone': 'us-central1-d',
        }],
    }, proj3.to_dict())

    proj4 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj4').get()
    self.assertIsNotNone(proj4)
    self.assertDictEqual({
        'name':
            'proj4',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone2-pre',
            'cpu_count': 99,
            'gce_zone': 'us-east2-a',
        }, {
            'cluster': 'oss-fuzz-linux-zone3-worker',
            'cpu_count': 1,
            'gce_zone': 'us-central1-d',
        }],
    }, proj4.to_dict())

    proj5 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj5').get()
    self.assertIsNotNone(proj5)
    self.assertDictEqual({
        'name':
            'proj5',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone2-pre',
            'cpu_count': 99,
            'gce_zone': 'us-east2-a',
        }, {
            'cluster': 'oss-fuzz-linux-zone3-worker',
            'cpu_count': 1,
            'gce_zone': 'us-central1-d',
        }],
    }, proj5.to_dict())

    proj6 = ndb.Key(data_types.OssFuzzProjectInfo, 'proj6').get()
    self.assertIsNotNone(proj6)
    self.assertDictEqual({
        'name':
            'proj6',
        'clusters': [{
            'cluster': 'oss-fuzz-linux-zone3-worker-high-end',
            'cpu_count': 2,
            'gce_zone': 'us-central1-d',
        }],
    }, proj6.to_dict())

    old_proj = ndb.Key(data_types.OssFuzzProjectInfo, 'old_proj').get()
    self.assertIsNone(old_proj)

    mock_bot_manager = self.mock.BotManager('clusterfuzz-external',
                                            'us-east2-a')

    # proj1: new project.
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj1').create.assert_called_with(
            expected_instance_template('clusterfuzz-external',
                                       'external-pre-zone2', 'proj1'))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj1').create.assert_called_with(
            'oss-fuzz-linux-zone2-pre-proj1',
            'oss-fuzz-linux-zone2-pre-proj1',
            size=100,
            wait_for_instances=False)
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj1').resize.assert_not_called()

    # proj2: already exists. needs a resize. old cluster should be deleted.
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj2').create.assert_not_called()
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj2').delete.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj2').create.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj2').delete.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj2').resize.assert_called_with(
            200, wait_for_instances=False)
    mock_bot_manager.instance_template(
        'old-cluster-proj2').delete.assert_called()
    mock_bot_manager.instance_group('old-cluster-proj2').delete.assert_called()

    # proj3: already exists. no changes needed.
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj3').delete.assert_not_called()
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj3').create.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj3').create.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj3').resize.assert_not_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj3').delete.assert_not_called()

    # proj4: needs a template update (version change).
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj4').delete.assert_called()
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj4').create.assert_called_with(
            expected_instance_template('clusterfuzz-external',
                                       'external-pre-zone2', 'proj4'))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj4').delete.assert_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj4').create.assert_called_with(
            'oss-fuzz-linux-zone2-pre-proj4',
            'oss-fuzz-linux-zone2-pre-proj4',
            size=99,
            wait_for_instances=False)
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj4').resize.assert_not_called()

    # proj5: needs a template update (disk size change).
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj5').delete.assert_called()
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-proj5').create.assert_called_with(
            expected_instance_template(
                'clusterfuzz-external',
                'external-pre-zone2',
                'proj5',
                disk_size_gb=10))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj5').delete.assert_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj5').create.assert_called_with(
            'oss-fuzz-linux-zone2-pre-proj5',
            'oss-fuzz-linux-zone2-pre-proj5',
            size=99,
            wait_for_instances=False)
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-proj5').resize.assert_not_called()

    # proj6: high end project.
    for j in range(1, 6):
      mock_bot_manager.instance_group(
          'oss-fuzz-linux-zone3-worker-high-end-proj' +
          str(j)).create.assert_not_called()

    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone3-worker-high-end-proj6').create.assert_called()

    # old_proj: deleted.
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-old-proj').create.assert_not_called()
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone2-pre-old-proj').delete.assert_called()
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone2-pre-old-proj').delete.assert_called()

    # host instances: created.
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone3-host').create.assert_called_with(
            expected_host_instance_template('clusterfuzz-external',
                                            'host-zone3'))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone3-host').create.assert_called_with(
            'oss-fuzz-linux-zone3-host',
            'oss-fuzz-linux-zone3-host',
            size=2,
            wait_for_instances=False)

    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone3-host-high-end').create.assert_called_with(
            'oss-fuzz-linux-zone3-host-high-end',
            'oss-fuzz-linux-zone3-host-high-end',
            size=1,
            wait_for_instances=False)

    # Worker instances: created.
    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone3-worker-proj1').create.assert_called_with(
            expected_instance_template(
                'clusterfuzz-external',
                'worker-zone3',
                'proj1',
                service_account='proj1@serviceaccount.com',
                tls_cert=True))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone3-worker-proj1').create.assert_called_with(
            'oss-fuzz-linux-zone3-worker-proj1',
            'oss-fuzz-linux-zone3-worker-proj1',
            size=1,
            wait_for_instances=False)

    mock_bot_manager.instance_template(
        'oss-fuzz-linux-zone3-worker-proj2').create.assert_called_with(
            expected_instance_template(
                'clusterfuzz-external',
                'worker-zone3',
                'proj2',
                service_account='proj2@serviceaccount.com',
                tls_cert=True))
    mock_bot_manager.instance_group(
        'oss-fuzz-linux-zone3-worker-proj2').create.assert_called_with(
            'oss-fuzz-linux-zone3-worker-proj2',
            'oss-fuzz-linux-zone3-worker-proj2',
            size=4,
            wait_for_instances=False)

    six.assertCountEqual(self, [{
        'instance_num': 0,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj1-0001',
        'project_name': u'proj1',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 1,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj2-0001',
        'project_name': u'proj2',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 2,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj2-0002',
        'project_name': u'proj2',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 3,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj2-0003',
        'project_name': u'proj2',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 4,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj2-0004',
        'project_name': u'proj2',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 5,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0001',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 6,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0002',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 7,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0003',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-abcd'
    }, {
        'instance_num': 0,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0004',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 1,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0005',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 2,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0006',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 3,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0007',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 4,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0008',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 5,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj3-0009',
        'project_name': u'proj3',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 6,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj4-0001',
        'project_name': u'proj4',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 7,
        'worker_name': u'oss-fuzz-linux-zone3-worker-proj5-0001',
        'project_name': u'proj5',
        'host_name': u'oss-fuzz-linux-zone3-host-efgh'
    }, {
        'instance_num': 0,
        'worker_name': u'oss-fuzz-linux-zone3-worker-high-end-proj6-0001',
        'project_name': u'proj6',
        'host_name': u'oss-fuzz-linux-zone3-host-high-end-1'
    }, {
        'instance_num': 1,
        'worker_name': u'oss-fuzz-linux-zone3-worker-high-end-proj6-0002',
        'project_name': u'proj6',
        'host_name': u'oss-fuzz-linux-zone3-host-high-end-1'
    }], [
        assignment.to_dict()
        for assignment in data_types.HostWorkerAssignment.query()
    ])


class OssFuzzDistributeCpusTest(unittest.TestCase):
  """Tests OSS-Fuzz CPU distribution."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.compute_engine_projects.load_project',
    ])
    self.mock.load_project.return_value = OSS_FUZZ_CLUSTERS

  def test_equal(self):
    """Tests for each project receiving equal share."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=1.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 30)
    self.assertListEqual([10, 10, 10], result)

  def test_equal_uneven(self):
    """Tests for each project receiving equal share with an uneven division."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=1.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 31)
    self.assertListEqual([11, 10, 10], result)

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 32)
    self.assertListEqual([11, 11, 10], result)

  def test_weight_preference(self):
    """Tests that remainders are given to projects with higher weights

    first.
    """
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=1.01),
        data_types.OssFuzzProject(name='proj3', cpu_weight=1.1),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 4)
    self.assertListEqual([1, 1, 2], result)

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 5)
    self.assertListEqual([1, 2, 2], result)

  def test_not_enough(self):
    """Tests allocation with not enough CPUs."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=1.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 1)
    self.assertListEqual([1, 0, 0], result)

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 2)
    self.assertListEqual([1, 1, 0], result)

  def test_minimum(self):
    """Tests that projects are given a minimum share."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=0.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=0.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=0.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 3)
    self.assertListEqual([1, 1, 1], result)

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 10)
    self.assertListEqual([4, 3, 3], result)

  def test_maximum(self):
    """Tests that projects are capped at the maximum share."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=1.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=1.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 10000)
    self.assertListEqual([1000, 1000, 1000], result)

  def test_primes(self):
    """Test a bunch of different distributions."""
    projects = [
        data_types.OssFuzzProject(name='proj1', cpu_weight=2.0),
        data_types.OssFuzzProject(name='proj2', cpu_weight=3.0),
        data_types.OssFuzzProject(name='proj3', cpu_weight=5.0),
        data_types.OssFuzzProject(name='proj4', cpu_weight=7.0),
        data_types.OssFuzzProject(name='proj5', cpu_weight=11.0),
    ]

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 101)
    self.assertListEqual([7, 10, 18, 26, 40], result)
    self.assertEqual(101, sum(result))

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 887)
    self.assertListEqual([63, 95, 158, 222, 349], result)
    self.assertEqual(887, sum(result))

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 2741)
    self.assertListEqual([214, 313, 509, 705, 1000], result)
    self.assertEqual(2741, sum(result))

    result = manage_vms.OssFuzzClustersManager(
        'clusterfuzz-external').distribute_cpus(projects, 3571)
    self.assertListEqual([356, 483, 738, 994, 1000], result)
    self.assertEqual(3571, sum(result))


@test_utils.with_cloud_emulators('datastore')
class AssignHostWorkerTest(unittest.TestCase):
  """Tests host -> worker assignment."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.compute_engine_projects.load_project',
    ])
    self.mock.load_project.return_value = OSS_FUZZ_CLUSTERS

  def test_assign_keep_existing(self):
    """Test that assignment keeps existing assignments."""
    host_names = ['host']
    worker_instances = [
        manage_vms.WorkerInstance(name='worker-proj-0', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-1', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-2', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-3', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-4', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-5', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-6', project='proj'),
        manage_vms.WorkerInstance(name='worker-proj-7', project='proj'),
    ]

    data_types.HostWorkerAssignment(
        host_name='host',
        instance_num=2,
        worker_name='worker-proj-6',
        project_name='proj',
        id='host-2').put()

    data_types.HostWorkerAssignment(
        host_name='host',
        instance_num=3,
        worker_name='worker-proj-1',
        project_name='proj',
        id='host-3').put()

    data_types.HostWorkerAssignment(
        host_name='host',
        instance_num=0,
        worker_name='worker-nonexistent-1',
        project_name='nonexistent',
        id='host-0').put()

    manager = manage_vms.OssFuzzClustersManager('clusterfuzz-external')
    new_assignments = manager.do_assign_hosts_to_workers(
        host_names, worker_instances, 8)
    self.assertListEqual([
        {
            'host_name': u'host',
            'instance_num': 0,
            'project_name': 'proj',
            'worker_name': 'worker-proj-0'
        },
        {
            'host_name': u'host',
            'instance_num': 1,
            'project_name': 'proj',
            'worker_name': 'worker-proj-2'
        },
        {
            'host_name': u'host',
            'instance_num': 4,
            'project_name': 'proj',
            'worker_name': 'worker-proj-3'
        },
        {
            'host_name': u'host',
            'instance_num': 5,
            'project_name': 'proj',
            'worker_name': 'worker-proj-4'
        },
        {
            'host_name': u'host',
            'instance_num': 6,
            'project_name': 'proj',
            'worker_name': 'worker-proj-5'
        },
        {
            'host_name': u'host',
            'instance_num': 7,
            'project_name': 'proj',
            'worker_name': 'worker-proj-7'
        },
    ], [assignment.to_dict() for assignment in new_assignments])
