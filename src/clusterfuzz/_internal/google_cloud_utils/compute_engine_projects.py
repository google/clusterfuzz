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
"""Load project data."""

from collections import namedtuple
import dataclasses
import os
from typing import Any
from typing import Dict
from typing import Optional

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.system import environment

FILE_SCHEME = 'file://'


class Project:
  """Project."""

  def __init__(self, project_id, clusters, instance_templates,
               host_worker_assignments):
    self.project_id = project_id
    self.clusters = clusters
    self.instance_templates = instance_templates
    self.host_worker_assignments = host_worker_assignments

  def get_instance_template(self, name):
    """Get instance template with the given name."""
    return next((template for template in self.instance_templates
                 if template['name'] == name), None)

  def get_cluster(self, name):
    """Get the cluster with the given name."""
    return next((cluster for cluster in self.clusters if cluster.name == name),
                None)


Cluster = namedtuple(
    'Cluster', [
        'name', 'gce_zone', 'instance_count', 'instance_template', 'distribute',
        'worker', 'high_end', 'auto_healing_policy'
    ],
    defaults=[{}])

HostWorkerAssignment = namedtuple('HostWorkerAssignment',
                                  ['host', 'worker', 'workers_per_host'])


@dataclasses.dataclass(kw_only=True)
class AutoHealingPolicy:
  """Represents an auto-healing policy for an instance group."""
  # The health check URL.
  health_check: str

  # The initial delay to apply to the auto-healing policy, in seconds.
  # This controls the policy but not the health check - health checks starts as
  # soon as the instance is created, but the instance group manager ignores
  # unhealthy instances for this delay after creation.
  initial_delay_sec: int

  @classmethod
  def from_config(
      cls, policy: Optional[Dict[str, Any]]) -> Optional['AutoHealingPolicy']:
    """Attempts to create a policy from the given yaml configuration value."""
    if policy is None:
      return None

    health_check = policy.get('health_check')
    initial_delay_sec = policy.get('initial_delay_sec')
    if health_check is None and initial_delay_sec is None:
      return None

    if health_check is None or initial_delay_sec is None:
      logging.warning(
          'Ignoring auto_healing_policy ' +
          'because its two values (health_check, initial_delay_sec) ' +
          'should never exist independently: ' +
          f'({health_check}, {initial_delay_sec})')
      return None

    assert isinstance(health_check, str), repr(health_check)
    assert isinstance(initial_delay_sec, int), repr(initial_delay_sec)

    return cls(health_check=health_check, initial_delay_sec=initial_delay_sec)

  def to_json_dict(self) -> Dict[str, Any]:
    """Returns this policy as an API-compatible dict."""
    return {
        "healthCheck": self.health_check,
        "initialDelaySec": self.initial_delay_sec,
    }


def _process_instance_template(instance_template):
  """Process instance template, normalizing some of metadata key values."""
  # Load metadata items for a particular instance template.
  items = instance_template['properties']['metadata']['items']
  for item in items:
    # If the item value is a relative file path specified using the file://
    # scheme, then subtitute it with the actual file content. This is needed
    # since compute engine instance manager cannot read files from our repo.
    if (isinstance(item['value'], str) and
        item['value'].startswith(FILE_SCHEME)):
      file_path = item['value'][len(FILE_SCHEME):]
      with open(
          os.path.join(environment.get_gce_config_directory(), file_path),
          encoding='utf-8') as f:
        item['value'] = f.read()


def _config_to_project(name, config):
  """Read a project config."""
  clusters = []

  for cluster_name, zone in config['clusters'].items():
    clusters.append(
        Cluster(
            name=cluster_name,
            gce_zone=zone['gce_zone'],
            instance_count=zone['instance_count'],
            instance_template=zone['instance_template'],
            distribute=zone.get('distribute', False),
            auto_healing_policy=AutoHealingPolicy.from_config(
                zone.get('auto_healing_policy')),
            worker=zone.get('worker', False),
            high_end=zone.get('high_end', False)))

  for instance_template in config['instance_templates']:
    _process_instance_template(instance_template)

  host_worker_assignments = []
  for assignment in config.get('host_worker_assignments', []):
    host_worker_assignments.append(
        HostWorkerAssignment(
            host=assignment['host'],
            worker=assignment['worker'],
            workers_per_host=assignment['workers_per_host']))

  return Project(name, clusters, config['instance_templates'],
                 host_worker_assignments)


def _project_configs():
  return local_config.Config(local_config.GCE_CLUSTERS_PATH).get()


def get_projects():
  projects = []
  for name, project in _project_configs().items():
    projects.append(_config_to_project(name, project))

  return projects


def load_project(project_name):
  config = _project_configs().get(project_name)
  if not config:
    return None

  return _config_to_project(project_name, config)
