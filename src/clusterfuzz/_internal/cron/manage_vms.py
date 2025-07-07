# Copyright 2023 Google LLC
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
"""Cron to managed VMs."""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import logging
from typing import Any
from typing import Dict
from typing import Optional

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.cron.helpers import bot_manager
from clusterfuzz._internal.google_cloud_utils import compute_engine_projects

NUM_THREADS = 8


class ManageVmsError(Exception):
  """Base exception class."""


def _get_project_ids():
  """Return the GCE project IDs."""
  return list(local_config.Config(local_config.GCE_CLUSTERS_PATH).get().keys())


def get_template_body(gce_project,
                      template_name,
                      task_tag=None,
                      disk_size_gb=None,
                      service_account=None,
                      tls_cert=None):
  """Return the instance template body."""
  template_body = copy.deepcopy(
      gce_project.get_instance_template(template_name))
  if task_tag:
    template_body['properties']['metadata']['items'].append({
        'key': 'task-tag',
        'value': task_tag,
    })

  if disk_size_gb:
    disk = template_body['properties']['disks'][0]
    disk['initializeParams']['diskSizeGb'] = disk_size_gb

  if service_account:
    template_body['properties']['serviceAccounts'][0]['email'] = service_account

  if tls_cert:
    template_body['properties']['metadata']['items'].extend([{
        'key': 'tls-cert',
        'value': tls_cert.cert_contents.decode('utf-8'),
    }, {
        'key': 'tls-key',
        'value': tls_cert.key_contents.decode('utf-8'),
    }])

  return template_body


def _get_template_disk_size(template):
  """Get disk size from template."""
  return int(
      template['properties']['disks'][0]['initializeParams']['diskSizeGb'])


def _get_template_service_account(template):
  """Get service account from template."""
  return template['properties']['serviceAccounts'][0]['email']


def _get_metadata_value(metadata_items, key):
  return next((item['value'] for item in metadata_items if item['key'] == key),
              None)


def _template_needs_update(current_template, new_template, resource_name):
  """Return whether or not the template needs an update."""
  current_version = json.loads(current_template['description'])['version']
  new_version = json.loads(new_template['description'])['version']

  if current_version != new_version:
    logging.info(
        'Instance template version out of date '
        '(current=%s, new=%s): %s', current_version, new_version, resource_name)
    return True

  current_disk_size_gb = _get_template_disk_size(current_template)
  new_disk_size_gb = _get_template_disk_size(new_template)

  if current_disk_size_gb != new_disk_size_gb:
    logging.info(
        'Instance template disk size changed '
        '(current=%d, new=%d): %s', current_disk_size_gb, new_disk_size_gb,
        resource_name)
    return True

  current_service_account = _get_template_service_account(current_template)
  new_service_account = _get_template_service_account(new_template)

  if current_service_account != new_service_account:
    logging.info('Service account changed '
                 '(current=%s, new=%s): %s', current_service_account,
                 new_service_account, resource_name)
    return True

  current_tls_cert = _get_metadata_value(
      current_template['properties']['metadata']['items'], 'tls-cert')

  new_tls_cert = _get_metadata_value(
      new_template['properties']['metadata']['items'], 'tls-cert')

  if current_tls_cert != new_tls_cert:
    logging.info('TLS cert changed.')
    return True

  return False


def _auto_healing_policy_to_dict(
    policy: Optional[compute_engine_projects.AutoHealingPolicy]
) -> Optional[Dict[str, Any]]:
  """Converts `policy` into its JSON API representation.

  Returns None if `policy` is None.
  """
  if policy is None:
    return None

  return {
      'healthCheck': policy.health_check,
      'initialDelaySec': policy.initial_delay_sec,
  }


def _update_auto_healing_policy(
    instance_group: bot_manager.InstanceGroup, instance_group_body,
    new_policy: Optional[compute_engine_projects.AutoHealingPolicy]):
  """Updates the given instance group's auto-healing policy if need be."""
  old_policy_dict = None
  policies = instance_group_body.get('autoHealingPolicies')
  if policies:
    old_policy_dict = policies[0]

  new_policy_dict = _auto_healing_policy_to_dict(new_policy)

  if new_policy_dict == old_policy_dict:
    return

  logging.info('Updating auto-healing policy from %s to %s', old_policy_dict,
               new_policy_dict)

  try:
    instance_group.patch_auto_healing_policies(
        auto_healing_policy=new_policy_dict, wait_for_instances=False)
  except bot_manager.OperationError as e:
    logging.error(
        'Failed to patch auto-healing policies for instance group %s: %s',
        instance_group.name, e)


class ClustersManager:
  """Manager for clusters in a project."""

  def __init__(self, project_id):
    self.gce_project = compute_engine_projects.load_project(project_id)
    self.thread_pool = None
    self.pending_updates = []

  def start_thread_pool(self):
    """Start the thread pool."""
    self.thread_pool = ThreadPoolExecutor(max_workers=NUM_THREADS)

  def wait_updates(self):
    """Wait for updates to finish."""
    for update in self.pending_updates:
      # Raise any exceptions.
      update.result()

    self.pending_updates = []

  def finish_updates(self):
    """Close the thread pool and finish cluster updates."""
    self.wait_updates()
    self.thread_pool.shutdown()
    self.thread_pool = None

  def update_clusters(self):
    """Update all clusters in a project."""
    self.start_thread_pool()

    for cluster in self.gce_project.clusters:
      self.pending_updates.append(
          self.thread_pool.submit(self.update_cluster, cluster, cluster.name,
                                  cluster.instance_count))

    self.finish_updates()

  def update_cluster(self,
                     cluster,
                     resource_name,
                     cpu_count,
                     task_tag=None,
                     disk_size_gb=None,
                     service_account=None,
                     tls_cert=None):
    """Update the cluster."""
    manager = bot_manager.BotManager(self.gce_project.project_id,
                                     cluster.gce_zone)

    instance_template = manager.instance_template(resource_name)
    instance_group = manager.instance_group(resource_name)

    # Load expected template body.
    template_body = get_template_body(
        self.gce_project,
        cluster.instance_template,
        task_tag=task_tag,
        disk_size_gb=disk_size_gb,
        service_account=service_account,
        tls_cert=tls_cert)

    if instance_template.exists():
      # Check for updates.
      current_template_body = instance_template.get()
      template_needs_update = _template_needs_update(
          current_template_body, template_body, resource_name)
    else:
      logging.info('Creating new instance template: %s', resource_name)
      instance_template.create(template_body)
      template_needs_update = False

    if instance_group.exists():
      if template_needs_update:
        # Instance groups need to be deleted first before an instance template
        # can be deleted.
        logging.info('Deleting instance group %s for template update.',
                     resource_name)
        try:
          instance_group.delete()
        except bot_manager.NotFoundError:
          # Already deleted.
          pass
      else:
        instance_group_body = instance_group.get()
        if instance_group_body['targetSize'] != cpu_count:
          logging.info('Resizing instance group %s from %d to %d.',
                       resource_name, instance_group_body['targetSize'],
                       cpu_count)
          try:
            instance_group.resize(cpu_count, wait_for_instances=False)
          except bot_manager.OperationError as e:
            logging.error('Failed to resize instance group %s: %s',
                          resource_name, str(e))

        else:
          logging.info('No instance group size changes needed.')

        _update_auto_healing_policy(instance_group, instance_group_body,
                                    cluster.auto_healing_policy)
        return

    if template_needs_update:
      logging.info('Recreating instance template: %s', resource_name)
      instance_template.delete()
      instance_template.create(template_body)

    logging.info('Creating new instance group: %s', resource_name)
    try:
      instance_group.create(
          resource_name,
          resource_name,
          size=cpu_count,
          auto_healing_policy=_auto_healing_policy_to_dict(
              cluster.auto_healing_policy),
          wait_for_instances=False)
    except bot_manager.OperationError as e:
      logging.error('Failed to create instance group %s: %s', resource_name,
                    str(e))


def main():
  """CPU distributor for OSS-Fuzz projects."""
  for project_id in _get_project_ids():
    ClustersManager(project_id).update_clusters()
  logging.info('Mange VMs succeeded.')
  return True
