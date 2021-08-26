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
"""Cron to managed VMs."""

from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
import copy
import itertools
import json
import logging

from google.cloud import ndb

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import compute_engine_projects
from handlers import base_handler
from handlers.cron.helpers import bot_manager
from libs import handler

PROJECT_MIN_CPUS = 1

# This is the maximum number of instances supported in a single instance group.
PROJECT_MAX_CPUS = 1000

NUM_THREADS = 8

WorkerInstance = namedtuple('WorkerInstance', ['name', 'project'])


class ManageVmsException(Exception):
  """Base exception class."""


def _get_project_ids():
  """Return the GCE project IDs."""
  return list(local_config.Config(local_config.GCE_CLUSTERS_PATH).get().keys())


def _instance_name_from_url(instance_url):
  """Extract instance name from url."""
  return instance_url.split('/')[-1]


def get_resource_name(prefix, project_name):
  """Get a name that can be used for GCE resources."""
  # https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers
  max_name_length = 58

  project_name = project_name.lower().replace('_', '-')
  name = prefix + '-' + project_name
  return name[:max_name_length]


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


class ClustersManager(object):
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
          wait_for_instances=False)
    except bot_manager.OperationError as e:
      logging.error('Failed to create instance group %s: %s', resource_name,
                    str(e))


class OssFuzzClustersManager(ClustersManager):
  """Manager for clusters in OSS-Fuzz."""

  def __init__(self, project_id):
    super().__init__(project_id)
    self.worker_to_assignment = {}
    for assignment in self.gce_project.host_worker_assignments:
      self.worker_to_assignment[assignment.worker] = assignment

    self.all_host_names = set()

  def update_clusters(self):
    """Update all clusters in a project."""
    self.start_thread_pool()

    all_projects = list(data_types.OssFuzzProject.query().order(
        data_types.OssFuzzProject.name))

    self.cleanup_old_projects([project.name for project in all_projects])

    projects = [project for project in all_projects if not project.high_end]
    high_end_projects = [
        project for project in all_projects if project.high_end
    ]

    project_infos = [
        self.get_or_create_project_info(project.name) for project in projects
    ]

    high_end_project_infos = [
        self.get_or_create_project_info(project.name)
        for project in high_end_projects
    ]

    for project, project_info in itertools.chain(
        list(zip(projects, project_infos)),
        list(zip(high_end_projects, high_end_project_infos))):
      self.cleanup_clusters(project, project_info)

    for cluster in self.gce_project.clusters:
      self.update_project_cpus(projects, project_infos, high_end_projects,
                               high_end_project_infos, cluster)

    self.cleanup_old_assignments(self.all_host_names)
    self.finish_updates()

  def get_or_create_project_info(self, project_name):
    """Get OSS-Fuzz CPU info by project name (or create a new one if it doesn't
    exist)."""
    key = ndb.Key(data_types.OssFuzzProjectInfo, project_name)
    project_info = key.get()
    if not project_info:
      project_info = data_types.OssFuzzProjectInfo(
          name=project_name, id=project_name)
      project_info.put()

    return project_info

  def get_or_create_host_worker_assignment(self, host_name, instance_num):
    """Get OSS-Fuzz host worker assignment (or create a new one if it doesn't
    exist)."""
    key_id = '%s-%d' % (host_name, instance_num)
    key = ndb.Key(data_types.HostWorkerAssignment, key_id)
    assignment = key.get()
    if not assignment:
      assignment = data_types.HostWorkerAssignment(
          host_name=host_name, instance_num=instance_num, id=key_id)
      assignment.put()

    return assignment

  def cleanup_old_assignments(self, host_names):
    """Remove old OSS-Fuzz host worker assignment entries."""
    to_delete = []
    for assignment in data_types.HostWorkerAssignment.query():
      if assignment.host_name not in host_names:
        to_delete.append(assignment.key)

    ndb_utils.delete_multi(to_delete)

  def distribute_cpus(self, projects, total_cpus):
    """Distribute OSS-Fuzz CPUs for each project by weight.

    |projects| should be sorted
    alphabetically by name to ensure determinism for the same set of CPUs.
    """
    available_cpus = total_cpus
    total_weight = sum(project.cpu_weight for project in projects)

    cpu_count = []

    for project in projects:
      if total_weight:
        share = project.cpu_weight / total_weight
      else:
        share = 0.0

      share_cpus = int(total_cpus * share)
      share_cpus = max(PROJECT_MIN_CPUS, share_cpus)
      share_cpus = min(PROJECT_MAX_CPUS, share_cpus)

      if share_cpus <= available_cpus:
        cpu_count.append(share_cpus)
        available_cpus -= share_cpus
      else:
        cpu_count.append(0)

    # indexes into |project| sorted by highest weight first.
    indexes_by_weight = sorted(
        list(range(len(projects))),
        key=lambda k: projects[k].cpu_weight,
        reverse=True)

    # Distribute the remainder from rounding errors (and capping) up to the cap,
    # preferring projects with a higher weight first.
    while available_cpus:
      cpus_allocated = 0

      for i in range(len(cpu_count)):
        project_index = indexes_by_weight[i]

        if cpu_count[project_index] < PROJECT_MAX_CPUS:
          cpu_count[project_index] += 1
          cpus_allocated += 1

        if cpus_allocated >= available_cpus:
          break

      if not cpus_allocated:
        # Hit the cap for each project. Realistically, this shouldn't ever
        # happen.
        break

      available_cpus -= cpus_allocated

    if available_cpus:
      logging.warning('%d CPUs are not being used.', available_cpus)

    return cpu_count

  def do_assign_hosts_to_workers(self, host_names, worker_instances,
                                 workers_per_host):
    """Assign OSS-Fuzz host instances to workers."""
    # Sort host and worker instance names to make assignment deterministic for
    # the same initial set of host and workers.
    host_names.sort()
    worker_instances.sort(key=lambda w: w.name)

    # Algorithm:
    # For each host instance,
    #   - If there is already an assignment, and a worker with the same name
    #   still exists, do nothing.
    #   - Otherwise, assign it to the first unassigned worker (in alphabetical
    #   order).
    # This should ensure that a worker is reassigned only if it was
    # reimaged/new.
    current_worker_names = {worker.name for worker in worker_instances}
    previous_assigned_workers = set()

    new_assignments = []

    for host_name in host_names:
      for i in range(0, workers_per_host):
        assignment = self.get_or_create_host_worker_assignment(host_name, i)
        if (assignment.worker_name and
            assignment.worker_name in current_worker_names):
          # Existing assignment is still valid. Don't do anything for these.
          logging.info('Keeping old assignment of %s(%d) -> %s.', host_name, i,
                       assignment.worker_name)
          previous_assigned_workers.add(assignment.worker_name)
          continue

        # This host instance was either unassigned or the worker it was
        # connected to no longer exists, so we need to assign it to a new
        # worker.
        new_assignments.append(assignment)

    new_workers = [
        worker for worker in worker_instances
        if worker.name not in previous_assigned_workers
    ]

    assert len(new_assignments) == len(new_workers)
    for assignment, worker in zip(new_assignments, new_workers):
      assignment.worker_name = worker.name
      assignment.project_name = worker.project
      logging.info('New assignment: %s(%d) - >%s.', assignment.host_name,
                   assignment.instance_num, assignment.worker_name)

    return new_assignments

  def delete_gce_resources(self, project_info, cluster_info):
    """Delete instance templates and instance groups."""
    manager = bot_manager.BotManager(self.gce_project.project_id,
                                     cluster_info.gce_zone)

    resource_name = get_resource_name(cluster_info.cluster, project_info.name)

    try:
      manager.instance_group(resource_name).delete()
    except bot_manager.NotFoundError:
      logging.info('Instance group %s already deleted.', resource_name)

    try:
      manager.instance_template(resource_name).delete()
    except bot_manager.NotFoundError:
      logging.info('Instance template %s already deleted.', resource_name)

  def cleanup_old_projects(self, existing_project_names):
    """Cleanup old projects."""
    to_delete = []

    for project_info in list(data_types.OssFuzzProjectInfo.query()):
      if project_info.name in existing_project_names:
        continue

      logging.info('Deleting %s', project_info.name)

      for cluster_info in project_info.clusters:
        self.delete_gce_resources(project_info, cluster_info)

      to_delete.append(project_info.key)

    ndb_utils.delete_multi(to_delete)

  def cleanup_clusters(self, project, project_info):
    """Remove nonexistant clusters."""
    existing_cluster_names = [
        cluster.name for cluster in self.gce_project.clusters
    ]

    # Delete clusters that no longer exist, or the if the high end flag changed
    # for a project.
    to_delete = [
        cluster_info for cluster_info in project_info.clusters if
        (cluster_info.cluster not in existing_cluster_names or project.high_end
         != self.gce_project.get_cluster(cluster_info.cluster).high_end)
    ]
    if not to_delete:
      return

    for cluster_info in to_delete:
      logging.info('Deleting old cluster %s for %s.', cluster_info.cluster,
                   project_info.name)
      self.delete_gce_resources(project_info, cluster_info)

    project_info.clusters = [
        cluster_info for cluster_info in project_info.clusters
        if cluster_info.cluster in existing_cluster_names
    ]

  def update_project_cluster(self,
                             project,
                             project_info,
                             cluster,
                             cpu_count,
                             disk_size_gb=None):
    """Update cluster allocation for a project."""
    service_account = None
    tls_cert = None

    if cluster.worker:
      # If this cluster is for untrusted workers, use the project service
      # account.
      service_account = project.service_account
      tls_cert = ndb.Key(data_types.WorkerTlsCert, project.name).get()
      if not tls_cert:
        logging.warning('TLS certs not set up yet for %s.', project.name)
        return

    cluster_info = project_info.get_cluster_info(cluster.name)
    if not cluster_info:
      project_info.clusters.append(
          data_types.OssFuzzProjectInfo.ClusterInfo(
              cluster=cluster.name,
              gce_zone=cluster.gce_zone,
              cpu_count=cpu_count))
      cluster_info = project_info.clusters[-1]

    # Get a name that can be used for the instance template and instance group.
    resource_name = get_resource_name(cluster.name, project_info.name)

    def do_update():
      """Update the cluster and cpu count info."""
      self.update_cluster(
          cluster,
          resource_name,
          cpu_count,
          task_tag=project_info.name,
          disk_size_gb=disk_size_gb,
          service_account=service_account,
          tls_cert=tls_cert)

      cluster_info.cpu_count = cpu_count

    self.pending_updates.append(self.thread_pool.submit(do_update))

  def update_project_cpus(self, projects, project_infos, high_end_projects,
                          high_end_project_infos, cluster):
    """Update CPU allocations for each project."""
    # Calculate CPUs in each cluster.
    if not cluster.distribute:
      self.pending_updates.append(
          self.thread_pool.submit(self.update_cluster, cluster, cluster.name,
                                  cluster.instance_count))
      return

    if cluster.high_end:
      current_projects = high_end_projects
      current_project_infos = high_end_project_infos
    else:
      current_projects = projects
      current_project_infos = project_infos

    cpu_counts = self.distribute_cpus(current_projects, cluster.instance_count)

    # Resize projects starting with ones that reduce number of CPUs. This is
    # so that we always have quota when we're resizing a project cluster.
    # pylint: disable=cell-var-from-loop
    def _cpu_diff_key(index):
      cluster_info = current_project_infos[index].get_cluster_info(cluster.name)
      if cluster_info and cluster_info.cpu_count is not None:
        old_cpu_count = cluster_info.cpu_count
      else:
        old_cpu_count = 0

      return cpu_counts[index] - old_cpu_count

    resize_order = sorted(list(range(len(cpu_counts))), key=_cpu_diff_key)
    for i in resize_order:
      project = current_projects[i]
      project_info = current_project_infos[i]
      self.update_project_cluster(
          project,
          project_info,
          cluster,
          cpu_counts[i],
          disk_size_gb=project.disk_size_gb)

    self.wait_updates()
    ndb_utils.put_multi(project_infos)
    ndb_utils.put_multi(high_end_project_infos)

    # If the workers are done, we're ready to assign them.
    # Note: This assumes that hosts are always specified before workers.
    if cluster.name in self.worker_to_assignment:
      self.assign_hosts_to_workers(self.worker_to_assignment[cluster.name])

  def get_all_workers_in_cluster(self, manager, cluster_name):
    """Get all workers in a cluster."""
    workers = []
    project_infos = list(data_types.OssFuzzProjectInfo.query().order(
        data_types.OssFuzzProjectInfo.name))

    for project_info in project_infos:
      cluster_info = next((cluster for cluster in project_info.clusters
                           if cluster.cluster == cluster_name), None)
      if not cluster_info or cluster_info.cpu_count == 0:
        continue

      worker_group_name = get_resource_name(cluster_info.cluster,
                                            project_info.name)
      worker_instance_group = manager.instance_group(worker_group_name)
      if not worker_instance_group.exists():
        logging.error('Worker instance group %s does not exist.',
                      worker_group_name)
        continue

      instances = list(worker_instance_group.list_managed_instances())
      if len(instances) != cluster_info.cpu_count:
        logging.error(
            'Number of instances in instance group %s does not match.'
            'Expected %d, got %d.', worker_group_name, cluster_info.cpu_count,
            len(instances))
        raise ManageVmsException('Inconsistent instance count in group.')

      for instance in instances:
        workers.append(
            WorkerInstance(
                name=_instance_name_from_url(instance['instance']),
                project=project_info.name))

    return workers

  def assign_hosts_to_workers(self, assignment):
    """Assign host instances to workers."""
    host_cluster = self.gce_project.get_cluster(assignment.host)
    worker_cluster = self.gce_project.get_cluster(assignment.worker)

    if host_cluster.gce_zone != worker_cluster.gce_zone:
      logging.error('Mismatching zones for %s and %s.', assignment.host,
                    assignment.worker)
      return

    if (host_cluster.instance_count * assignment.workers_per_host !=
        worker_cluster.instance_count):
      logging.error('Invalid host/worker cluster size for %s and %s.',
                    assignment.host, assignment.worker)
      return

    if host_cluster.high_end != worker_cluster.high_end:
      logging.error('Mismatching high end setting for %s and %s',
                    assignment.host, assignment.worker)
      return

    manager = bot_manager.BotManager(self.gce_project.project_id,
                                     host_cluster.gce_zone)
    host_instance_group = manager.instance_group(host_cluster.name)

    if not host_instance_group.exists():
      logging.error('Host instance group %s does not exist.', host_cluster.name)
      return

    host_names = [
        _instance_name_from_url(instance['instance'])
        for instance in host_instance_group.list_managed_instances()
    ]
    self.all_host_names.update(host_names)
    worker_instances = self.get_all_workers_in_cluster(manager,
                                                       worker_cluster.name)

    if len(worker_instances) != worker_cluster.instance_count:
      logging.error(
          'Actual number of worker instances for %s did not match. '
          'Expected %d, got %d.', worker_cluster.name,
          worker_cluster.instance_count, len(worker_instances))
      return

    new_assignments = self.do_assign_hosts_to_workers(
        host_names, worker_instances, assignment.workers_per_host)
    ndb_utils.put_multi(new_assignments)


class Handler(base_handler.Handler):
  """CPU distributor for OSS-Fuzz projects."""

  @handler.cron()
  def get(self):
    """Handle a get request."""
    if utils.is_oss_fuzz():
      manager_class = OssFuzzClustersManager
    else:
      manager_class = ClustersManager

    for project_id in _get_project_ids():
      manager = manager_class(project_id)
      manager.update_clusters()
