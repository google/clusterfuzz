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
"""Handler used for setting up oss-fuzz jobs."""

import base64
import copy
import json
import re
import urllib2
import yaml

from google.appengine.api import app_identity

import service_accounts

from base import tasks
from base import untrusted
from base import utils
from config import db_config
from config import local_config
from datastore import data_handler
from datastore import data_types
from datastore import ndb
from fuzzing import fuzzer_selection
from google_cloud_utils import pubsub
from google_cloud_utils import storage
from handlers import base_handler
from libs import handler
from metrics import logs
from system import environment

AFL_BUILD_BUCKET = 'clusterfuzz-builds-afl'
LIBFUZZER_BUILD_BUCKET = 'clusterfuzz-builds'
NO_ENGINE_BUILD_BUCKET = 'clusterfuzz-builds-no-engine'
BUCKET_PROJECT_URL = 'clusterfuzz-external.appspot.com'
BUILD_URL_TEMPLATE = ('https://commondatastorage.googleapis.com/{bucket}/'
                      '{project}/{project}-{sanitizer}-([0-9]+).zip')
BUILD_BUCKET_PATH_TEMPLATE = (
    'gs://{bucket}/{project}/{project}-{sanitizer}-([0-9]+).zip')
IMAGE_BUCKET_NAME = 'artifacts.clusterfuzz-images.appspot.com'

BACKUPS_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=100)
LOGS_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=14)
QUARANTINE_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=90)

JOB_TEMPLATE = ('RELEASE_BUILD_BUCKET_PATH = {build_bucket_path}\n'
                'FUZZ_LOGS_BUCKET = {logs_bucket}\n'
                'CORPUS_BUCKET = {corpus_bucket}\n'
                'QUARANTINE_BUCKET = {quarantine_bucket}\n'
                'BACKUP_BUCKET = {backup_bucket}\n'
                'AUTOMATIC_LABELS = Proj-{project},Engine-{engine}\n'
                'PROJECT_NAME = {project}\n'
                'SUMMARY_PREFIX = {project}\n'
                'REVISION_VARS_URL = {revision_vars_url}\n'
                'MANAGED = True\n')

OBJECT_VIEWER_IAM_ROLE = 'roles/storage.objectViewer'
OBJECT_ADMIN_IAM_ROLE = 'roles/storage.objectAdmin'

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')

REVISION_URL = ('https://commondatastorage.googleapis.com/'
                '{bucket}/{project}/{project}-{sanitizer}-%s.srcmap.json')

REQUEST_TIMEOUT = 60

ALLOWED_VIEW_RESTRICTIONS = ['none', 'security', 'all']

PUBSUB_PLATFORMS = ['linux']


class OssFuzzSetupException(Exception):
  """Exception."""


class JobInfo(object):
  """Job information."""

  def __init__(self,
               prefix,
               engine,
               memory_tool,
               cf_job_templates,
               experimental=False,
               minimize_job_override=None):
    self.prefix = prefix
    self.engine = engine
    self.memory_tool = memory_tool
    self.cf_job_templates = cf_job_templates
    self.experimental = experimental
    self.minimize_job_override = minimize_job_override

  def job_name(self, project_name):
    return self.prefix + project_name


# The order of templates is important here. Later templates override settings in
# the earlier ones. An engine template may override vars set for a sanitizer.
LIBFUZZER_ASAN_JOB = JobInfo('libfuzzer_asan_', 'libfuzzer', 'address',
                             ['asan', 'libfuzzer'])
LIBFUZZER_MSAN_JOB = JobInfo('libfuzzer_msan_', 'libfuzzer', 'memory',
                             ['msan', 'libfuzzer'])
LIBFUZZER_UBSAN_JOB = JobInfo('libfuzzer_ubsan_', 'libfuzzer', 'undefined',
                              ['ubsan', 'libfuzzer'])
AFL_ASAN_JOB = JobInfo(
    'afl_asan_',
    'afl',
    'address', ['asan', 'afl'],
    minimize_job_override=LIBFUZZER_ASAN_JOB)
NO_ENGINE_ASAN_JOB = JobInfo('asan_', 'none', 'address', [])

JOB_MAP = {
    'libfuzzer': {
        'address': LIBFUZZER_ASAN_JOB,
        'memory': LIBFUZZER_MSAN_JOB,
        'undefined': LIBFUZZER_UBSAN_JOB,
    },
    'afl': {
        'address': AFL_ASAN_JOB,
    },
    'none': {
        'address': NO_ENGINE_ASAN_JOB,
    }
}

DEFAULT_SANITIZERS = ['address', 'undefined']
DEFAULT_ENGINES = ['libfuzzer', 'afl']


def _get_build_bucket_for_engine(engine):
  """Return the bucket for the given engine."""
  if engine == 'libfuzzer':
    return LIBFUZZER_BUILD_BUCKET

  if engine == 'afl':
    return AFL_BUILD_BUCKET

  if engine == 'none':
    return NO_ENGINE_BUILD_BUCKET

  assert OssFuzzSetupException('Invalid fuzzing engine.')
  return None  # Otherwise pylint is not happy.


def _to_experimental_job(job_info):
  job_info = copy.copy(job_info)
  job_info.experimental = True
  return job_info


def get_build_bucket_path(project_name, engine, memory_tool):
  """Returns the build bucket path for the project and memory tool."""
  return BUILD_BUCKET_PATH_TEMPLATE.format(
      bucket=_get_build_bucket_for_engine(engine),
      project=project_name,
      sanitizer=memory_tool)


def get_github_url(url):
  """Return contents of URL."""
  github_credentials = db_config.get_value('github_credentials')
  if not github_credentials:
    raise OssFuzzSetupException('No github credentials.')

  client_id, client_secret = github_credentials.strip().split(';')
  url += '?client_id=%s&client_secret=%s' % (client_id, client_secret)

  try:
    return json.loads(urllib2.urlopen(url).read())
  except urllib2.HTTPError as e:
    logs.log_error(
        'Failed to get url with code %d and response %s.' % (e.code, e.read()))
    raise

  return None


def find_github_item_url(github_json, name):
  """Get url of a blob/tree from a github json response."""
  for item in github_json['tree']:
    if item['path'] == name:
      return item['url']

  return None


def get_projects():
  """Return list of projects for oss-fuzz."""
  ossfuzz_tree_url = ('https://api.github.com/repos/google/oss-fuzz/'
                      'git/trees/master')
  tree = get_github_url(ossfuzz_tree_url)
  projects = []

  projects_url = find_github_item_url(tree, 'projects')
  if not projects_url:
    logs.log_error('No projects found.')
    return []

  tree = get_github_url(projects_url)
  for item in tree['tree']:
    if item['type'] != 'tree':
      continue

    item_json = get_github_url(item['url'])
    project_yaml_url = find_github_item_url(item_json, 'project.yaml')
    if not project_yaml_url:
      continue

    projects_yaml = get_github_url(project_yaml_url)
    info = yaml.load(base64.b64decode(projects_yaml['content']))

    has_dockerfile = (
        find_github_item_url(item_json, 'Dockerfile') or 'dockerfile' in info)
    if not has_dockerfile:
      continue

    projects.append((item['path'], info))

  return projects


def _process_sanitizers_field(sanitizers):
  """Pre-process sanitizers field into a map from sanitizer name -> dict of
  options."""
  processed_sanitizers = {}
  if not isinstance(sanitizers, list):
    return None

  # each field can either be a Map or a String:
  # sanitizers:
  #   - undefined:
  #       experimental: true
  #   - address
  #   - memory
  for sanitizer in sanitizers:
    if isinstance(sanitizer, basestring):
      processed_sanitizers[sanitizer] = {}
    elif isinstance(sanitizer, dict):
      for key, value in sanitizer.iteritems():
        processed_sanitizers[key] = value
    else:
      return None

  return processed_sanitizers


def get_jobs_for_project(project, info):
  """Return jobs for the project."""
  sanitizers = _process_sanitizers_field(
      info.get('sanitizers', DEFAULT_SANITIZERS))
  if not sanitizers:
    logs.log_error('Invalid sanitizers field for %s.' % project)
    return []

  engines = info.get('fuzzing_engines', DEFAULT_ENGINES)

  jobs = []
  for engine in engines:
    if engine not in JOB_MAP:
      continue

    for sanitizer, options in sanitizers.iteritems():
      experimental = (
          options.get('experimental', False) or info.get('experimental', False))
      if sanitizer in JOB_MAP[engine]:
        job = JOB_MAP[engine][sanitizer]
        if experimental:
          job = _to_experimental_job(job)

        jobs.append(job)

  return jobs


def convert_googlemail_to_gmail(email):
  """Convert @googlemail.com to @gmail.com."""
  # TODO(ochang): Investiate if we can/need to do this in general, and not just
  # for cloud storage bucket IAMs.
  if email.endswith('@googlemail.com'):
    return email.split('@')[0] + '@gmail.com'

  return email


def _add_users_to_bucket(info, client, bucket_name, iam_policy):
  """Add user account to bucket."""
  ccs = sorted(
      ['user:' + convert_googlemail_to_gmail(cc) for cc in ccs_from_info(info)])
  binding = storage.get_bucket_iam_binding(iam_policy, OBJECT_VIEWER_IAM_ROLE)

  if binding:
    # buckets.getIamPolicy can return duplicate members when we add a @gmail.com
    # as well as @googlemail.com address for the same account.
    binding['members'] = sorted(list(set(binding['members'])))
    if binding['members'] == ccs:
      return iam_policy

    filtered_members = [
        member for member in binding['members'] if member in ccs
    ]

    if len(filtered_members) != len(binding['members']):
      # Remove old members.
      binding['members'] = filtered_members
      iam_policy = storage.set_bucket_iam_policy(client, bucket_name,
                                                 iam_policy)

  # We might have no binding either from start or after filtering members above.
  # Create a new one in those cases.
  binding = storage.get_or_create_bucket_iam_binding(iam_policy,
                                                     OBJECT_VIEWER_IAM_ROLE)

  for cc in ccs:
    if cc in binding['members']:
      continue

    logs.log('Adding %s to bucket IAM for %s' % (cc, bucket_name))
    # Add CCs one at a time since the API does not work with invalid or
    # non-Google emails.
    modified_iam_policy = storage.add_single_bucket_iam(
        client, iam_policy, OBJECT_VIEWER_IAM_ROLE, bucket_name, cc)
    if modified_iam_policy:
      iam_policy = modified_iam_policy
      binding = storage.get_bucket_iam_binding(iam_policy,
                                               OBJECT_VIEWER_IAM_ROLE)

  if not binding['members']:
    # Check that the final binding has members. Empty bindings are not valid.
    storage.remove_bucket_iam_binding(iam_policy, OBJECT_VIEWER_IAM_ROLE)

  return iam_policy


def _set_bucket_service_account(service_account, client, bucket_name,
                                iam_policy):
  """Set service account for a bucket."""
  # Add service account as objectAdmin.
  binding = storage.get_or_create_bucket_iam_binding(iam_policy,
                                                     OBJECT_ADMIN_IAM_ROLE)

  members = ['serviceAccount:' + service_account['email']]
  if members == binding['members']:
    # No changes required.
    return iam_policy

  binding['members'] = members
  return storage.set_bucket_iam_policy(client, bucket_name, iam_policy)


def add_bucket_iams(info, client, bucket_name, service_account):
  """Add CC'ed users to storage bucket IAM."""
  iam_policy = storage.get_bucket_iam_policy(client, bucket_name)
  if not iam_policy:
    return

  iam_policy = _add_users_to_bucket(info, client, bucket_name, iam_policy)
  _set_bucket_service_account(service_account, client, bucket_name, iam_policy)


def _deployment_bucket_name():
  """Deployment bucket name."""
  return '{project}-deployment'.format(
      project=app_identity.get_application_id())


def _shared_corpus_bucket_name():
  """Shared corpus bucket name."""
  return environment.get_value('SHARED_CORPUS_BUCKET')


def add_service_account_to_bucket(client, bucket_name, service_account, role):
  """Add service account to the gcr.io images bucket."""
  iam_policy = storage.get_bucket_iam_policy(client, bucket_name)
  if not iam_policy:
    return

  binding = storage.get_or_create_bucket_iam_binding(iam_policy, role)

  member = 'serviceAccount:' + service_account['email']
  if member in binding['members']:
    # No changes required.
    return

  binding['members'].append(member)
  storage.set_bucket_iam_policy(client, bucket_name, iam_policy)


def get_backup_bucket_name(project_name):
  """Return the backup_bucket_name."""
  return project_name + '-backup.' + BUCKET_PROJECT_URL


def get_corpus_bucket_name(project_name):
  """Return the corpus_bucket_name."""
  return project_name + '-corpus.' + BUCKET_PROJECT_URL


def get_quarantine_bucket_name(project_name):
  """Return the quarantine_bucket_name."""
  return project_name + '-quarantine.' + BUCKET_PROJECT_URL


def get_logs_bucket_name(project_name):
  """Return the logs bucket name."""
  return project_name + '-logs.' + BUCKET_PROJECT_URL


def sync_cf_job(project, info, corpus_bucket, quarantine_bucket, logs_bucket,
                backup_bucket, libfuzzer, afl):
  """Sync the config with ClusterFuzz."""
  # Create/update ClusterFuzz jobs.
  for template in get_jobs_for_project(project, info):
    if template.engine == 'libfuzzer':
      fuzzer_entity = libfuzzer
    elif template.engine == 'afl':
      fuzzer_entity = afl
    elif template.engine == 'none':
      # Engine-less jobs are not automatically managed.
      continue
    else:
      raise OssFuzzSetupException('Invalid fuzzing engine.')

    job_name = template.job_name(project)
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
      job = data_types.Job()

    if job_name not in fuzzer_entity.jobs and not info.get('disabled', False):
      # Enable new job.
      fuzzer_entity.jobs.append(job_name)

    job.name = job_name
    job.platform = untrusted.platform_name(project, 'linux')
    job.templates = template.cf_job_templates

    revision_vars_url = REVISION_URL.format(
        project=project,
        bucket=_get_build_bucket_for_engine(template.engine),
        sanitizer=template.memory_tool)

    job.environment_string = JOB_TEMPLATE.format(
        build_bucket_path=get_build_bucket_path(project, template.engine,
                                                template.memory_tool),
        logs_bucket=logs_bucket,
        corpus_bucket=corpus_bucket,
        quarantine_bucket=quarantine_bucket,
        backup_bucket=backup_bucket,
        engine=template.engine,
        project=project,
        revision_vars_url=revision_vars_url)

    help_url = info.get('help_url')
    if help_url:
      job.environment_string += 'HELP_URL = %s\n' % help_url

    if template.experimental:
      job.environment_string += 'EXPERIMENTAL = True\n'

    if template.minimize_job_override:
      minimize_job_override = template.minimize_job_override.job_name(project)
      job.environment_string += (
          'MINIMIZE_JOB_OVERRIDE = %s\n' % minimize_job_override)

    view_restrictions = info.get('view_restrictions')
    if view_restrictions:
      if view_restrictions in ALLOWED_VIEW_RESTRICTIONS:
        job.environment_string += (
            'ISSUE_VIEW_RESTRICTIONS = %s\n' % view_restrictions)
      else:
        logs.log_error('Invalid view restriction setting %s for project %s.' %
                       (view_restrictions, project))

    job.put()


def sync_cf_revision_mappings(project, info):
  """Sync ClusterFuzz revision mappings."""
  config = db_config.get()

  # Parse existing values.
  revision_var_urls = {}
  for line in config.revision_vars_url.splitlines():
    job, vars_url = line.split(';')
    revision_var_urls[job] = vars_url

  for template in get_jobs_for_project(project, info):
    job_name = template.job_name(project)
    revision_var_urls[job_name] = REVISION_URL.format(
        project=project,
        bucket=_get_build_bucket_for_engine(template.engine),
        sanitizer=template.memory_tool)

  config.revision_vars_url = '\n'.join(
      '%s;%s' % (key_value, vars_url)
      for key_value, vars_url in revision_var_urls.iteritems())
  config.put()


def sync_user_permissions(project, info):
  """Sync permissions of project based on project.yaml."""
  ccs = ccs_from_info(info)

  for template in get_jobs_for_project(project, info):
    job_name = template.job_name(project)

    # Delete removed CCs.
    existing_ccs = data_types.ExternalUserPermission.query(
        data_types.ExternalUserPermission.entity_kind ==
        data_types.PermissionEntityKind.JOB,
        data_types.ExternalUserPermission.entity_name == job_name)
    ndb.delete_multi([
        permission.key
        for permission in existing_ccs
        if permission.email not in ccs
    ])

    for cc in ccs:
      query = data_types.ExternalUserPermission.query(
          data_types.ExternalUserPermission.email == cc,
          data_types.ExternalUserPermission.entity_kind ==
          data_types.PermissionEntityKind.JOB,
          data_types.ExternalUserPermission.entity_name == job_name)

      existing_permission = query.get()
      if existing_permission:
        continue

      data_types.ExternalUserPermission(
          email=cc,
          entity_kind=data_types.PermissionEntityKind.JOB,
          entity_name=job_name,
          is_prefix=False,
          auto_cc=data_types.AutoCCType.ALL).put()


def refresh_fuzzer_job_mappings(fuzzer_entities):
  """Ensure that jobs can be created for this fuzzer."""
  # Update mappings for this fuzzer so jobs can be created.
  for fuzzer_entity in fuzzer_entities:
    fuzzer_selection.update_mappings_for_fuzzer(fuzzer_entity)


def ccs_from_info(info):
  """Get list of CC's from project info."""
  ccs = []
  if 'primary_contact' in info:
    primary_contact = info['primary_contact']
    if isinstance(primary_contact, basestring):
      ccs.append(primary_contact)
    else:
      raise OssFuzzSetupException('Bad primary_contact %s.' % primary_contact)

  if 'auto_ccs' in info:
    auto_ccs = info.get('auto_ccs')
    if isinstance(auto_ccs, list):
      ccs.extend(auto_ccs)
    elif isinstance(auto_ccs, basestring):
      ccs.append(auto_ccs)
    else:
      raise OssFuzzSetupException('Bad auto_ccs %s.' % auto_ccs)

  return [utils.normalize_email(cc) for cc in ccs]


def cleanup_old_jobs(project_names):
  """Delete old jobs that are no longer used."""
  to_delete = []

  for job in data_types.Job.query():
    if not job.environment_string:
      continue

    job_environment = job.get_environment()
    if not job_environment.get('MANAGED', False):
      continue

    job_project = job_environment['PROJECT_NAME']
    if job_project not in project_names:
      to_delete.append(job.key)

  if to_delete:
    ndb.delete_multi(to_delete)


def cleanup_old_projects_settings(project_names):
  """Delete old projects that are no longer used or disabled."""
  to_delete = []

  for project in data_types.OssFuzzProject.query():
    if project.name not in project_names:
      to_delete.append(project.key)

  if to_delete:
    ndb.delete_multi(to_delete)


def create_project_settings(project, info, service_account):
  """Setup settings for ClusterFuzz (such as CPU distribution)."""
  key = ndb.Key(data_types.OssFuzzProject, project)
  oss_fuzz_project = key.get()

  # Expecting to run a blackbox fuzzer, so use high end hosts.
  is_high_end = info.get('fuzzing_engines') == ['none']

  ccs = ccs_from_info(info)

  if oss_fuzz_project:
    if oss_fuzz_project.service_account != service_account['email']:
      oss_fuzz_project.service_account = service_account['email']
      oss_fuzz_project.put()

    if oss_fuzz_project.high_end != is_high_end:
      oss_fuzz_project.high_end = is_high_end
      oss_fuzz_project.put()

    if oss_fuzz_project.ccs != ccs:
      oss_fuzz_project.ccs = ccs
      oss_fuzz_project.put()
  else:
    data_types.OssFuzzProject(
        id=project,
        name=project,
        high_end=is_high_end,
        service_account=service_account['email'],
        ccs=ccs).put()


def create_pubsub_topics(project):
  """Create pubsub topics for tasks."""
  for platform in PUBSUB_PLATFORMS:
    name = untrusted.queue_name(project, platform)
    client = pubsub.PubSubClient()
    application_id = app_identity.get_application_id()

    topic_name = pubsub.topic_name(application_id, name)
    if client.get_topic(topic_name) is None:
      client.create_topic(topic_name)

    subscription_name = pubsub.subscription_name(application_id, name)
    if client.get_subscription(subscription_name) is None:
      client.create_subscription(subscription_name, topic_name)


def cleanup_pubsub_topics(project_names):
  """Delete old pubsub topics and subscriptions."""
  client = pubsub.PubSubClient()
  application_id = app_identity.get_application_id()

  expected_topics = set()
  for platform in PUBSUB_PLATFORMS:
    expected_topics.update(
        [untrusted.queue_name(project, platform) for project in project_names])

  pubsub_config = local_config.Config('pubsub.queues')
  unmanaged_queues = [queue['name'] for queue in pubsub_config.get('resources')]

  for topic in client.list_topics(pubsub.project_name(application_id)):
    _, name = pubsub.parse_name(topic)

    if (not name.startswith(tasks.JOBS_PREFIX) and
        not name.startswith(tasks.HIGH_END_JOBS_PREFIX)):
      # Some topic created by another service, ignore.
      continue

    if name in unmanaged_queues:
      continue

    if name in expected_topics:
      continue

    for subscription in client.list_topic_subscriptions(topic):
      client.delete_subscription(subscription)

    client.delete_topic(topic)


class Handler(base_handler.Handler):
  """Setup ClusterFuzz jobs for oss-fuzz."""

  @handler.check_cron()
  def get(self):
    """Handles a GET request."""
    libfuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'libFuzzer').get()
    if not libfuzzer:
      logs.log_error('Failed to get libFuzzer Fuzzer entity.')
      return

    afl = data_types.Fuzzer.query(data_types.Fuzzer.name == 'afl').get()
    if not afl:
      logs.log_error('Failed to get AFL Fuzzer entity.')
      return

    # Create storage client.
    client = storage.create_discovery_storage_client()

    # Clear old job associations.
    libfuzzer.jobs = []
    afl.jobs = []

    data_bundles = set([
        libfuzzer.data_bundle_name,
        afl.data_bundle_name,
    ])

    projects = get_projects()
    for project, info in projects:
      logs.log('Syncing configs for %s.' % project)

      if not VALID_PROJECT_NAME_REGEX.match(project):
        logs.log_error('Invalid project name: ' + project)
        continue

      service_account = service_accounts.get_or_create_service_account(project)
      service_accounts.set_service_account_roles(service_account)

      # Create GCS buckets.
      backup_bucket_name = get_backup_bucket_name(project)
      corpus_bucket_name = get_corpus_bucket_name(project)
      logs_bucket_name = get_logs_bucket_name(project)
      quarantine_bucket_name = get_quarantine_bucket_name(project)

      storage.create_bucket_if_needed(backup_bucket_name, BACKUPS_LIFECYCLE)
      storage.create_bucket_if_needed(corpus_bucket_name)
      storage.create_bucket_if_needed(quarantine_bucket_name,
                                      QUARANTINE_LIFECYCLE)
      storage.create_bucket_if_needed(logs_bucket_name, LOGS_LIFECYCLE)

      try:
        # Note: This is expermiental and uses an alpha storage API that could
        # break at any time.
        add_bucket_iams(info, client, backup_bucket_name, service_account)
        add_bucket_iams(info, client, corpus_bucket_name, service_account)
        add_bucket_iams(info, client, logs_bucket_name, service_account)
        add_bucket_iams(info, client, quarantine_bucket_name, service_account)
      except Exception as e:
        logs.log_error('Failed to add bucket IAMs for %s: %s' % (project, e))

      # Grant the service account read access to deployment, images and
      # shared corpus buckets.
      add_service_account_to_bucket(client, _deployment_bucket_name(),
                                    service_account, OBJECT_VIEWER_IAM_ROLE)
      # TODO(ochang): Remove this once bucket is public.
      add_service_account_to_bucket(client, IMAGE_BUCKET_NAME, service_account,
                                    OBJECT_VIEWER_IAM_ROLE)
      add_service_account_to_bucket(client, _shared_corpus_bucket_name(),
                                    service_account, OBJECT_VIEWER_IAM_ROLE)

      for data_bundle in data_bundles:
        # Workers also need to be able to set up these global bundles.
        data_bundle_bucket_name = data_handler.get_data_bundle_bucket_name(
            data_bundle)
        add_service_account_to_bucket(client, data_bundle_bucket_name,
                                      service_account, OBJECT_VIEWER_IAM_ROLE)

      # Create CF jobs for project.
      sync_cf_job(project, info, corpus_bucket_name, quarantine_bucket_name,
                  logs_bucket_name, backup_bucket_name, libfuzzer, afl)

      # Create revision mappings for CF.
      sync_cf_revision_mappings(project, info)

      sync_user_permissions(project, info)

      # Create Pub/Sub topics for tasks.
      create_pubsub_topics(project)

      # Set up projects settings (such as CPU distribution settings).
      if not info.get('disabled', False):
        create_project_settings(project, info, service_account)

    # Update CF Fuzzer entities for new jobs added.
    libfuzzer.put()
    afl.put()

    # Update job task queues.
    refresh_fuzzer_job_mappings([libfuzzer, afl])

    # Delete old jobs.
    project_names = [project[0] for project in projects]
    cleanup_old_jobs(project_names)

    # Delete old pubsub topics.
    cleanup_pubsub_topics(project_names)

    # Delete old/disabled project settings.
    enabled_projects = [
        project for project, info in projects
        if not info.get('disabled', False)
    ]
    cleanup_old_projects_settings(enabled_projects)
