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
"""Handler used for setting up oss-fuzz and android jobs."""

import base64
import collections
import copy
import json
import re

from google.cloud import ndb
import requests
import yaml

from clusterfuzz._internal.base import tasks
from clusterfuzz._internal.base import untrusted
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import db_config
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import fuzzer_selection
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs

from . import service_accounts

BUILD_BUCKET_PATH_TEMPLATE = (
    'gs://%BUCKET%/%PROJECT%/%PROJECT%-%SANITIZER%-([0-9]+).zip')

BACKUPS_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=100)
LOGS_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=14)
QUARANTINE_LIFECYCLE = storage.generate_life_cycle_config('Delete', age=90)

JOB_TEMPLATE = ('{build_type} = {build_bucket_path}\n'
                'PROJECT_NAME = {project_name}\n'
                'SUMMARY_PREFIX = {project_name}\n'
                'MANAGED = True\n'
                'DISK_SIZE_GB = {disk_size_gb}\n')

OBJECT_VIEWER_IAM_ROLE = 'roles/storage.objectViewer'
OBJECT_ADMIN_IAM_ROLE = 'roles/storage.objectAdmin'

VALID_PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')

REVISION_URL = ('https://commondatastorage.googleapis.com/'
                '{bucket}/{project}/{project}-{sanitizer}-%s.srcmap.json')

REQUEST_TIMEOUT = 60

ALLOWED_VIEW_RESTRICTIONS = ['none', 'security', 'all']

PUBSUB_PLATFORMS = ['linux']

MEMORY_SAFE_LANGUAGES = {'go', 'java', 'python', 'rust'}
OSS_FUZZ_DEFAULT_PROJECT_CPU_WEIGHT = 1.0
OSS_FUZZ_MEMORY_SAFE_LANGUAGE_PROJECT_WEIGHT = 0.2

SetupResult = collections.namedtuple('SetupResult', 'project_names job_names')

HTTP_TIMEOUT_SECONDS = 30

PROJECTS_USING_SUBQUEUES = {'android'}


class ProjectSetupError(Exception):
  """Exception."""


class JobInfo:
  """Job information."""

  def __init__(self,
               prefix,
               engine,
               memory_tool,
               cf_job_templates,
               architecture='x86_64',
               experimental=False,
               minimize_job_override=None):
    self.prefix = prefix
    self.engine = engine
    self.memory_tool = memory_tool
    self.architecture = architecture
    self.cf_job_templates = cf_job_templates
    self.experimental = experimental
    self.minimize_job_override = minimize_job_override

  def job_name(self, project_name, config_suffix):
    return (
        self.prefix + data_types.normalized_name(project_name) + config_suffix)


# The order of templates is important here. Later templates override settings in
# the earlier ones. An engine template may override vars set for a sanitizer.
LIBFUZZER_ASAN_JOB = JobInfo('libfuzzer_asan_', 'libfuzzer', 'address',
                             ['libfuzzer', 'engine_asan', 'prune'])
LIBFUZZER_HWASAN_JOB = JobInfo(
    'libfuzzer_hwasan_',
    'libfuzzer',
    'hardware', ['libfuzzer', 'engine_asan'],
    architecture='arm')
LIBFUZZER_MSAN_JOB = JobInfo('libfuzzer_msan_', 'libfuzzer', 'memory',
                             ['libfuzzer', 'engine_msan'])
LIBFUZZER_UBSAN_JOB = JobInfo('libfuzzer_ubsan_', 'libfuzzer', 'undefined',
                              ['libfuzzer', 'engine_ubsan'])
LIBFUZZER_ASAN_I386_JOB = JobInfo(
    'libfuzzer_asan_i386_',
    'libfuzzer',
    'address', ['libfuzzer', 'engine_asan'],
    architecture='i386')

AFL_ASAN_JOB = JobInfo(
    'afl_asan_',
    'afl',
    'address', ['afl', 'engine_asan'],
    minimize_job_override=LIBFUZZER_ASAN_JOB)
NO_ENGINE_ASAN_JOB = JobInfo('asan_', 'none', 'address', [])
NO_ENGINE_HWASAN_JOB = JobInfo('noengine_hwasan_', 'none', 'hardware', [])
NO_ENGINE_NONE_JOB = JobInfo('noengine_nosanitizer_', 'none', 'none', [])

HONGGFUZZ_ASAN_JOB = JobInfo(
    'honggfuzz_asan_',
    'honggfuzz',
    'address', ['honggfuzz', 'engine_asan'],
    minimize_job_override=LIBFUZZER_ASAN_JOB)

GFT_ASAN_JOB = JobInfo('googlefuzztest_asan_', 'googlefuzztest', 'address',
                       ['googlefuzztest', 'engine_asan'])
GFT_MSAN_JOB = JobInfo('googlefuzztest_msan_', 'googlefuzztest', 'memory',
                       ['googlefuzztest', 'engine_msan'])
GFT_UBSAN_JOB = JobInfo('googlefuzztest_ubsan_', 'googlefuzztest', 'undefined',
                        ['googlefuzztest', 'engine_ubsan'])

CENTIPEDE_ASAN_JOB = JobInfo('centipede_asan_', 'centipede', 'address',
                             ['centipede', 'engine_asan'])

LIBFUZZER_NONE_JOB = JobInfo('libfuzzer_nosanitizer_', 'libfuzzer', 'none',
                             ['libfuzzer', 'prune'])
LIBFUZZER_NONE_I386_JOB = JobInfo(
    'libfuzzer_nosanitizer_i386_',
    'libfuzzer',
    'none', ['libfuzzer', 'prune'],
    architecture='i386')

JOB_MAP = {
    'libfuzzer': {
        'x86_64': {
            'address': LIBFUZZER_ASAN_JOB,
            'memory': LIBFUZZER_MSAN_JOB,
            'undefined': LIBFUZZER_UBSAN_JOB,
            'none': LIBFUZZER_NONE_JOB,
        },
        'i386': {
            'address': LIBFUZZER_ASAN_I386_JOB,
            'none': LIBFUZZER_NONE_I386_JOB,
        },
        'arm': {
            'hardware': LIBFUZZER_HWASAN_JOB,
            'none': LIBFUZZER_NONE_JOB,
        },
    },
    'afl': {
        'x86_64': {
            'address': AFL_ASAN_JOB,
        },
    },
    'honggfuzz': {
        'x86_64': {
            'address': HONGGFUZZ_ASAN_JOB,
        },
    },
    'googlefuzztest': {
        'x86_64': {
            'address': GFT_ASAN_JOB,
            'memory': GFT_MSAN_JOB,
            'undefined': GFT_UBSAN_JOB,
        },
    },
    'none': {
        'x86_64': {
            'address': NO_ENGINE_ASAN_JOB,
        },
        'arm': {
            'address': NO_ENGINE_ASAN_JOB,
            'hardware': NO_ENGINE_HWASAN_JOB,
            'none': NO_ENGINE_NONE_JOB,
        },
    },
    'centipede': {
        'x86_64': {
            'address': CENTIPEDE_ASAN_JOB,
        },
    },
}

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_SANITIZERS = ['address', 'undefined']
DEFAULT_ENGINES = ['libfuzzer', 'afl', 'honggfuzz']


def _to_experimental_job(job_info):
  job_info = copy.copy(job_info)
  job_info.experimental = True
  return job_info


def get_github_url(url):
  """Return contents of URL."""
  github_credentials = db_config.get_value('github_credentials')
  if not github_credentials:
    raise ProjectSetupError('No github credentials.')

  client_id, client_secret = github_credentials.strip().split(';')
  response = requests.get(
      url, auth=(client_id, client_secret), timeout=HTTP_TIMEOUT_SECONDS)
  if response.status_code != 200:
    logs.error(
        f'Failed to get github url: {url}.', status_code=response.status_code)
    response.raise_for_status()

  return json.loads(response.text)


def find_github_item_url(github_json, name):
  """Get url of a blob/tree from a github json response."""
  for item in github_json['tree']:
    if item['path'] == name:
      return item['url']

  return None


def get_oss_fuzz_projects():
  """Return list of projects for oss-fuzz."""
  ossfuzz_tree_url = ('https://api.github.com/repos/google/oss-fuzz/'
                      'git/trees/master')
  tree = get_github_url(ossfuzz_tree_url)
  projects = []

  projects_url = find_github_item_url(tree, 'projects')
  if not projects_url:
    logs.error('No projects found.')
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
    info = yaml.safe_load(base64.b64decode(projects_yaml['content']))

    has_dockerfile = (
        find_github_item_url(item_json, 'Dockerfile') or 'dockerfile' in info)
    if not has_dockerfile:
      continue

    projects.append((item['path'], info))

  return projects


def get_projects_from_gcs(gcs_url):
  """Get projects from GCS path."""
  try:
    data = json.loads(storage.read_data(gcs_url))
  except json.decoder.JSONDecodeError as e:
    raise ProjectSetupError(f'Error loading json file from {gcs_url}: {e}')

  return [(project['name'], project) for project in data['projects']]


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
    if isinstance(sanitizer, str):
      processed_sanitizers[sanitizer] = {}
    elif isinstance(sanitizer, dict):
      for key, value in sanitizer.items():
        processed_sanitizers[key] = value
    else:
      return None

  return processed_sanitizers


def get_jobs_for_project(project, info):
  """Return jobs for the project."""
  sanitizers = _process_sanitizers_field(
      info.get('sanitizers', DEFAULT_SANITIZERS))
  if not sanitizers:
    logs.error(f'Invalid sanitizers field for {project}.')
    return []

  engines = info.get('fuzzing_engines', DEFAULT_ENGINES)
  architectures = info.get('architectures', DEFAULT_ARCHITECTURES)

  jobs = []
  for engine in engines:
    if engine not in JOB_MAP:
      continue

    for architecture in architectures:
      if architecture not in JOB_MAP[engine]:
        continue

      for sanitizer, options in sanitizers.items():
        experimental = (
            options.get('experimental', False) or
            info.get('experimental', False))
        if sanitizer in JOB_MAP[engine][architecture]:
          job = JOB_MAP[engine][architecture][sanitizer]
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

    logs.info(f'Adding {cc} to bucket IAM for {bucket_name}.')
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


def has_maintainer(info):
  """Return whether or not a project has at least one maintainer."""
  return info.get('primary_contact') or info.get('auto_ccs')


def ccs_from_info(info):
  """Get list of CC's from project info."""

  def _get_ccs(field_name, allow_list=True):
    """Return list of emails to cc given a field name."""
    if field_name not in info:
      return []

    field_value = info.get(field_name)
    if allow_list and isinstance(field_value, list):
      return field_value
    if isinstance(field_value, str):
      return [field_value]
    if field_value is None:
      return []

    raise ProjectSetupError(f'Bad value for field {field_name}: {field_value}.')

  ccs = []
  ccs.extend(_get_ccs('primary_contact', allow_list=False))
  ccs.extend(_get_ccs('auto_ccs'))
  ccs.extend(_get_ccs('vendor_ccs'))

  return [utils.normalize_email(cc) for cc in ccs]


def update_fuzzer_jobs(job_names):
  """Update fuzzer job mappings."""
  to_delete = {}

  # First, find all jobs that need to be deleted
  for job in data_types.Job.query():
    if not job.environment_string:
      continue

    job_environment = job.get_environment()
    if not utils.string_is_true(job_environment.get('MANAGED', 'False')):
      continue

    if job.name in job_names:
      continue

    logs.info(f'Deleting job {job.name}')

    print(f'Deleting job {job.name}')
    to_delete[job.name] = job.key

  # Clean up job references from all fuzzer entities
  for fuzzer in data_types.Fuzzer.query():
    # modified = False
    for job_name in to_delete:
      try:
        fuzzer.jobs.remove(job_name)
        # modified = True
      except ValueError:
        pass

    # if modified:
    fuzzer.put()
    fuzzer_selection.update_mappings_for_fuzzer(fuzzer)

  if to_delete:
    ndb_utils.delete_multi(to_delete.values())


def cleanup_old_projects_settings(project_names):
  """Delete old projects that are no longer used or disabled."""
  to_delete = []

  for project in data_types.OssFuzzProject.query():
    if project.name not in project_names:
      logs.info(f'Deleting project {project.name}.')
      to_delete.append(project.key)

  if to_delete:
    ndb_utils.delete_multi(to_delete)


def create_project_settings(project, info, service_account):
  """Setup settings for ClusterFuzz (such as CPU distribution)."""
  key = ndb.Key(data_types.OssFuzzProject, project)
  oss_fuzz_project = key.get()

  # Expecting to run a blackbox fuzzer, so use high end hosts.
  is_high_end = info.get('blackbox', False)

  ccs = ccs_from_info(info)
  language = info.get('language')

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
    if language in MEMORY_SAFE_LANGUAGES:
      cpu_weight = OSS_FUZZ_MEMORY_SAFE_LANGUAGE_PROJECT_WEIGHT
    else:
      cpu_weight = OSS_FUZZ_DEFAULT_PROJECT_CPU_WEIGHT

    data_types.OssFuzzProject(
        id=project,
        name=project,
        high_end=is_high_end,
        cpu_weight=cpu_weight,
        service_account=service_account['email'],
        ccs=ccs).put()


def _create_pubsub_topic(name, client):
  """Create a pubsub topic and subscription if needed."""
  application_id = utils.get_application_id()

  topic_name = pubsub.topic_name(application_id, name)
  if client.get_topic(topic_name) is None:
    client.create_topic(topic_name)

  subscription_name = pubsub.subscription_name(application_id, name)
  if client.get_subscription(subscription_name) is None:
    client.create_subscription(subscription_name, topic_name)


def create_pubsub_topics_for_untrusted(project):
  """Create pubsub topics from untrusted sources for tasks."""
  client = pubsub.PubSubClient()
  for platform in PUBSUB_PLATFORMS:
    name = untrusted.queue_name(project, platform)
    _create_pubsub_topic(name, client)


def create_pubsub_topics_for_queue_id(platform):
  """Create pubsub topics from project configs for tasks."""
  platform, queue_id = platform.split(tasks.SUBQUEUE_IDENTIFIER)
  name = untrusted.queue_name(platform, queue_id)
  client = pubsub.PubSubClient()
  _create_pubsub_topic(name, client)


def cleanup_pubsub_topics(project_names):
  """Delete old pubsub topics and subscriptions."""
  client = pubsub.PubSubClient()
  application_id = utils.get_application_id()

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


class ProjectSetup:
  """Project setup."""

  def __init__(self,
               build_bucket_path_template,
               revision_url_template,
               build_type,
               config_suffix='',
               external_config=None,
               segregate_projects=False,
               experimental_sanitizers=None,
               engine_build_buckets=None,
               fuzzer_entities=None,
               add_info_labels=False,
               add_revision_mappings=False,
               additional_vars=None):
    self._build_type = build_type
    self._config_suffix = config_suffix
    self._external_config = external_config
    self._build_bucket_path_template = build_bucket_path_template
    self._revision_url_template = revision_url_template
    self._segregate_projects = segregate_projects
    self._experimental_sanitizers = experimental_sanitizers
    self._engine_build_buckets = engine_build_buckets
    self._fuzzer_entities = fuzzer_entities
    self._add_info_labels = add_info_labels
    self._add_revision_mappings = add_revision_mappings
    self._additional_vars = additional_vars

  def _get_build_bucket(self, engine, architecture):
    """Return the bucket for the given |engine| and |architecture|."""
    if architecture != 'x86_64':
      engine += '-' + architecture

    bucket = self._engine_build_buckets.get(engine)
    if not bucket:
      raise ProjectSetupError('Invalid fuzzing engine ' + engine)

    return bucket

  def _deployment_bucket_name(self):
    """Deployment bucket name."""
    return f'{utils.get_application_id()}-deployment'

  def _backup_bucket_name(self, project_name):
    """Return the backup_bucket_name."""
    return project_name + '-backup.' + data_handler.bucket_domain_suffix()

  def _corpus_bucket_name(self, project_name):
    """Return the corpus_bucket_name."""
    return project_name + '-corpus.' + data_handler.bucket_domain_suffix()

  def _quarantine_bucket_name(self, project_name):
    """Return the quarantine_bucket_name."""
    return project_name + '-quarantine.' + data_handler.bucket_domain_suffix()

  def _logs_bucket_name(self, project_name):
    """Return the logs bucket name."""
    return project_name + '-logs.' + data_handler.bucket_domain_suffix()

  def _create_service_accounts_and_buckets(self, project, info):
    """Create per-project service account and buckets."""
    service_account, exists = service_accounts.get_or_create_service_account(
        project)
    if not exists:
      # TODO(ochang): Temporary hack to get around
      # https://github.com/google/clusterfuzz/issues/2775.
      service_accounts.set_service_account_roles(service_account)

    # Create GCS buckets.
    backup_bucket_name = self._backup_bucket_name(project)
    corpus_bucket_name = self._corpus_bucket_name(project)
    logs_bucket_name = self._logs_bucket_name(project)
    quarantine_bucket_name = self._quarantine_bucket_name(project)

    storage.create_bucket_if_needed(backup_bucket_name, BACKUPS_LIFECYCLE)
    storage.create_bucket_if_needed(corpus_bucket_name)
    storage.create_bucket_if_needed(quarantine_bucket_name,
                                    QUARANTINE_LIFECYCLE)
    storage.create_bucket_if_needed(logs_bucket_name, LOGS_LIFECYCLE)

    client = storage.create_discovery_storage_client()
    try:
      add_bucket_iams(info, client, backup_bucket_name, service_account)
      add_bucket_iams(info, client, corpus_bucket_name, service_account)
      add_bucket_iams(info, client, logs_bucket_name, service_account)
      add_bucket_iams(info, client, quarantine_bucket_name, service_account)
    except Exception as e:
      logs.error(f'Failed to add bucket IAMs for {project}: {e}.')

    # Grant the service account read access to deployment bucket.
    add_service_account_to_bucket(client, self._deployment_bucket_name(),
                                  service_account, OBJECT_VIEWER_IAM_ROLE)
    data_bundles = {
        fuzzer_entity.get().data_bundle_name
        for fuzzer_entity in self._fuzzer_entities.values()
    }
    for data_bundle in data_bundles:
      if not data_bundle:
        continue

      # Workers also need to be able to set up these global bundles.
      data_bundle_bucket_name = data_handler.get_data_bundle_bucket_name(
          data_bundle)
      add_service_account_to_bucket(client, data_bundle_bucket_name,
                                    service_account, OBJECT_VIEWER_IAM_ROLE)

    return (service_account, backup_bucket_name, corpus_bucket_name,
            logs_bucket_name, quarantine_bucket_name)

  def _get_build_bucket_path(self, project_name, info, engine, memory_tool,
                             architecture):
    """Returns the build bucket path for the |project|, |engine|, |memory_tool|,
    and |architecture|."""
    build_path = info.get('build_path')
    if not build_path:
      build_path = self._build_bucket_path_template

    build_path = build_path.replace(
        '%BUCKET%', self._get_build_bucket(engine, architecture))
    build_path = build_path.replace('%PROJECT%', project_name)
    build_path = build_path.replace('%ENGINE%', engine)
    build_path = build_path.replace('%SANITIZER%', memory_tool)
    return build_path

  def _get_base_project_name(self, project):
    """Returns the base project if subqueues are being used."""
    for base_project in PROJECTS_USING_SUBQUEUES:
      if project.startswith(base_project):
        return base_project
    return project

  def _sync_job(self, project, info, corpus_bucket_name, quarantine_bucket_name,
                logs_bucket_name, backup_bucket_name):
    """Sync the config with ClusterFuzz."""
    # Create/update ClusterFuzz jobs.
    job_names = []

    for template in get_jobs_for_project(project, info):
      if template.engine == 'none':
        if not info.get('managed_engineless', False):
          # Engine-less jobs are not automatically managed unless explicitly
          # enabled
          continue
        # For engineless jobs, we don't need a fuzzer entity
        fuzzer_entity = None
        # Get fuzzers specified for this project
        fuzzers = info.get('fuzzers', [])
      else:
        fuzzer_entity = self._fuzzer_entities.get(template.engine).get()
        if not fuzzer_entity:
          raise ProjectSetupError('Invalid fuzzing engine ' + template.engine)
        fuzzers = []

      job_name = template.job_name(project, self._config_suffix)
      job = data_types.Job.query(data_types.Job.name == job_name).get()
      if not job:
        job = data_types.Job()

      if self._external_config:
        if ('reproduction_topic' not in self._external_config or
            'updates_subscription' not in self._external_config):
          raise ProjectSetupError('Invalid external_config.')

        job.external_reproduction_topic = self._external_config[
            'reproduction_topic']
        job.external_updates_subscription = self._external_config[
            'updates_subscription']
      else:
        job.external_reproduction_topic = None
        job.external_updates_subscription = None

      if not info.get('disabled', False):
        job_names.append(job_name)
        if (fuzzer_entity and job_name not in fuzzer_entity.jobs and
            not job.is_external()):
          # Enable new job.
          fuzzer_entity.jobs.append(job_name)
          fuzzer_entity.put()
        # For engineless jobs, update the fuzzer-job mappings
        for fuzzer_name in fuzzers:
          fuzzer = data_types.Fuzzer.query(
              data_types.Fuzzer.name == fuzzer_name).get()
          if not fuzzer:
            raise ProjectSetupError(
                f'Invalid fuzzer {fuzzer_name} specified for engineless job')
          if job_name not in fuzzer.jobs:
            fuzzer.jobs.append(job_name)
            fuzzer.put()

      job.name = job_name
      if self._segregate_projects:
        job.platform = untrusted.platform_name(project, 'linux')
      else:
        job.platform = 'LINUX'

      job.templates = template.cf_job_templates

      # Centipede always uses unsanitized binary as the main fuzz target.
      if template.engine == 'centipede':
        build_bucket_path = self._get_build_bucket_path(
            project, info, template.engine, 'none', template.architecture)
        print(template, build_bucket_path)
      else:
        build_bucket_path = self._get_build_bucket_path(
            project, info, template.engine, template.memory_tool,
            template.architecture)
      base_project_name = self._get_base_project_name(project)
      oss_fuzz_project = ndb.Key(data_types.OssFuzzProject, project).get()
      oss_fuzz_gb = oss_fuzz_project.disk_size_gb if oss_fuzz_project else None
      job.environment_string = JOB_TEMPLATE.format(
          build_type=self._build_type,
          build_bucket_path=build_bucket_path,
          engine=template.engine,
          project_name=base_project_name,
          disk_size_gb=oss_fuzz_gb)
      if oss_fuzz_gb is not None:
        job.environment_string += 'ALLOW_UNPACK_OVER_HTTP = True\n'

      # Centipede requires a separate build of the sanitized binary.
      if template.engine == 'centipede':
        extra_build_bucket_path = self._get_build_bucket_path(
            project, info, template.engine, template.memory_tool,
            template.architecture)
        job.environment_string += (
            f'EXTRA_BUILD_BUCKET_PATH = {extra_build_bucket_path}\n')
      if self._add_revision_mappings:
        revision_vars_url = self._revision_url_template.format(
            project=project,
            bucket=self._get_build_bucket(template.engine,
                                          template.architecture),
            sanitizer=template.memory_tool)

        job.environment_string += f'REVISION_VARS_URL = {revision_vars_url}\n'

      if logs_bucket_name:
        job.environment_string += f'FUZZ_LOGS_BUCKET = {logs_bucket_name}\n'

      if corpus_bucket_name:
        job.environment_string += f'CORPUS_BUCKET = {corpus_bucket_name}\n'

      if quarantine_bucket_name:
        job.environment_string += (
            f'QUARANTINE_BUCKET = {quarantine_bucket_name}\n')

      if backup_bucket_name:
        job.environment_string += f'BACKUP_BUCKET = {backup_bucket_name}\n'

      if self._add_info_labels:
        automatic_labels = [f'Proj-{project}', f'Engine-{template.engine}']
        labels = info.get('labels')
        if labels and '*' in labels:
          automatic_labels.extend(labels['*'])
        automatic_labels = ','.join(automatic_labels)
        job.environment_string += f'AUTOMATIC_LABELS = {automatic_labels}\n'

      help_url = info.get('help_url')
      if help_url:
        job.environment_string += f'HELP_URL = {help_url}\n'

      if (template.experimental or
          (self._experimental_sanitizers and
           template.memory_tool in self._experimental_sanitizers)):
        job.environment_string += 'EXPERIMENTAL = True\n'

      if template.minimize_job_override:
        minimize_job_override = template.minimize_job_override.job_name(
            project, self._config_suffix)
        job.environment_string += (
            f'MINIMIZE_JOB_OVERRIDE = {minimize_job_override}\n')

      view_restrictions = info.get('view_restrictions')
      if view_restrictions:
        view_restrictions = view_restrictions.lower()
        if view_restrictions in ALLOWED_VIEW_RESTRICTIONS:
          job.environment_string += (
              f'ISSUE_VIEW_RESTRICTIONS = {view_restrictions}\n')
        else:
          logs.error(f'Invalid view restriction setting {view_restrictions} '
                     f'for project {project}.')

      if not has_maintainer(info):
        job.environment_string += 'DISABLE_DISCLOSURE = True\n'

      selective_unpack = info.get('selective_unpack')
      if selective_unpack:
        job.environment_string += 'UNPACK_ALL_FUZZ_TARGETS_AND_FILES = False\n'

      main_repo = info.get('main_repo')
      if main_repo:
        job.environment_string += f'MAIN_REPO = {main_repo}\n'

      file_github_issue = info.get('file_github_issue', False)
      job.environment_string += f'FILE_GITHUB_ISSUE = {file_github_issue}\n'

      # Device-specific queues created during project setup.
      queue_id = info.get('queue_id', False)
      if queue_id:
        platform = info.get('platform',
                            'LINUX').upper() + ':' + queue_id.upper()
        job.platform = platform
        if platform.startswith('ANDROID'):
          job.templates.append('android')

        create_pubsub_topics_for_queue_id(job.platform)

      if self._additional_vars:
        additional_vars = {}
        additional_vars.update(self._additional_vars.get('all', {}))

        engine_vars = self._additional_vars.get(template.engine, {})
        engine_sanitizer_vars = engine_vars.get(template.memory_tool, {})
        additional_vars.update(engine_sanitizer_vars)

        for key, value in sorted(additional_vars.items()):
          job.environment_string += (
              f'{key} = {str(value).encode("unicode-escape").decode("utf-8")}\n'
          )

      if info.get('additional_vars'):
        additional_vars = {}
        additional_vars.update(info.get('additional_vars', {}))
        for key, value in sorted(additional_vars.items()):
          job.environment_string += (
              f'{key} = {str(value).encode("unicode-escape").decode("utf-8")}\n'
          )

      job.put()
    print(project, job_names)
    return job_names

  def sync_user_permissions(self, project, info):
    """Sync permissions of project based on project.yaml."""
    ccs = ccs_from_info(info)

    for template in get_jobs_for_project(project, info):
      job_name = template.job_name(project, self._config_suffix)

      # Delete removed CCs.
      existing_ccs = data_types.ExternalUserPermission.query(
          data_types.ExternalUserPermission.entity_kind ==
          data_types.PermissionEntityKind.JOB,
          data_types.ExternalUserPermission.entity_name == job_name)
      ndb_utils.delete_multi([
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

  def set_up(self, projects):
    """Do project setup. Return a list of all the project names that were set
    up."""
    job_names = []
    for project, info in projects:
      logs.info(f'Syncing configs for {project}.')

      backup_bucket_name = None
      corpus_bucket_name = None
      logs_bucket_name = None
      quarantine_bucket_name = None

      if self._segregate_projects:
        # Create per project service account and GCS buckets.
        (service_account, backup_bucket_name, corpus_bucket_name,
         logs_bucket_name, quarantine_bucket_name) = (
             self._create_service_accounts_and_buckets(project, info))

      # Create CF jobs for project.
      current_job_names = self._sync_job(project, info, corpus_bucket_name,
                                         quarantine_bucket_name,
                                         logs_bucket_name, backup_bucket_name)
      job_names.extend(current_job_names)

      if self._segregate_projects:
        self.sync_user_permissions(project, info)

        # Create Pub/Sub topics for tasks.
        create_pubsub_topics_for_untrusted(project)

        # Set up projects settings (such as CPU distribution settings).
        if not info.get('disabled', False):
          create_project_settings(project, info, service_account)

    # Delete old/disabled project settings.
    enabled_projects = [
        project for project, info in projects
        if not info.get('disabled', False)
    ]
    return SetupResult(enabled_projects, job_names)


def cleanup_stale_projects(project_names, job_names, segregate_projects):
  """Clean up stale projects."""
  update_fuzzer_jobs(job_names)
  cleanup_old_projects_settings(project_names)

  if segregate_projects:
    cleanup_pubsub_topics(project_names)


def main():
  """Setup ClusterFuzz jobs for projects."""
  libfuzzer = data_types.Fuzzer.query(
      data_types.Fuzzer.name == 'libFuzzer').get()
  if not libfuzzer:
    logs.error('Failed to get libFuzzer Fuzzer entity.')
    return False

  afl = data_types.Fuzzer.query(data_types.Fuzzer.name == 'afl').get()
  if not afl:
    logs.error('Failed to get AFL Fuzzer entity.')
    return False

  honggfuzz = data_types.Fuzzer.query(
      data_types.Fuzzer.name == 'honggfuzz').get()
  if not honggfuzz:
    logs.error('Failed to get honggfuzz Fuzzer entity.')
    return False

  gft = data_types.Fuzzer.query(
      data_types.Fuzzer.name == 'googlefuzztest').get()
  if not gft:
    logs.error('Failed to get googlefuzztest Fuzzer entity.')
    return False

  centipede = data_types.Fuzzer.query(
      data_types.Fuzzer.name == 'centipede').get()
  if not centipede:
    logs.error('Failed to get Centipede Fuzzer entity.')
    return False

  project_config = local_config.ProjectConfig()
  segregate_projects = project_config.get('segregate_projects')
  project_setup_configs = project_config.get('project_setup')
  project_names = set()
  job_names = set()

  fuzzer_entities = {
      'afl': afl.key,
      'centipede': centipede.key,
      'honggfuzz': honggfuzz.key,
      'googlefuzztest': gft.key,
      'libfuzzer': libfuzzer.key,
  }

  for setup_config in project_setup_configs:
    bucket_config = setup_config.get('build_buckets')

    if not bucket_config:
      raise ProjectSetupError('Project setup buckets not specified.')

    config = ProjectSetup(
        BUILD_BUCKET_PATH_TEMPLATE,
        REVISION_URL,
        setup_config.get('build_type'),
        config_suffix=setup_config.get('job_suffix', ''),
        external_config=setup_config.get('external_config', ''),
        segregate_projects=segregate_projects,
        experimental_sanitizers=setup_config.get('experimental_sanitizers', []),
        engine_build_buckets={
            'libfuzzer': bucket_config.get('libfuzzer'),
            'libfuzzer-i386': bucket_config.get('libfuzzer_i386'),
            'libfuzzer-arm': bucket_config.get('libfuzzer_arm'),
            'afl': bucket_config.get('afl'),
            'honggfuzz': bucket_config.get('honggfuzz'),
            'googlefuzztest': bucket_config.get('googlefuzztest'),
            'none': bucket_config.get('no_engine'),
            'centipede': bucket_config.get('centipede'),
        },
        fuzzer_entities=fuzzer_entities,
        add_info_labels=setup_config.get('add_info_labels', False),
        add_revision_mappings=setup_config.get('add_revision_mappings', False),
        additional_vars=setup_config.get('additional_vars'))

    projects_source = setup_config.get('source')
    if projects_source == 'oss-fuzz':
      projects = get_oss_fuzz_projects()
    elif projects_source.startswith(storage.GS_PREFIX):
      projects = get_projects_from_gcs(projects_source)
    else:
      raise ProjectSetupError('Invalid projects source: ' + projects_source)

    if not projects:
      raise ProjectSetupError('Missing projects list.')

    result = config.set_up(projects)
    project_names.update(result.project_names)
    job_names.update(result.job_names)

  cleanup_stale_projects(project_names, job_names, segregate_projects)

  logs.info('Project setup succeeded.')
  return True
