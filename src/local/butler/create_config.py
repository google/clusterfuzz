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
"""Script for creating a new deployment config."""

import json
import os
import shutil
import subprocess
import sys

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient import discovery
import google_auth_httplib2
import httplib2

from local.butler import appengine
from local.butler import common

_REQUIRED_SERVICES = (
    'appengineflex.googleapis.com',
    'bigquery-json.googleapis.com',
    'cloudapis.googleapis.com',
    'cloudbuild.googleapis.com',
    'clouddebugger.googleapis.com',
    'clouderrorreporting.googleapis.com',
    'cloudprofiler.googleapis.com',
    'cloudresourcemanager.googleapis.com',
    'compute.googleapis.com',
    'containerregistry.googleapis.com',
    'datastore.googleapis.com',
    'deploymentmanager.googleapis.com',
    'file.googleapis.com',
    'iam.googleapis.com',
    'iamcredentials.googleapis.com',
    'logging.googleapis.com',
    'monitoring.googleapis.com',
    'oslogin.googleapis.com',
    'pubsub.googleapis.com',
    'redis.googleapis.com',
    'replicapool.googleapis.com',
    'replicapoolupdater.googleapis.com',
    'resourceviews.googleapis.com',
    'siteverification.googleapis.com',
    'sourcerepo.googleapis.com',
    'stackdriver.googleapis.com',
    'storage-api.googleapis.com',
    'storage-component.googleapis.com',
    'vpcaccess.googleapis.com',
)

_NUM_RETRIES = 2
_ENABLE_SERVICE_BATCH_SIZE = 19


class DomainVerifier(object):
  """Domain verifier."""

  def __init__(self, oauth_client_secrets_path):
    flow = InstalledAppFlow.from_client_secrets_file(
        oauth_client_secrets_path,
        scopes=['https://www.googleapis.com/auth/siteverification'])
    credentials = flow.run_console()

    http = google_auth_httplib2.AuthorizedHttp(
        credentials, http=httplib2.Http())

    self.api = discovery.build('siteVerification', 'v1', http=http)

  def get_domain_verification_tag(self, domain):
    """Get the domain verification meta tag."""
    response = self.api.webResource().getToken(
        body={
            'verificationMethod': 'FILE',
            'site': {
                'identifier': domain,
                'type': 'SITE',
            }
        }).execute(num_retries=_NUM_RETRIES)

    return response['token']

  def verify(self, domain):
    """Verify the domain verification meta tag."""
    self.api.webResource().insert(
        body={
            'site': {
                'identifier': domain,
                'type': 'SITE',
            }
        },
        verificationMethod='FILE').execute(num_retries=_NUM_RETRIES)

  def add_owner(self, domain, email):
    """Add a new domain owner."""
    response = self.api.webResource().get(id=domain).execute(
        num_retries=_NUM_RETRIES)

    if email not in response['owners']:
      response['owners'].append(email)

    self.api.webResource().update(
        id=domain, body=response).execute(num_retries=_NUM_RETRIES)


def get_numeric_project_id(gcloud, project_id):
  """Get the numeric project ID."""
  project_info = json.loads(
      gcloud.run('projects', 'describe', project_id, '--format=json'))
  return project_info['projectNumber']


def app_engine_service_account(project_id):
  """Get the default App Engine service account."""
  return project_id + '@appspot.gserviceaccount.com'


def compute_engine_service_account(gcloud, project_id):
  """Get the default compute engine service account."""
  return (get_numeric_project_id(gcloud, project_id) +
          '-compute@developer.gserviceaccount.com')


def enable_services(gcloud):
  """Enable required services."""
  for i in range(0, len(_REQUIRED_SERVICES), _ENABLE_SERVICE_BATCH_SIZE):
    end = i + _ENABLE_SERVICE_BATCH_SIZE
    gcloud.run('services', 'enable', *_REQUIRED_SERVICES[i:i + end])


def replace_file_contents(file_path, replacements):
  """Replace contents of a file."""
  with open(file_path) as f:
    old_contents = f.read()
    contents = old_contents
    for find, replace in replacements:
      contents = contents.replace(find, replace)

  if contents == old_contents:
    return

  with open(file_path, 'w') as f:
    f.write(contents)


def project_bucket(project_id, bucket_name):
  """Return a project-specific bucket name."""
  return '{name}.{project_id}.appspot.com'.format(
      name=bucket_name, project_id=project_id)


def create_new_config(gcloud, project_id, new_config_dir,
                      domain_verification_tag, bucket_replacements,
                      gae_location, gce_zone, firebase_api_key):
  """Create a new config directory."""
  if os.path.exists(new_config_dir):
    print('Overwriting existing directory.')
    shutil.rmtree(new_config_dir)

  gae_region = appengine.region_from_location(gae_location)
  replacements = [
      ('test-clusterfuzz-service-account-email',
       compute_engine_service_account(gcloud, project_id)),
      ('test-clusterfuzz', project_id),
      ('test-project', project_id),
      ('domain-verification-tag', domain_verification_tag),
      ('gae-region', gae_region),
      ('gce-zone', gce_zone),
      ('firebase-api-key', firebase_api_key),
  ]
  replacements.extend(bucket_replacements)

  shutil.copytree(os.path.join('configs', 'test'), new_config_dir)
  for root_dir, _, filenames in os.walk(new_config_dir):
    for filename in filenames:
      file_path = os.path.join(root_dir, filename)
      replace_file_contents(file_path, replacements)


def deploy_appengine(gcloud, config_dir, appengine_location):
  """Deploy to App Engine."""
  try:
    gcloud.run('app', 'describe')
  except common.GcloudError:
    # Create new App Engine app if it does not exist.
    gcloud.run('app', 'create', '--region=' + appengine_location)

  subprocess.check_call([
      'python', 'butler.py', 'deploy', '--force', '--targets', 'appengine',
      '--prod', '--config-dir', config_dir
  ])


def deploy_zips(config_dir):
  """Deploy source zips."""
  subprocess.check_call([
      'python', 'butler.py', 'deploy', '--force', '--targets', 'zips', '--prod',
      '--config-dir', config_dir
  ])


def create_buckets(project_id, buckets):
  """Create buckets."""
  gsutil = common.Gsutil()
  for bucket in buckets:
    try:
      gsutil.run('defstorageclass', 'get', 'gs://' + bucket)
    except common.GsutilError:
      # Create the bucket if it does not exist.
      gsutil.run('mb', '-p', project_id, 'gs://' + bucket)


def set_cors(config_dir, buckets):
  """Sets cors settings."""
  gsutil = common.Gsutil()
  cors_file_path = os.path.join(config_dir, 'gae', 'cors.json')
  for bucket in buckets:
    gsutil.run('cors', 'set', cors_file_path, 'gs://' + bucket)


def add_service_account_role(gcloud, project_id, service_account, role):
  """Add an IAM role to a service account."""
  gcloud.run('projects', 'add-iam-policy-binding', project_id, '--member',
             'serviceAccount:' + service_account, '--role', role)


def execute(args):
  """Create a new config directory and deployment."""
  # Check this early on, as the deployment at the end would fail otherwise.
  if common.is_git_dirty():
    print('Your checkout contains uncommitted changes. Cannot proceed.')
    sys.exit(1)
  verifier = DomainVerifier(args.oauth_client_secrets_path)

  gcloud = common.Gcloud(args.project_id)
  enable_services(gcloud)

  # Get tag for domain verification.
  appspot_domain = 'https://' + args.project_id + '.appspot.com/'
  domain_verification_tag = verifier.get_domain_verification_tag(appspot_domain)

  blobs_bucket = project_bucket(args.project_id, 'blobs')
  deployment_bucket = project_bucket(args.project_id, 'deployment')

  bucket_replacements = (
      ('test-blobs-bucket', blobs_bucket),
      ('test-deployment-bucket', deployment_bucket),
      ('test-bigquery-bucket', project_bucket(args.project_id, 'bigquery')),
      ('test-backup-bucket', project_bucket(args.project_id, 'backup')),
      ('test-coverage-bucket', project_bucket(args.project_id, 'coverage')),
      ('test-fuzzer-logs-bucket', project_bucket(args.project_id,
                                                 'fuzzer-logs')),
      ('test-corpus-bucket', project_bucket(args.project_id, 'corpus')),
      ('test-quarantine-bucket', project_bucket(args.project_id, 'quarantine')),
      ('test-shared-corpus-bucket',
       project_bucket(args.project_id, 'shared-corpus')),
      ('test-fuzz-logs-bucket', project_bucket(args.project_id, 'fuzz-logs')),
      ('test-mutator-plugins-bucket',
       project_bucket(args.project_id, 'mutator-plugins')),
  )

  # Write new configs.
  create_new_config(gcloud, args.project_id, args.new_config_dir,
                    domain_verification_tag, bucket_replacements,
                    args.appengine_location, args.gce_zone,
                    args.firebase_api_key)
  prev_dir = os.getcwd()
  os.chdir(args.new_config_dir)

  # Deploy App Engine and finish verification of domain.
  os.chdir(prev_dir)
  deploy_appengine(
      gcloud, args.new_config_dir, appengine_location=args.appengine_location)
  verifier.verify(appspot_domain)

  # App Engine service account requires:
  # - Domain ownership to create domain namespaced GCS buckets
  # - Datastore export permission for periodic backups.
  # - Service account signing permission for GCS uploads.
  service_account = app_engine_service_account(args.project_id)
  verifier.add_owner(appspot_domain, service_account)
  add_service_account_role(gcloud, args.project_id, service_account,
                           'roles/datastore.importExportAdmin')
  add_service_account_role(gcloud, args.project_id, service_account,
                           'roles/iam.serviceAccountTokenCreator')

  # Create buckets now that domain is verified.
  create_buckets(args.project_id, [bucket for _, bucket in bucket_replacements])

  # Set CORS settings on the buckets.
  set_cors(args.new_config_dir, [blobs_bucket])

  # Set deployment bucket for the cloud project.
  gcloud.run('compute', 'project-info', 'add-metadata',
             '--metadata=deployment-bucket=' + deployment_bucket)

  # Deploy source zips.
  deploy_zips(args.new_config_dir)
