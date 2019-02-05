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
"""deploy.py handles the deploy command"""

from collections import namedtuple
import datetime
import json
import os
import re
import sys
import time

from local.butler import appengine
from local.butler import common
from local.butler import constants
from local.butler import package
from src.python.config import local_config
from src.python.system import environment

APPENGINE_FILESIZE_LIMIT = 30 * 1000 * 1000  # ~32 MB
DEPLOY_RETRIES = 3
MATCH_ALL = '*'
RETRY_WAIT_SECONDS = 10

# Give 12 hours for cron jobs to complete before deleting a version.
VERSION_DELETE_WINDOW_MINUTES = 12 * 60

GO_SRC_PREFIX = 'go-'
INDEX_YAML_PATH = os.path.join(appengine.SRC_DIR_PY, 'index.yaml')
SERVICE_REGEX = re.compile(r'service\s*:\s*(.*)')

Version = namedtuple('Version', ['id', 'deploy_time', 'traffic_split'])


def now():
  """Used for mocks."""
  return datetime.datetime.now()


def _get_services(paths):
  """Get list of services from deployment yamls."""
  services = []
  for path in paths:
    for line in open(path):
      match = SERVICE_REGEX.search(line)
      if match:
        matched_service = match.group(1)
        if matched_service not in services:
          services.append(matched_service)
        break

  return services


def _deploy_app_prod(project,
                     deployment_bucket,
                     yaml_paths,
                     package_zip_paths,
                     deploy_appengine=True):
  """Deploy app in production."""
  if deploy_appengine:
    services = _get_services(yaml_paths)
    rebased_yaml_paths = appengine.copy_yamls_and_preprocess(yaml_paths)

    _deploy_appengine(
        project, [INDEX_YAML_PATH] + rebased_yaml_paths,
        stop_previous_version=False)
    for path in rebased_yaml_paths:
      os.remove(path)

    for service in services:
      _delete_old_versions(project, service, VERSION_DELETE_WINDOW_MINUTES)

  if package_zip_paths:
    for package_zip_path in package_zip_paths:
      _deploy_zip(deployment_bucket, package_zip_path)

    _deploy_manifest(deployment_bucket, constants.PACKAGE_TARGET_MANIFEST_PATH)


def _deploy_app_staging(project, yaml_paths):
  """Deploy app in staging."""
  services = _get_services(yaml_paths)
  rebased_yaml_paths = appengine.copy_yamls_and_preprocess(yaml_paths)
  _deploy_appengine(project, rebased_yaml_paths, stop_previous_version=True)
  for path in rebased_yaml_paths:
    os.remove(path)

  for service in services:
    _delete_old_versions(project, service, 0)


def _versions_to_delete(versions, window):
  """Return the versions that should be deleted."""
  # gcloud app versions list returns local time.
  cutoff = now() - datetime.timedelta(minutes=window)

  # Don't delete any versions that stopped serving within
  # |window| minutes before now (or the latest one, since that's definitely
  # still serving).
  # This is so that cron jobs have a chance to finish.

  # Find the first version for which the deploy time of the next version is
  # after the cutoff. This is the first version that we do not delete, because
  # it was still serving after the cutoff.
  delete_end = 0
  while (delete_end < len(versions) - 1 and
         versions[delete_end + 1].deploy_time <= cutoff):
    delete_end += 1

  return versions[:delete_end]


def _delete_old_versions(project, service, delete_window):
  """Delete old versions."""

  def _to_datetime(entry):
    """Parse datetime entry."""
    return datetime.datetime(entry['year'], entry['month'], entry['day'],
                             entry['hour'], entry['minute'], entry['second'])

  _, versions = common.execute('gcloud app versions list --format=json '
                               '--project=%s --service=%s' % (project, service))
  versions = [
      Version(version['id'], _to_datetime(version['last_deployed_time']),
              version['traffic_split']) for version in json.loads(versions)
  ]

  versions.sort(key=lambda v: v.deploy_time)
  assert versions[-1].traffic_split == 1.0

  to_delete = _versions_to_delete(versions, delete_window)
  if not to_delete:
    return

  versions = ' '.join(version.id for version in to_delete)
  common.execute('gcloud app versions delete --quiet '
                 '--project=%s --service=%s %s' % (project, service, versions))


def _deploy_appengine(project, yamls, stop_previous_version, version=None):
  """Deploy to appengine using `yamls`."""
  stop_previous_version_arg = ('--stop-previous-version'
                               if stop_previous_version else
                               '--no-stop-previous-version')

  version_arg = '--version=' + version if version else ''

  for retry_num in xrange(DEPLOY_RETRIES + 1):
    return_code, _ = common.execute(
        'gcloud app deploy %s --quiet '
        '--project=%s %s %s' % (stop_previous_version_arg, project, version_arg,
                                ' '.join(yamls)),
        exit_on_error=False)

    if return_code == 0:
      break

    if retry_num == DEPLOY_RETRIES:
      print 'Failed to deploy after %d retries.' % DEPLOY_RETRIES
      sys.exit(return_code)

    print 'gcloud deployment failed, retrying...'
    time.sleep(RETRY_WAIT_SECONDS)


def find_file_exceeding_limit(path, limit):
  """Find one individual file that exceeds limit within path (recursively)."""
  for root, _, filenames in os.walk(path):
    for filename in filenames:
      full_path = os.path.join(root, filename)
      if os.path.getsize(full_path) >= limit:
        return full_path
  return None


def _deploy_zip(bucket_name, zip_path):
  """Deploy zip to GCS."""
  common.execute('gsutil cp %s gs://%s/%s' % (zip_path, bucket_name,
                                              os.path.basename(zip_path)))


def _deploy_manifest(bucket_name, manifest_path):
  """Deploy source manifest to GCS."""
  common.execute(
      'gsutil cp -a public-read %s '
      'gs://%s/clusterfuzz-source.manifest' % (manifest_path, bucket_name))


def _update_deployment_manager(project, name, path):
  """Update deployment manager settings."""
  config_dir = environment.get_config_directory()
  config_path = os.path.join(config_dir, path)
  if not os.path.exists(config_path):
    return

  gcloud = common.Gcloud(project)
  try:
    gcloud.run('deployment-manager', 'deployments', 'update', name,
               '--config=' + config_path)
  except common.GcloudError:
    # Create deployment if it does not exist.
    gcloud.run('deployment-manager', 'deployments', 'create', name,
               '--config=' + config_path)


def _update_pubsub_queues(project):
  """Update pubsub queues."""
  _update_deployment_manager(project, 'pubsub',
                             os.path.join('pubsub', 'queues.yaml'))


def _update_alerts(project):
  """Update pubsub topics."""
  if local_config.ProjectConfig().get('monitoring.enabled'):
    _update_deployment_manager(project, 'alerts',
                               os.path.join('monitoring', 'alerts.yaml'))


def _update_bigquery(project):
  """Update bigquery datasets and tables."""
  _update_deployment_manager(project, 'bigquery',
                             os.path.join('bigquery', 'datasets.yaml'))


def get_remote_sha():
  """Get remote sha of origin/master."""
  _, remote_sha_line = common.execute('git ls-remote origin refs/heads/master')

  return re.split(r'\s+', remote_sha_line)[0]


def is_diff_origin_master():
  """Check if the current state is different from origin/master."""
  common.execute('git fetch')
  remote_sha = get_remote_sha()
  _, local_sha = common.execute('git rev-parse HEAD')
  _, diff_output = common.execute('git diff origin/master --stat')

  return diff_output.strip() or remote_sha.strip() != local_sha.strip()


def _staging_deployment_helper(deploy_go):
  """Helper for staging deployment."""
  config = local_config.Config(local_config.GAE_CONFIG_PATH)
  project = config.get('application_id')

  print 'Deploying %s to staging.' % project
  deployment_config = config.sub_config('deployment')
  yaml_paths = deployment_config.get_absolute_path('staging')
  yaml_paths = appengine.filter_yaml_paths(yaml_paths, deploy_go)

  _deploy_app_staging(project, yaml_paths)
  print 'Staging deployment finished.'


def _prod_deployment_helper(config_dir,
                            package_zip_paths,
                            deploy_go=True,
                            deploy_appengine=True):
  """Helper for production deployment."""
  config = local_config.Config()
  deployment_bucket = config.get('project.deployment.bucket')

  gae_config = config.sub_config(local_config.GAE_CONFIG_PATH)
  gae_deployment = gae_config.sub_config('deployment')
  project = gae_config.get('application_id')

  print 'Deploying %s to prod.' % project
  yaml_paths = gae_deployment.get_absolute_path('prod')
  yaml_paths = appengine.filter_yaml_paths(yaml_paths, deploy_go)

  if deploy_appengine:
    _update_pubsub_queues(project)
    _update_alerts(project)
    _update_bigquery(project)

  _deploy_app_prod(
      project,
      deployment_bucket,
      yaml_paths,
      package_zip_paths,
      deploy_appengine=deploy_appengine)

  if deploy_appengine:
    common.execute('python butler.py run setup --config-dir {config_dir} '
                   '--non-dry-run'.format(config_dir=config_dir))
  print 'Production deployment finished.'


def execute(args):
  """Deploy Clusterfuzz to Appengine."""
  os.environ['ROOT_DIR'] = '.'

  if not os.path.exists(args.config_dir):
    print 'Please provide a valid configuration directory.'
    sys.exit(1)

  os.environ['CONFIG_DIR_OVERRIDE'] = args.config_dir

  if not common.has_file_in_path('gcloud'):
    print 'Please install gcloud.'
    sys.exit(1)

  is_ci = os.getenv('TEST_BOT_ENVIRONMENT')
  if not is_ci and common.is_git_dirty():
    print 'Your branch is dirty. Please fix before deploying.'
    sys.exit(1)

  if not common.has_file_in_path('gsutil'):
    print 'gsutil not found in PATH.'
    sys.exit(1)

  # Build templates before deployment.
  appengine.build_templates()

  if not is_ci and not args.staging:
    if is_diff_origin_master():
      if args.force:
        print 'You are not on origin/master. --force is used. Continue.'
        for _ in range(3):
          print '.'
          time.sleep(1)
        print
      else:
        print 'You are not on origin/master. Please fix or use --force.'
        sys.exit(1)

  if args.staging:
    revision = common.compute_staging_revision()
    platforms = ['linux']  # No other platforms required.
  elif args.prod:
    revision = common.compute_prod_revision()
    platforms = constants.PLATFORMS.keys()
  else:
    print('Please specify either --prod or --staging. For production '
          'deployments, you probably want to use deploy.sh from your '
          'configs directory instead.')
    sys.exit(1)

  deploy_zips = 'zips' in args.targets
  deploy_appengine = 'appengine' in args.targets

  package_zip_paths = []
  if deploy_zips:
    for platform_name in platforms:
      package_zip_paths.append(
          package.package(revision, platform_name=platform_name))
  else:
    # package.package calls these, so only set these up if we're not packaging,
    # since they can be fairly slow.
    appengine.symlink_dirs()
    common.install_dependencies('linux')
    with open(constants.PACKAGE_TARGET_MANIFEST_PATH, 'w') as f:
      f.write('%s\n' % revision)

  too_large_file_path = find_file_exceeding_limit('src/appengine',
                                                  APPENGINE_FILESIZE_LIMIT)
  if too_large_file_path:
    print(("%s is larger than %d bytes. It wouldn't be deployed to appengine."
           ' Please fix.') % (too_large_file_path, APPENGINE_FILESIZE_LIMIT))
    sys.exit(1)

  deploy_go = args.with_go
  if args.staging:
    _staging_deployment_helper(deploy_go)
  else:
    _prod_deployment_helper(args.config_dir, package_zip_paths, deploy_go,
                            deploy_appengine)

  with open(constants.PACKAGE_TARGET_MANIFEST_PATH) as f:
    print 'Source updated to %s' % f.read()

  if platforms[-1] != common.get_platform():
    # Make sure the installed dependencies are for the current platform.
    common.install_dependencies()
