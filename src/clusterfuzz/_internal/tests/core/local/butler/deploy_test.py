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
"""Deploy tests."""
# pylint: disable=protected-access
import datetime
import json
import os
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest
import yaml

from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from local.butler import common
from local.butler import deploy


@mock.patch('local.butler.deploy.RETRY_WAIT_SECONDS', 0)
class DeployTest(fake_filesystem_unittest.TestCase):
  """Deploy tests."""

  def setUp(self):
    """Setup for deploy test."""
    real_cwd = os.path.realpath(os.getcwd())
    test_utils.set_up_pyfakefs(self)
    self.fs.add_real_directory(
        os.path.join(real_cwd, 'src', 'appengine'), read_only=False)

    helpers.patch_environ(self)
    helpers.patch(self, [
        'local.butler.common.execute',
        'local.butler.common.Gcloud.run',
        'local.butler.common.has_file_in_path',
        'local.butler.deploy.now',
        'os.remove',
    ])
    self.mock.execute.side_effect = self._mock_execute
    self.mock.has_file_in_path.return_value = True
    self.deploy_failure_count = 0

    os.environ['ROOT_DIR'] = '.'
    self.mock.now.return_value = datetime.datetime(2017, 1, 3, 12, 1)
    self.manifest_target = 'clusterfuzz-source.manifest.3'
    self.additional_manifest_target = 'clusterfuzz-source.manifest.3-chrome-tests-syncer'

  def _check_env_variables(self, yaml_paths):
    """Check that environment variables are written to yaml paths."""
    for yaml_path in yaml_paths:
      with open(yaml_path) as f:
        data = yaml.safe_load(f)

      self.assertIn('env_variables', data)
      env_variables = data['env_variables']
      self.assertEqual('test-clusterfuzz', env_variables['APPLICATION_ID'])
      self.assertEqual('test-project', env_variables['PROJECT_NAME'])
      self.assertEqual('test-corpus-bucket', env_variables['CORPUS_BUCKET'])
      self.assertEqual('test-quarantine-bucket',
                       env_variables['QUARANTINE_BUCKET'])

  def _check_no_env_variables(self, yaml_paths):
    """Check that environment variables are not written to yaml paths."""
    for yaml_path in yaml_paths:
      with open(yaml_path) as f:
        data = yaml.safe_load(f)

      self.assertNotIn('env_variables', data)

  # pylint: disable=unused-argument
  def _mock_execute(self, command, *args, **kwargs):
    """Mock execute."""
    if 'app deploy' in command:
      if self.deploy_failure_count == 0:
        return (0, b'ok')

      self.deploy_failure_count -= 1
      return (1, b'failure')

    if 'app describe' in command:
      return (0, b'us-central1')

    if 'describe redis-instance' in command:
      return (0, b'redis-ip')

    if 'describe' in command:
      return (1, b'')

    if 'versions list' in command:
      return (0,
              json.dumps([
                  {
                      'id': 'v1',
                      'last_deployed_time': {
                          'year': 2017,
                          'month': 1,
                          'day': 2,
                          'hour': 0,
                          'minute': 0,
                          'second': 0,
                      },
                      'traffic_split': 0.0,
                  },
                  {
                      'id': 'v2',
                      'last_deployed_time': {
                          'year': 2017,
                          'month': 1,
                          'day': 3,
                          'hour': 0,
                          'minute': 0,
                          'second': 0,
                      },
                      'traffic_split': 0.0,
                  },
                  {
                      'id': 'current',
                      'last_deployed_time': {
                          'year': 2017,
                          'month': 1,
                          'day': 3,
                          'hour': 12,
                          'minute': 0,
                          'second': 1,
                      },
                      'traffic_split': 1.0,
                  },
              ]).encode())

    return (0, b'')

  def test_app_runner(self):
    """Helper to run app deployment tests."""
    deploy._prod_deployment_helper('/config_dir',
                                   ['/windows.zip', '/mac.zip', '/linux.zip'])

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'pubsub'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'pubsub', '--config=./configs/test/pubsub/queues.yaml'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'bigquery'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'bigquery', '--config=./configs/test/bigquery/datasets.yaml'),
        mock.call(mock.ANY, 'buckets', 'describe',
                  'gs://test-deployment-bucket'),
        mock.call(mock.ANY, 'cp', '/windows.zip',
                  'gs://test-deployment-bucket/windows.zip'),
        mock.call(mock.ANY, 'cp', '/mac.zip',
                  'gs://test-deployment-bucket/mac.zip'),
        mock.call(mock.ANY, 'cp', '/linux.zip',
                  'gs://test-deployment-bucket/linux.zip'),
        mock.call(mock.ANY, 'cp',
                  'src/appengine/resources/clusterfuzz-source.manifest',
                  'gs://test-deployment-bucket/' + self.manifest_target),
        mock.call(
            mock.ANY, 'cp',
            'src/appengine/resources/clusterfuzz-source.manifest',
            'gs://test-deployment-bucket/' + self.additional_manifest_target),
    ])

    self.mock.execute.assert_has_calls([
        mock.call('terraform -chdir=/config_dir/terraform init'),
        mock.call('terraform -chdir=/config_dir/terraform apply '
                  '-target=module.clusterfuzz -auto-approve'),
        mock.call('rm -rf /config_dir/terraform/.terraform*'),
        mock.call('gcloud app describe --project=test-clusterfuzz '
                  '--format="value(locationId)"'),
        mock.call('gcloud redis instances describe redis-instance '
                  '--project=test-clusterfuzz --region=us-central1 '
                  '--format="value(host)"'),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call('gcloud app versions list --format=json '
                  '--project=test-clusterfuzz --service=default'),
        mock.call(
            'gcloud app versions delete --quiet --project=test-clusterfuzz '
            '--service=default v1'),
        mock.call('gcloud app versions list --format=json '
                  '--project=test-clusterfuzz --service=cron-service'),
        mock.call(
            'gcloud app versions delete --quiet --project=test-clusterfuzz '
            '--service=cron-service v1'),
        mock.call(
            'python butler.py run setup --config-dir /config_dir --non-dry-run'
        ),
    ])
    self._check_env_variables([
        'src/appengine/app.yaml',
        'src/appengine/cron-service.yaml',
    ])
    self._check_no_env_variables(
        ['src/appengine/cron.yaml', 'src/appengine/index.yaml'])

  def test_app_staging(self):
    """Test deploy app to staging."""
    deploy._staging_deployment_helper()

    self.mock.execute.assert_has_calls([
        mock.call(
            'gcloud app deploy --stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/staging.yaml',
            exit_on_error=False),
        mock.call('gcloud app versions list --format=json '
                  '--project=test-clusterfuzz --service=staging'),
        mock.call(
            'gcloud app versions delete --quiet --project=test-clusterfuzz '
            '--service=staging v1 v2'),
    ])
    self._check_env_variables(['src/appengine/staging.yaml'])

  def test_app_retry_runner(self):
    """Helper for testing app deployment retries."""
    self.deploy_failure_count = 1

    deploy._prod_deployment_helper('/config_dir',
                                   ['/windows.zip', '/mac.zip', '/linux.zip'])

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'pubsub'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'pubsub', '--config=./configs/test/pubsub/queues.yaml'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'bigquery'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'bigquery', '--config=./configs/test/bigquery/datasets.yaml'),
        mock.call(mock.ANY, 'buckets', 'describe',
                  'gs://test-deployment-bucket'),
        mock.call(mock.ANY, 'cp', '/windows.zip',
                  'gs://test-deployment-bucket/windows.zip'),
        mock.call(mock.ANY, 'cp', '/mac.zip',
                  'gs://test-deployment-bucket/mac.zip'),
        mock.call(mock.ANY, 'cp', '/linux.zip',
                  'gs://test-deployment-bucket/linux.zip'),
        mock.call(mock.ANY, 'cp',
                  'src/appengine/resources/clusterfuzz-source.manifest',
                  'gs://test-deployment-bucket/' + self.manifest_target),
        mock.call(
            mock.ANY, 'cp',
            'src/appengine/resources/clusterfuzz-source.manifest',
            'gs://test-deployment-bucket/' + self.additional_manifest_target),
    ])

    self.mock.execute.assert_has_calls([
        mock.call('terraform -chdir=/config_dir/terraform init'),
        mock.call('terraform -chdir=/config_dir/terraform apply '
                  '-target=module.clusterfuzz -auto-approve'),
        mock.call('rm -rf /config_dir/terraform/.terraform*'),
        mock.call('gcloud app describe --project=test-clusterfuzz '
                  '--format="value(locationId)"'),
        mock.call('gcloud redis instances describe redis-instance '
                  '--project=test-clusterfuzz --region=us-central1 '
                  '--format="value(host)"'),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call('gcloud app versions list --format=json '
                  '--project=test-clusterfuzz --service=default'),
        mock.call(
            'gcloud app versions delete --quiet --project=test-clusterfuzz '
            '--service=default v1'),
        mock.call('gcloud app versions list --format=json '
                  '--project=test-clusterfuzz --service=cron-service'),
        mock.call(
            'gcloud app versions delete --quiet --project=test-clusterfuzz '
            '--service=cron-service v1'),
        mock.call(
            'python butler.py run setup --config-dir /config_dir --non-dry-run'
        ),
    ])
    self._check_env_variables([
        'src/appengine/app.yaml',
        'src/appengine/cron-service.yaml',
    ])
    self._check_no_env_variables(
        ['src/appengine/cron.yaml', 'src/appengine/index.yaml'])

  def test_app_retry_failure(self):
    """Test deploy app with retries (failure)."""
    self.deploy_failure_count = 4

    with self.assertRaises(SystemExit):
      deploy._prod_deployment_helper('/config_dir',
                                     ['/windows.zip', '/mac.zip', '/linux.zip'])

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'pubsub'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'pubsub', '--config=./configs/test/pubsub/queues.yaml'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'describe',
                  'bigquery'),
        mock.call(mock.ANY, 'deployment-manager', 'deployments', 'update',
                  'bigquery', '--config=./configs/test/bigquery/datasets.yaml'),
    ])

    self.mock.execute.assert_has_calls([
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
        mock.call(
            'gcloud app deploy --no-stop-previous-version --quiet '
            '--project=test-clusterfuzz  '
            'src/appengine/index.yaml '
            'src/appengine/app.yaml '
            'src/appengine/cron.yaml '
            'src/appengine/cron-service.yaml',
            exit_on_error=False),
    ])

  def test_custom_zip_deployment(self):
    """Verifies custom zip deployment uploads the single developer zip package
    and its custom manifest to the default project test bucket (<PROJECT-ID>-test-deployment)
    without running App Engine or Terraform deploy commands."""
    deploy._prod_deployment_helper(
        '/config_dir', ['/ibarba.zip'],
        deploy_appengine=False,
        deploy_terraform=False,
        deployment_bucket_override='test-clusterfuzz-test-deployment',
        custom_manifest_name='ibarba.zip.manifest')

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'buckets', 'describe',
                  'gs://test-clusterfuzz-test-deployment'),
        mock.call(mock.ANY, 'cp', '/ibarba.zip',
                  'gs://test-clusterfuzz-test-deployment/ibarba.zip'),
        mock.call(mock.ANY, 'cp',
                  'src/appengine/resources/clusterfuzz-source.manifest',
                  'gs://test-clusterfuzz-test-deployment/ibarba.zip.manifest'),
    ])
    # Ensure appengine and terraform commands were not executed.
    for call in self.mock.execute.call_args_list:
      self.assertNotIn('app deploy', call[0][0])
      self.assertNotIn('terraform', call[0][0])

  def test_custom_zip_deployment_bucket_override(self):
    """Verifies custom zip deployment respects an explicit bucket override,
    uploading the zip package and manifest to the specified bucket instead of
    the default test bucket."""
    deploy._prod_deployment_helper(
        '/config_dir', ['/my_bot.zip'],
        deploy_appengine=False,
        deploy_terraform=False,
        deployment_bucket_override='my-custom-bucket',
        custom_manifest_name='my_bot.zip.manifest')

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'buckets', 'describe', 'gs://my-custom-bucket'),
        mock.call(mock.ANY, 'cp', '/my_bot.zip',
                  'gs://my-custom-bucket/my_bot.zip'),
        mock.call(mock.ANY, 'cp',
                  'src/appengine/resources/clusterfuzz-source.manifest',
                  'gs://my-custom-bucket/my_bot.zip.manifest'),
    ])

  def test_create_bucket_if_needed_when_bucket_exists(self):
    """Verifies _create_bucket_if_needed does not attempt to create the bucket
    when 'gcloud storage buckets describe' confirms it already exists."""
    deploy._create_bucket_if_needed('existing-bucket', project='test-app')
    self.mock.run.assert_called_once_with(mock.ANY, 'buckets', 'describe',
                                          'gs://existing-bucket')

  def test_create_bucket_if_needed_when_bucket_missing(self):
    """Verifies _create_bucket_if_needed automatically creates the bucket with
    uniform bucket-level access when 'gcloud storage buckets describe' raises
    a GcloudError (e.g. 404)."""
    self.mock.run.side_effect = [
        common.GcloudError('Bucket not found: 404'),  # buckets describe fails
        None,  # buckets create succeeds
    ]
    deploy._create_bucket_if_needed('missing-bucket', project='test-app')
    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'buckets', 'describe', 'gs://missing-bucket'),
        mock.call(mock.ANY, 'buckets', 'create', 'gs://missing-bucket',
                  '--uniform-bucket-level-access'),
    ])

  def test_custom_zip_deployment_creates_missing_bucket(self):
    """Verifies custom zip deployment automatically creates the target bucket
    if it does not exist before copying package zips and manifests."""

    def _mock_run(self_gcloud, *args):
      if args[:2] == ('buckets', 'describe'):
        raise common.GcloudError('Bucket not found: 404')

    self.mock.run.side_effect = _mock_run
    deploy._prod_deployment_helper(
        '/config_dir', ['/ibarba.zip'],
        deploy_appengine=False,
        deploy_terraform=False,
        deployment_bucket_override='test-clusterfuzz-test-deployment',
        custom_manifest_name='ibarba.zip.manifest')

    self.mock.run.assert_has_calls([
        mock.call(mock.ANY, 'buckets', 'describe',
                  'gs://test-clusterfuzz-test-deployment'),
        mock.call(mock.ANY, 'buckets', 'create',
                  'gs://test-clusterfuzz-test-deployment',
                  '--uniform-bucket-level-access'),
        mock.call(mock.ANY, 'cp', '/ibarba.zip',
                  'gs://test-clusterfuzz-test-deployment/ibarba.zip'),
        mock.call(mock.ANY, 'cp',
                  'src/appengine/resources/clusterfuzz-source.manifest',
                  'gs://test-clusterfuzz-test-deployment/ibarba.zip.manifest'),
    ])


class GetGitUserTest(unittest.TestCase):
  """Tests for common.get_git_user username resolution and fallback order."""

  def setUp(self):
    helpers.patch(self, ['local.butler.common.execute'])
    helpers.patch_environ(self)

  def test_git_config_email(self):
    """Verifies get_git_user extracts the username prefix before '@' when
    'git config user.email' returns a standard email address."""
    self.mock.execute.return_value = (0, b'ibarba@google.com\n')
    self.assertEqual('ibarba', common.get_git_user())

  def test_git_config_email_no_at(self):
    """Verifies get_git_user returns the raw string directly when
    'git config user.email' does not contain an '@' delimiter."""
    self.mock.execute.return_value = (0, b'myusername\n')
    self.assertEqual('myusername', common.get_git_user())

  def test_git_config_email_empty(self):
    """Verifies get_git_user falls back to 'git config user.name' when
    'git config user.email' returns empty output or whitespace."""
    self.mock.execute.side_effect = [
        (0, b'   \n'),  # git config user.email empty
        (0, b'Jane Doe\n'),  # git config user.name succeeds
    ]
    self.assertEqual('jane_doe', common.get_git_user())

  def test_git_config_email_command_failure(self):
    """Verifies get_git_user falls back to 'git config user.name' when the
    'git config user.email' command exits with a non-zero return code."""
    self.mock.execute.side_effect = [
        (1, b''),  # git config user.email fails
        (0, b'Jane Doe\n'),  # git config user.name succeeds
    ]
    self.assertEqual('jane_doe', common.get_git_user())

  def test_git_config_name_spaces_and_special_chars(self):
    """Verifies get_git_user normalizes user names by lowercasing and
    replacing spaces with underscores."""
    self.mock.execute.side_effect = [
        (1, b''),  # git config user.email fails
        (0, b'First Middle Last\n'),  # git config user.name
    ]
    self.assertEqual('first_middle_last', common.get_git_user())

  def test_fallback_to_os_user_env(self):
    """Verifies get_git_user falls back to the system '$USER' environment
    variable when both git email and git name configurations are missing."""
    self.mock.execute.side_effect = [
        (1, b''),  # git config user.email fails
        (1, b''),  # git config user.name fails
    ]
    os.environ['USER'] = 'dev_worker'
    self.assertEqual('dev_worker', common.get_git_user())

  def test_fallback_to_default_when_no_os_user(self):
    """Verifies get_git_user defaults to 'custom_user' when neither git config
    nor the system '$USER' environment variable is available."""
    self.mock.execute.side_effect = [
        (1, b''),  # git config user.email fails
        (1, b''),  # git config user.name fails
    ]
    if 'USER' in os.environ:
      del os.environ['USER']
    self.assertEqual('custom_user', common.get_git_user())


class DeployExecuteTest(unittest.TestCase):
  """Test deploy.execute."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'local.butler.common.compute_prod_revision',
        'local.butler.common.compute_staging_revision',
        'local.butler.common.get_git_user',
        'local.butler.common.get_platform',
        'local.butler.common.has_file_in_path',
        'local.butler.common.install_dependencies',
        'local.butler.common.is_git_dirty',
        'local.butler.appengine.build_templates',
        'local.butler.package.package',
        'local.butler.deploy.find_file_exceeding_limit',
        'local.butler.deploy.is_diff_origin_master',
        'local.butler.deploy._enforce_safe_day_to_deploy',
        'local.butler.deploy._prod_deployment_helper',
        'local.butler.deploy._staging_deployment_helper',
        'local.butler.deploy.local_config.Config',
        'local.butler.deploy.local_config.ProjectConfig',
        'clusterfuzz._internal.system.environment.set_value',
        'os.path.exists',
    ])
    self.mock.exists.return_value = True
    self.mock.has_file_in_path.return_value = True
    self.mock.is_git_dirty.return_value = False
    self.mock.is_diff_origin_master.return_value = False
    self.mock.compute_prod_revision.return_value = 'prod-rev-1'
    self.mock.compute_staging_revision.return_value = 'staging-rev-1'
    self.mock.get_platform.return_value = 'linux'
    self.mock.find_file_exceeding_limit.return_value = None
    self.mock.Config.return_value.sub_config.return_value.get.return_value = (
        'test-app')
    self.mock.ProjectConfig.return_value.get.return_value = {
        'APPLICATION_ID': 'test-app'
    }
    self.mock.package.return_value = ['/packages/custom.zip']

    self.manifest_patcher = mock.patch(
        'builtins.open', mock.mock_open(read_data='test-revision'))
    self.manifest_patcher.start()

  def tearDown(self):
    self.manifest_patcher.stop()

  def test_execute_custom_zip_default_git_user(self):
    """Verifies butler.py deploy --targets custom_zip automatically discovers
    the git username, packages <git_user>.zip, and deploys it with its manifest
    to gs://<PROJECT-ID>-test-deployment/."""
    self.mock.get_git_user.return_value = 'ibarba'
    args = mock.MagicMock(
        staging=False,
        prod=True,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name=None,
        deployment_bucket=None,
    )
    deploy.execute(args)

    self.mock.package.assert_called_once_with(
        'prod-rev-1', release='prod', custom_zip_name='ibarba.zip')
    self.mock._prod_deployment_helper.assert_called_once_with(
        '/config/dir',
        ['/packages/custom.zip'],
        False,  # deploy_appengine
        False,  # deploy_terraform
        test_deployment=False,
        release='prod',
        deployment_bucket_override='test-app-test-deployment',
        custom_manifest_name='ibarba.zip.manifest')

  def test_execute_custom_zip_without_explicit_prod_flag(self):
    """Verifies butler.py deploy --targets custom_zip defaults to computing
    production revision without requiring an explicit --prod or --staging flag."""
    self.mock.get_git_user.return_value = 'ibarba'
    args = mock.MagicMock(
        staging=False,
        prod=False,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name=None,
        deployment_bucket=None,
    )
    deploy.execute(args)

    self.mock.compute_prod_revision.assert_called_once()
    self.mock.package.assert_called_once_with(
        'prod-rev-1', release='prod', custom_zip_name='ibarba.zip')

  def test_execute_custom_zip_fails_when_no_project_id(self):
    """Verifies butler.py deploy --targets custom_zip fails with exit code 1
    when no application_id is found in the project configuration."""
    self.mock.Config.return_value.sub_config.return_value.get.return_value = None
    args = mock.MagicMock(
        staging=False,
        prod=False,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name=None,
        deployment_bucket=None,
    )
    with self.assertRaises(SystemExit):
      deploy.execute(args)

  def test_execute_custom_zip_no_git_user_fallback(self):
    """Verifies butler.py deploy --targets custom_zip falls back to
    'custom_user.zip' and 'custom_user.zip.manifest' when no git or OS username
    is discovered."""
    self.mock.get_git_user.return_value = 'custom_user'
    args = mock.MagicMock(
        staging=False,
        prod=True,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name=None,
        deployment_bucket=None,
    )
    deploy.execute(args)

    self.mock.package.assert_called_once_with(
        'prod-rev-1', release='prod', custom_zip_name='custom_user.zip')
    self.mock._prod_deployment_helper.assert_called_once_with(
        '/config/dir', ['/packages/custom.zip'],
        False,
        False,
        test_deployment=False,
        release='prod',
        deployment_bucket_override='test-app-test-deployment',
        custom_manifest_name='custom_user.zip.manifest')

  def test_execute_custom_zip_name_without_extension(self):
    """Verifies butler.py deploy --targets custom_zip appends the '.zip'
    extension when --custom-zip-name is provided without one."""
    args = mock.MagicMock(
        staging=False,
        prod=True,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name='my_custom_bot',
        deployment_bucket='my-test-bucket',
    )
    deploy.execute(args)

    self.mock.package.assert_called_once_with(
        'prod-rev-1', release='prod', custom_zip_name='my_custom_bot.zip')
    self.mock._prod_deployment_helper.assert_called_once_with(
        '/config/dir', ['/packages/custom.zip'],
        False,
        False,
        test_deployment=False,
        release='prod',
        deployment_bucket_override='my-test-bucket',
        custom_manifest_name='my_custom_bot.zip.manifest')

  def test_execute_custom_zip_name_with_extension(self):
    """Verifies butler.py deploy --targets custom_zip preserves the provided file
    name without duplicate '.zip' extensions when --custom-zip-name already ends
    in '.zip'."""
    args = mock.MagicMock(
        staging=False,
        prod=True,
        targets=['custom_zip'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name='my_custom_bot.zip',
        deployment_bucket='my-test-bucket',
    )
    deploy.execute(args)

    self.mock.package.assert_called_once_with(
        'prod-rev-1', release='prod', custom_zip_name='my_custom_bot.zip')
    self.mock._prod_deployment_helper.assert_called_once_with(
        '/config/dir', ['/packages/custom.zip'],
        False,
        False,
        test_deployment=False,
        release='prod',
        deployment_bucket_override='my-test-bucket',
        custom_manifest_name='my_custom_bot.zip.manifest')

  def test_execute_custom_zip_disables_appengine_and_terraform(self):
    """Verifies butler.py deploy disables App Engine and Terraform operations
    whenever 'custom_zip' is in targets, even if 'appengine' or 'terraform' are
    also specified."""
    args = mock.MagicMock(
        staging=False,
        prod=True,
        targets=['custom_zip', 'appengine', 'terraform'],
        config_dir='/config/dir',
        release='prod',
        force=False,
        custom_zip_name='bot.zip',
        deployment_bucket='test-deployment',
    )
    deploy.execute(args)

    self.mock._prod_deployment_helper.assert_called_once_with(
        '/config/dir',
        ['/packages/custom.zip'],
        False,  # deploy_appengine disabled
        False,  # deploy_terraform disabled
        test_deployment=False,
        release='prod',
        deployment_bucket_override='test-deployment',
        custom_manifest_name='bot.zip.manifest')


class FindFileExceedingLimitTest(fake_filesystem_unittest.TestCase):
  """Test finding files exceeding limit."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fs.create_file('/test/small1', contents='aaa')
    self.fs.create_file('/test/small2', contents='aaa')
    self.fs.create_file('/test/dir1/small3', contents='aaa')
    self.fs.create_file('/test/dir1/small4', contents='aaa')
    self.fs.create_file('/test/dir1/dir1/small5', contents='aaa')
    self.fs.create_file('/test/dir2/small6', contents='aaa')

  def test_get_too_large_file(self):
    """Test getting a too large file."""
    self.fs.create_file('/test/dir1/dir1/too_large', contents='aaaaaa')
    self.assertEqual('/test/dir1/dir1/too_large',
                     deploy.find_file_exceeding_limit('/test', 5))

  def test_get_none(self):
    """Test when there's no too large file."""
    self.assertIsNone(deploy.find_file_exceeding_limit('/test', 10))


class GetRemoteShaTest(unittest.TestCase):
  """Test get_remote_sha."""

  def setUp(self):
    helpers.patch(self, ['local.butler.common.execute'])

  def test_get(self):
    """Test get_remote_sha."""
    self.mock.execute.return_value = (
        0, b'cbb7f93c7ddc1c3a3c98f45ebf5c3490a0c38e95        refs/heads/master')

    self.assertEqual(b'cbb7f93c7ddc1c3a3c98f45ebf5c3490a0c38e95',
                     deploy.get_remote_sha())


class IsDiffOriginMasterTest(unittest.TestCase):
  """Test is_diff_origin_master."""

  def setUp(self):
    helpers.patch(
        self,
        ['local.butler.common.execute', 'local.butler.deploy.get_remote_sha'])

    self.head = ''
    self.diff = ''

    def execute(cmd):
      if cmd == 'git -C . fetch':
        return (0, '')
      if cmd == 'git -C . rev-parse HEAD':
        return (0, self.head)
      if cmd == 'git -C . diff origin/master --stat':
        return (0, self.diff)
      raise RuntimeError()

    self.mock.execute.side_effect = execute

  def test_good(self):
    """Test good."""
    self.diff = ''
    self.mock.get_remote_sha.return_value = 'sha'
    self.head = 'sha'

    self.assertFalse(deploy.is_diff_origin_master())

  def test_diff(self):
    """Test diff."""
    self.diff = 'something'
    self.mock.get_remote_sha.return_value = 'sha'
    self.head = 'sha'

    self.assertTrue(deploy.is_diff_origin_master())

  def test_diff_sha(self):
    """Test different sha."""
    self.diff = ''
    self.mock.get_remote_sha.return_value = 'sha'
    self.head = 'sha2'

    self.assertTrue(deploy.is_diff_origin_master())


class VersionsToDeleteTest(unittest.TestCase):
  """Test _versions_to_delete."""

  def setUp(self):
    helpers.patch(self, [
        'local.butler.deploy.now',
    ])

  def test_single_version(self):
    """Test single revision."""
    self.mock.now.return_value = datetime.datetime(2017, 1, 1, 0, 0)
    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2017, 1, 1, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([], to_delete)

  def test_two_revisions(self):
    """Test two revision."""
    self.mock.now.return_value = datetime.datetime(2017, 1, 1, 0, 0)
    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2017, 1, 1, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([], to_delete)

  def test_cutoff(self):
    """Test various cutoffs."""
    self.mock.now.return_value = datetime.datetime(2017, 1, 30, 0, 0)
    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2017, 1, 28, 23, 59), 0.0),
        deploy.Version('3', datetime.datetime(2017, 1, 29, 0, 0), 0.0),
        deploy.Version('4', datetime.datetime(2017, 1, 30, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2017, 1, 28, 23, 59), 0.0),
    ], to_delete)

    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2017, 1, 28, 23, 59), 0.0),
        deploy.Version('3', datetime.datetime(2017, 1, 29, 0, 1), 0.0),
        deploy.Version('4', datetime.datetime(2017, 1, 30, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
    ], to_delete)

    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2017, 1, 29, 0, 1), 0.0),
        deploy.Version('3', datetime.datetime(2017, 1, 29, 0, 2), 0.0),
        deploy.Version('4', datetime.datetime(2017, 1, 30, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([], to_delete)

    # Latest version should never be deleted.
    to_delete = deploy._versions_to_delete([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2016, 1, 29, 0, 1), 0.0),
        deploy.Version('3', datetime.datetime(2016, 1, 29, 0, 2), 0.0),
        deploy.Version('4', datetime.datetime(2016, 1, 30, 0, 0), 1.0),
    ], 24 * 60)

    self.assertEqual([
        deploy.Version('1', datetime.datetime(2016, 1, 1, 0, 0), 0.0),
        deploy.Version('2', datetime.datetime(2016, 1, 29, 0, 1), 0.0),
        deploy.Version('3', datetime.datetime(2016, 1, 29, 0, 2), 0.0),
    ], to_delete)
