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
import sys
import unittest

import mock
from pyfakefs import fake_filesystem_unittest
import yaml

from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
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
    self.manifest_target = 'clusterfuzz-source.manifest'
    if sys.version_info.major == 3:
      self.manifest_target += '.3'

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
      self.assertEqual('test-shared-corpus-bucket',
                       env_variables['SHARED_CORPUS_BUCKET'])

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
      return (0, b'us-central')

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

  def test_app(self):
    """Test deploy app."""
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
        mock.call('gsutil cp /windows.zip gs://test-deployment-bucket/'
                  'windows.zip'),
        mock.call('gsutil cp /mac.zip gs://test-deployment-bucket/'
                  'mac.zip'),
        mock.call('gsutil cp /linux.zip gs://test-deployment-bucket/'
                  'linux.zip'),
        mock.call('gsutil cp -a public-read src/appengine/resources/'
                  'clusterfuzz-source.manifest '
                  'gs://test-deployment-bucket/' + self.manifest_target),
        mock.call('python butler.py run setup --config-dir /config_dir '
                  '--non-dry-run'),
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

  def test_app_retry(self):
    """Test deploy app with retries."""
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
        mock.call('gsutil cp /windows.zip gs://test-deployment-bucket/'
                  'windows.zip'),
        mock.call('gsutil cp /mac.zip gs://test-deployment-bucket/'
                  'mac.zip'),
        mock.call('gsutil cp /linux.zip gs://test-deployment-bucket/'
                  'linux.zip'),
        mock.call('gsutil cp -a public-read src/appengine/resources/'
                  'clusterfuzz-source.manifest '
                  'gs://test-deployment-bucket/' + self.manifest_target),
        mock.call('python butler.py run setup --config-dir /config_dir '
                  '--non-dry-run'),
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
      if cmd == 'git fetch':
        return (0, '')
      if cmd == 'git rev-parse HEAD':
        return (0, self.head)
      if cmd == 'git diff origin/master --stat':
        return (0, self.diff)
      raise Exception()

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
