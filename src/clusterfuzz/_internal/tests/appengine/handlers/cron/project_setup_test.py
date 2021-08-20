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
"""Tests for project_setup."""
import ast
import copy
import json
import os
import posixpath
import unittest

import flask
from google.cloud import ndb
import googleapiclient
import mock
import six
import webtest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import pubsub
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import mock_config
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import project_setup

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'project_setup_data')

EXISTING_BUCKETS = set(['lib1-logs.clusterfuzz-external.appspot.com'])


def _read_data_file(data_file):
  """Helper function to read the contents of a data file."""
  with open(os.path.join(DATA_DIRECTORY, data_file)) as handle:
    return handle.read()


class MockRequest(object):
  """Mock API request."""

  def __init__(self, raise_exception=False, return_value=None):
    self.raise_exception = raise_exception
    self.return_value = return_value

  def execute(self):
    """Mock execute()."""
    if self.raise_exception:
      raise googleapiclient.errors.HttpError(mock.Mock(status=404), b'')

    return self.return_value


def mock_bucket_get(bucket=None):
  """Mock buckets().get()."""
  if bucket in EXISTING_BUCKETS:
    return MockRequest(False, {'name': 'bucket'})

  return MockRequest(True)


def mock_get_iam_policy(bucket=None):
  """Mock buckets().getIamPolicy()."""
  response = {
      'kind': 'storage#policy',
      'resourceId': 'fake',
      'bindings': [],
      'etag': 'fake'
  }

  if bucket in ('lib1-logs.clusterfuzz-external.appspot.com',
                'lib3-logs.clusterfuzz-external.appspot.com'):
    response['bindings'].append({
        'role': 'roles/storage.objectViewer',
        'members': ['user:user@example.com',]
    })

  return MockRequest(return_value=response)


class CopyingMock(mock.MagicMock):
  """MagicMock that copies arguments."""

  def __call__(self, *args, **kwargs):
    args = copy.deepcopy(args)
    kwargs = copy.deepcopy(kwargs)
    return super().__call__(*args, **kwargs)


def mock_set_iam_policy(bucket=None, body=None):  # pylint: disable=unused-argument
  """Mock buckets().setIamPolicy()."""
  bindings = body['bindings']
  if bindings and 'user:primary@example.com' in bindings[0]['members']:
    return MockRequest(raise_exception=True)

  return MockRequest(return_value=copy.deepcopy(body))


def _mock_get_or_create_service_account(project):
  return {
      'email': project + '@serviceaccount.com',
  }


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class OssFuzzProjectSetupTest(unittest.TestCase):
  """Test project_setup for OSS-Fuzz."""

  def setUp(self):
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/setup', view_func=project_setup.Handler.as_view('/setup'))
    self.app = webtest.TestApp(flaskapp)

    helpers.patch_environ(self)

    data_types.Job(
        name='libfuzzer_asan_old_job',
        environment_string=('MANAGED = True\n'
                            'PROJECT_NAME = old\n')).put()
    data_types.Job(
        name='libfuzzer_msan_old_job',
        environment_string=('MANAGED = True\n'
                            'PROJECT_NAME = old\n')).put()
    data_types.Job(
        name='afl_asan_old_job',
        environment_string=('MANAGED = True\n'
                            'PROJECT_NAME = old\n')).put()
    data_types.Job(
        name='afl_msan_old_job',
        environment_string=('MANAGED = True\n'
                            'PROJECT_NAME = old\n')).put()
    data_types.Job(name='unmanaged_job', environment_string='').put()

    # Will be removed.
    data_types.ExternalUserPermission(
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL,
        entity_name='libfuzzer_asan_lib1',
        email='willberemoved@example.com').put()

    # Existing CC. Makes sure no duplicates are created.
    data_types.ExternalUserPermission(
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL,
        entity_name='libfuzzer_asan_lib1',
        email='primary@example.com').put()

    # Existing project settings. Should not get modified.
    data_types.OssFuzzProject(id='lib1', name='lib1', cpu_weight=1.5).put()

    # Should get deleted.
    data_types.OssFuzzProject(id='old_lib', name='old_lib').put()

    self.libfuzzer = data_types.Fuzzer(name='libFuzzer', jobs=[])
    self.libfuzzer.data_bundle_name = 'global'
    self.libfuzzer.jobs = ['libfuzzer_asan_old_job', 'libfuzzer_msan_old_job']
    self.libfuzzer.put()

    self.afl = data_types.Fuzzer(name='afl', jobs=[])
    self.afl.data_bundle_name = 'global'
    self.afl.jobs = ['afl_asan_old_job', 'afl_msan_old_job']
    self.afl.put()

    self.honggfuzz = data_types.Fuzzer(name='honggfuzz', jobs=[])
    self.honggfuzz.data_bundle_name = 'global'
    self.honggfuzz.put()

    self.gft = data_types.Fuzzer(name='googlefuzztest', jobs=[])
    self.gft.put()

    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        ('get_application_id_2',
         'clusterfuzz._internal.base.utils.get_application_id'),
        'clusterfuzz._internal.google_cloud_utils.storage.build',
        'time.sleep',
        'handlers.base_handler.Handler.is_cron',
        'handlers.cron.project_setup.get_oss_fuzz_projects',
        'handlers.cron.service_accounts.get_or_create_service_account',
        'handlers.cron.service_accounts.set_service_account_roles',
    ])

    self.mock.get_or_create_service_account.side_effect = (
        _mock_get_or_create_service_account)

    self.mock.ProjectConfig.return_value = mock_config.MockConfig({
        'segregate_projects':
            True,
        'project_setup': [{
            'source': 'oss-fuzz',
            'build_type': 'RELEASE_BUILD_BUCKET_PATH',
            'add_info_labels': True,
            'add_revision_mappings': True,
            'build_buckets': {
                'afl': 'clusterfuzz-builds-afl',
                'dataflow': 'clusterfuzz-builds-dataflow',
                'honggfuzz': 'clusterfuzz-builds-honggfuzz',
                'libfuzzer': 'clusterfuzz-builds',
                'libfuzzer_i386': 'clusterfuzz-builds-i386',
                'no_engine': 'clusterfuzz-builds-no-engine',
            }
        }]
    })

  def test_execute(self):
    """Tests executing of cron job."""
    mock_storage = mock.MagicMock()
    mock_storage.buckets().insert().execute.return_value = 'timeCreated'
    self.mock.get_application_id_2.return_value = 'clusterfuzz-external'
    self.mock.build.return_value = mock_storage

    pubsub_client = pubsub.PubSubClient()
    app_id = utils.get_application_id()
    unmanaged_topic_name = pubsub.topic_name(app_id, 'jobs-linux')
    old_topic_name = pubsub.topic_name(app_id, 'jobs-shouldbedeleted')
    old_subscription_name = pubsub.subscription_name(app_id,
                                                     'jobs-shouldbedeleted')
    other_topic_name = pubsub.topic_name(app_id, 'other')

    pubsub_client.create_topic(unmanaged_topic_name)
    pubsub_client.create_topic(old_topic_name)
    pubsub_client.create_topic(other_topic_name)
    pubsub_client.create_subscription(old_subscription_name, old_topic_name)

    self.mock.get_oss_fuzz_projects.return_value = [
        ('lib1', {
            'homepage': 'http://example.com',
            'primary_contact': 'primary@example.com',
            'auto_ccs': [
                'User@example.com',
                'user2@googlemail.com',
            ],
        }),
        ('lib2', {
            'homepage': 'http://example2.com',
            'disabled': True,
            'fuzzing_engines': ['libfuzzer',],
        }),
        ('lib3', {
            'homepage':
                'http://example3.com',
            'sanitizers': [
                'address',
                {
                    'memory': {
                        'experimental': True,
                    },
                },
                'undefined',
            ],
            'auto_ccs':
                'User@example.com',
            'disabled':
                False,
            'fuzzing_engines': ['libfuzzer',],
            'view_restrictions':
                'none',
            'architectures': ['i386', 'x86_64'],
        }),
        ('lib4', {
            'homepage': 'http://example4.com',
            'language': 'go',
            'sanitizers': ['address'],
            'auto_ccs': 'User@example.com',
            'fuzzing_engines': ['none'],
            'blackbox': True,
        }),
        ('lib5', {
            'homepage': 'http://example5.com',
            'sanitizers': ['address'],
            'fuzzing_engines': ['libfuzzer',],
            'experimental': True,
            'selective_unpack': True,
            'main_repo': 'https://github.com/google/main-repo',
        }),
        ('lib6', {
            'homepage': 'http://example6.com',
            'sanitizers': ['address', 'dataflow', 'memory', 'undefined'],
            'fuzzing_engines': ['libfuzzer', 'afl', 'dataflow'],
            'auto_ccs': 'User@example.com',
            'vendor_ccs': ['vendor1@example.com', 'vendor2@example.com'],
        }),
    ]

    mock_storage.buckets().get.side_effect = mock_bucket_get
    mock_storage.buckets().getIamPolicy.side_effect = mock_get_iam_policy
    mock_storage.buckets().setIamPolicy = CopyingMock()
    mock_storage.buckets().setIamPolicy.side_effect = mock_set_iam_policy

    self.app.get('/setup')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib1').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib1')
    self.assertEqual(job.platform, 'LIB1_LINUX')
    six.assertCountEqual(self, job.templates,
                         ['engine_asan', 'libfuzzer', 'prune'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib1/lib1-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib1\n'
        'SUMMARY_PREFIX = lib1\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib1/lib1-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib1-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib1-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib1-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib1-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib1,Engine-libfuzzer\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib2').get()
    self.assertIsNone(job)

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib3')
    self.assertEqual(job.platform, 'LIB3_LINUX')
    six.assertCountEqual(self, job.templates,
                         ['engine_asan', 'libfuzzer', 'prune'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_i386_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib3')
    self.assertEqual(job.platform, 'LIB3_LINUX')
    six.assertCountEqual(self, job.templates, ['engine_asan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds-i386/lib3/lib3-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds-i386/lib3/lib3-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_msan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib3')
    self.assertEqual(job.platform, 'LIB3_LINUX')
    six.assertCountEqual(self, job.templates, ['engine_msan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-memory-([0-9]+).zip\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-memory-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'EXPERIMENTAL = True\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_ubsan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib3')
    self.assertEqual(job.platform, 'LIB3_LINUX')
    six.assertCountEqual(self, job.templates, ['engine_ubsan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-undefined-([0-9]+).zip\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-undefined-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(data_types.Job.name == 'afl_asan_lib1').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.project, 'lib1')
    self.assertEqual(job.platform, 'LIB1_LINUX')
    six.assertCountEqual(self, job.templates, ['engine_asan', 'afl'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds-afl/lib1/lib1-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib1\n'
        'SUMMARY_PREFIX = lib1\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds-afl/lib1/lib1-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib1-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib1-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib1-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib1-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib1,Engine-afl\n'
        'MINIMIZE_JOB_OVERRIDE = libfuzzer_asan_lib1\n')

    # Engine-less job. Manually managed.
    job = data_types.Job.query(data_types.Job.name == 'asan_lib4').get()
    self.assertIsNone(job)

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib5').get()
    self.assertEqual(job.project, 'lib5')
    self.assertEqual(job.platform, 'LIB5_LINUX')
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib5/lib5-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib5\n'
        'SUMMARY_PREFIX = lib5\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib5/lib5-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib5-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib5-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib5-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib5-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib5,Engine-libfuzzer\n'
        'EXPERIMENTAL = True\n'
        'UNPACK_ALL_FUZZ_TARGETS_AND_FILES = False\n'
        'MAIN_REPO = https://github.com/google/main-repo\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib6').get()
    self.assertEqual(job.project, 'lib6')
    self.assertEqual(job.platform, 'LIB6_LINUX')
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib6/lib6-address-([0-9]+).zip\n'
        'PROJECT_NAME = lib6\n'
        'SUMMARY_PREFIX = lib6\n'
        'MANAGED = True\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib6/lib6-address-%s.srcmap.json\n'
        'FUZZ_LOGS_BUCKET = lib6-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib6-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib6-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib6-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib6,Engine-libfuzzer\n'
        'DATAFLOW_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds-dataflow/lib6/lib6-dataflow-([0-9]+).zip\n')

    self.maxDiff = None  # pylint: disable=invalid-name

    libfuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'libFuzzer').get()
    six.assertCountEqual(self, libfuzzer.jobs, [
        'libfuzzer_asan_lib1',
        'libfuzzer_asan_lib3',
        'libfuzzer_asan_i386_lib3',
        'libfuzzer_asan_lib5',
        'libfuzzer_msan_lib3',
        'libfuzzer_ubsan_lib1',
        'libfuzzer_ubsan_lib3',
        'libfuzzer_asan_lib6',
        'libfuzzer_msan_lib6',
        'libfuzzer_ubsan_lib6',
    ])

    afl = data_types.Fuzzer.query(data_types.Fuzzer.name == 'afl').get()
    six.assertCountEqual(self, afl.jobs, [
        'afl_asan_lib1',
        'afl_asan_lib6',
    ])

    # Test that old unused jobs are deleted.
    self.assertIsNone(
        data_types.Job.query(
            data_types.Job.name == 'libfuzzer_asan_old_job').get())
    self.assertIsNone(
        data_types.Job.query(
            data_types.Job.name == 'libfuzzer_msan_old_job').get())

    # Unmanaged job should still exist.
    self.assertIsNotNone(
        data_types.Job.query(data_types.Job.name == 'unmanaged_job').get())

    # Test that project settings are created.
    lib1_settings = ndb.Key(data_types.OssFuzzProject, 'lib1').get()
    self.assertIsNotNone(lib1_settings)
    self.assertDictEqual({
        'cpu_weight':
            1.5,
        'name':
            'lib1',
        'disk_size_gb':
            None,
        'service_account':
            'lib1@serviceaccount.com',
        'high_end':
            False,
        'ccs': [
            'primary@example.com', 'user@example.com', 'user2@googlemail.com'
        ],
    }, lib1_settings.to_dict())

    lib2_settings = ndb.Key(data_types.OssFuzzProject, 'lib2').get()
    self.assertIsNone(lib2_settings)

    lib3_settings = ndb.Key(data_types.OssFuzzProject, 'lib3').get()
    self.assertIsNotNone(lib3_settings)
    self.assertDictEqual({
        'cpu_weight': 1.0,
        'name': 'lib3',
        'disk_size_gb': None,
        'service_account': 'lib3@serviceaccount.com',
        'high_end': False,
        'ccs': ['user@example.com'],
    }, lib3_settings.to_dict())

    lib4_settings = ndb.Key(data_types.OssFuzzProject, 'lib4').get()
    self.assertIsNotNone(lib4_settings)
    self.assertDictEqual({
        'cpu_weight': 0.2,
        'name': 'lib4',
        'disk_size_gb': None,
        'service_account': 'lib4@serviceaccount.com',
        'high_end': True,
        'ccs': ['user@example.com'],
    }, lib4_settings.to_dict())

    old_lib_settings = ndb.Key(data_types.OssFuzzProject, 'old_lib').get()
    self.assertIsNone(old_lib_settings)

    mock_storage.buckets().get.assert_has_calls([
        mock.call(bucket='lib1-backup.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib1-corpus.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib1-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib1-logs.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib2-backup.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib2-corpus.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib2-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib2-logs.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib3-backup.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib3-corpus.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib3-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(bucket='lib3-logs.clusterfuzz-external.appspot.com'),
    ])

    mock_storage.buckets().insert.assert_has_calls([
        mock.call(
            body={
                'name': 'lib1-backup.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 100
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={'name': 'lib1-corpus.clusterfuzz-external.appspot.com'},
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib1-quarantine.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 90
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib2-backup.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 100
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={'name': 'lib2-corpus.clusterfuzz-external.appspot.com'},
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib2-quarantine.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 90
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib2-logs.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 14
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib3-backup.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 100
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={'name': 'lib3-corpus.clusterfuzz-external.appspot.com'},
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib3-quarantine.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 90
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
        mock.call(
            body={
                'name': 'lib3-logs.clusterfuzz-external.appspot.com',
                'lifecycle': {
                    'rule': [{
                        'action': {
                            'type': 'Delete'
                        },
                        'condition': {
                            'age': 14
                        }
                    }]
                }
            },
            project='clusterfuzz-external'),
        mock.call().execute(),
    ])

    mock_storage.buckets().setIamPolicy.assert_has_calls([
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:primary@example.com']
                }]
            },
            bucket='lib1-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user2@gmail.com']
                }]
            },
            bucket='lib1-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }]
            },
            bucket='lib1-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='lib1-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:primary@example.com']
                }]
            },
            bucket='lib1-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user2@gmail.com']
                }]
            },
            bucket='lib1-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }]
            },
            bucket='lib1-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='lib1-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role':
                        'roles/storage.objectViewer',
                    'members': [
                        'user:primary@example.com', 'user:user@example.com'
                    ]
                }]
            },
            bucket='lib1-logs.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }]
            },
            bucket='lib1-logs.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='lib1-logs.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:primary@example.com']
                }]
            },
            bucket='lib1-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user2@gmail.com']
                }]
            },
            bucket='lib1-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }]
            },
            bucket='lib1-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:user2@gmail.com', 'user:user@example.com'
                    ]
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='lib1-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='clusterfuzz-external-deployment'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='test-shared-corpus-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket='test-mutator-plugins-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib1@serviceaccount.com']
                }]
            },
            bucket=u'global-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='lib2-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='lib2-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='lib2-logs.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='lib2-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='clusterfuzz-external-deployment'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='test-shared-corpus-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket='test-mutator-plugins-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib2@serviceaccount.com']
                }]
            },
            bucket=u'global-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }]
            },
            bucket='lib3-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='lib3-backup.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }]
            },
            bucket='lib3-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='lib3-corpus.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='lib3-logs.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }]
            },
            bucket='lib3-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:user@example.com']
                }, {
                    'role': 'roles/storage.objectAdmin',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='lib3-quarantine.clusterfuzz-external.appspot.com'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='clusterfuzz-external-deployment'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='test-shared-corpus-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket='test-mutator-plugins-bucket'),
        mock.call(
            body={
                'resourceId':
                    'fake',
                'kind':
                    'storage#policy',
                'etag':
                    'fake',
                'bindings': [{
                    'role': 'roles/storage.objectViewer',
                    'members': ['serviceAccount:lib3@serviceaccount.com']
                }]
            },
            bucket=u'global-corpus.clusterfuzz-external.appspot.com')
    ])

    mappings = data_types.FuzzerJob.query()
    tags_fuzzers_and_jobs = [(m.platform, m.fuzzer, m.job) for m in mappings]
    six.assertCountEqual(self, tags_fuzzers_and_jobs, [
        ('LIB1_LINUX', 'afl', 'afl_asan_lib1'),
        ('LIB1_LINUX', 'libFuzzer', 'libfuzzer_asan_lib1'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_asan_lib3'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_asan_i386_lib3'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_msan_lib3'),
        ('LIB1_LINUX', 'libFuzzer', 'libfuzzer_ubsan_lib1'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_ubsan_lib3'),
        ('LIB5_LINUX', 'libFuzzer', 'libfuzzer_asan_lib5'),
        ('LIB6_LINUX', 'libFuzzer', 'libfuzzer_asan_lib6'),
        ('LIB6_LINUX', 'libFuzzer', 'libfuzzer_msan_lib6'),
        ('LIB6_LINUX', 'libFuzzer', 'libfuzzer_ubsan_lib6'),
        ('LIB6_LINUX', 'afl', 'afl_asan_lib6'),
        ('LIB1_LINUX', 'honggfuzz', 'honggfuzz_asan_lib1'),
    ])

    all_permissions = [
        entity.to_dict()
        for entity in data_types.ExternalUserPermission.query()
    ]

    six.assertCountEqual(self, all_permissions, [{
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_asan_lib1',
        'email': u'primary@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_ubsan_lib1',
        'email': u'primary@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_ubsan_lib1',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_ubsan_lib1',
        'email': u'user2@googlemail.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_asan_lib1',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_asan_lib1',
        'email': u'user2@googlemail.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'afl_asan_lib1',
        'email': u'primary@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'afl_asan_lib1',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'afl_asan_lib1',
        'email': u'user2@googlemail.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_msan_lib3',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_ubsan_lib3',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'libfuzzer_asan_lib3',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'auto_cc': 1,
        'entity_name': u'asan_lib4',
        'email': u'user@example.com'
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'libfuzzer_asan_i386_lib3',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'libfuzzer_msan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'libfuzzer_ubsan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'libfuzzer_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'afl_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor1@example.com',
        'entity_name': u'libfuzzer_msan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor1@example.com',
        'entity_name': u'libfuzzer_ubsan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor1@example.com',
        'entity_name': u'libfuzzer_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor1@example.com',
        'entity_name': u'afl_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor2@example.com',
        'entity_name': u'libfuzzer_msan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor2@example.com',
        'entity_name': u'libfuzzer_ubsan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor2@example.com',
        'entity_name': u'libfuzzer_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'vendor2@example.com',
        'entity_name': u'afl_asan_lib6',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'primary@example.com',
        'entity_name': u'honggfuzz_asan_lib1',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user@example.com',
        'entity_name': u'honggfuzz_asan_lib1',
        'auto_cc': 1
    }, {
        'entity_kind': 1,
        'is_prefix': False,
        'email': u'user2@googlemail.com',
        'entity_name': u'honggfuzz_asan_lib1',
        'auto_cc': 1
    }])

    expected_topics = [
        'projects/clusterfuzz-external/topics/jobs-linux',
        'projects/clusterfuzz-external/topics/other',
        'projects/clusterfuzz-external/topics/jobs-lib1-linux',
        'projects/clusterfuzz-external/topics/jobs-lib3-linux',
        'projects/clusterfuzz-external/topics/jobs-lib4-linux',
        'projects/clusterfuzz-external/topics/jobs-lib5-linux',
        'projects/clusterfuzz-external/topics/jobs-lib6-linux',
    ]
    six.assertCountEqual(self, expected_topics,
                         list(pubsub_client.list_topics('projects/' + app_id)))

    for topic in expected_topics[2:]:
      lib = posixpath.basename(topic).split('-')[1]
      six.assertCountEqual(self, [
          'projects/clusterfuzz-external/subscriptions/'
          'jobs-{}-linux'.format(lib),
      ], pubsub_client.list_topic_subscriptions(topic))

    self.assertIsNotNone(pubsub_client.get_topic(unmanaged_topic_name))
    self.assertIsNotNone(pubsub_client.get_topic(other_topic_name))
    self.assertIsNone(pubsub_client.get_topic(old_topic_name))
    self.assertIsNone(pubsub_client.get_subscription(old_subscription_name))


URL_RESULTS = ast.literal_eval(_read_data_file('url_results.txt'))


def mock_get_url(url):
  """Mock get_url()."""
  if url not in URL_RESULTS:
    return None

  return URL_RESULTS[url]


class MockRequestsGet(object):
  """Mock requests.get."""

  def __init__(self, url, params=None, auth=None):  # pylint: disable=unused-argument
    if url in URL_RESULTS:
      self.text = URL_RESULTS[url]
      self.status_code = 200
    else:
      self.text = None
      self.status_code = 500


@test_utils.with_cloud_emulators('datastore')
class GetLibrariesTest(unittest.TestCase):
  """Test get_oss_fuzz_projects()."""

  def setUp(self):
    data_types.Config(github_credentials='client_id;client_secret').put()

    helpers.patch(self, ['requests.get'])
    self.mock.get.side_effect = MockRequestsGet

  def test_get_oss_fuzz_projects(self):
    """Tests get_oss_fuzz_projects()."""
    libraries = project_setup.get_oss_fuzz_projects()
    self.assertListEqual(
        sorted(libraries), [('boringssl', {
            'homepage': 'https://boringssl.googlesource.com/boringssl/'
        }), ('curl', {
            'homepage': 'https://curl.haxx.se/',
            'dockerfile': {
                'git': 'fake',
                'path': 'path/Dockerfile',
            }
        })])


def _mock_read_data(path):
  """Mock read_data."""
  if 'dbg' in path:
    return json.dumps({
        'projects': [{
            'build_path': 'gs://bucket-dbg/a-b/%ENGINE%/%SANITIZER%/'
                          '%TARGET%/([0-9]+).zip',
            'name': '//a/b',
            'fuzzing_engines': ['libfuzzer', 'honggfuzz'],
            'sanitizers': ['address']
        }]
    })

  return json.dumps({
      'projects': [
          {
              'build_path':
                  'gs://bucket/a-b/%ENGINE%/%SANITIZER%/%TARGET%/([0-9]+).zip',
              'name':
                  '//a/b',
              'fuzzing_engines': ['libfuzzer', 'honggfuzz'],
              'sanitizers': ['address', 'memory']
          },
          {
              'build_path':
                  'gs://bucket/c-d/%ENGINE%/%SANITIZER%/%TARGET%/([0-9]+).zip',
              'name':
                  '//c/d',
              'fuzzing_engines': ['libfuzzer', 'googlefuzztest'],
              'sanitizers': ['address']
          },
      ]
  })


@test_utils.with_cloud_emulators('datastore', 'pubsub')
class GenericProjectSetupTest(unittest.TestCase):
  """Test generic project setup."""

  def setUp(self):
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/setup', view_func=project_setup.Handler.as_view('/setup'))
    self.app = webtest.TestApp(flaskapp)

    helpers.patch_environ(self)

    data_types.Job(name='old_unmanaged').put()
    data_types.Job(
        name='old_managed',
        environment_string='MANAGED = True\nPROJECT_NAME = old').put()

    self.libfuzzer = data_types.Fuzzer(
        name='libFuzzer', jobs=['old_unmanaged', 'old_managed'])
    self.libfuzzer.put()

    self.afl = data_types.Fuzzer(name='afl', jobs=[])
    self.afl.put()

    self.honggfuzz = data_types.Fuzzer(name='honggfuzz', jobs=[])
    self.honggfuzz.put()

    self.gft = data_types.Fuzzer(name='googlefuzztest', jobs=[])
    self.gft.put()

    helpers.patch(self, [
        'clusterfuzz._internal.config.local_config.ProjectConfig',
        ('get_application_id_2',
         'clusterfuzz._internal.base.utils.get_application_id'),
        'clusterfuzz._internal.google_cloud_utils.storage.build',
        'clusterfuzz._internal.google_cloud_utils.storage.read_data',
        'time.sleep',
        'handlers.base_handler.Handler.is_cron',
    ])

    self.mock.read_data.side_effect = _mock_read_data

    self.mock.ProjectConfig.return_value = mock_config.MockConfig({
        'project_setup': [
            {
                'source': 'gs://bucket/projects.json',
                'build_type': 'FUZZ_TARGET_BUILD_BUCKET_PATH',
                'experimental_sanitizers': ['memory'],
                'build_buckets': {
                    'afl': 'clusterfuzz-builds-afl',
                    'dataflow': 'clusterfuzz-builds-dataflow',
                    'honggfuzz': 'clusterfuzz-builds-honggfuzz',
                    'googlefuzztest': 'clusterfuzz-builds-googlefuzztest',
                    'libfuzzer': 'clusterfuzz-builds',
                    'libfuzzer_i386': 'clusterfuzz-builds-i386',
                    'no_engine': 'clusterfuzz-builds-no-engine',
                },
                'additional_vars': {
                    'all': {
                        'STRING_VAR': 'VAL',
                        'BOOL_VAR': True,
                        'INT_VAR': 0,
                    },
                    'libfuzzer': {
                        'address': {
                            'ASAN_VAR': 'VAL',
                        },
                        'memory': {
                            'MSAN_VAR': 'VAL',
                        }
                    }
                }
            },
            {
                'source': 'gs://bucket-dbg/projects.json',
                'job_suffix': '_dbg',
                'external_config': {
                    'reproduction_topic':
                        'projects/proj/topics/reproduction',
                    'updates_subscription':
                        'projects/proj/subscriptions/updates',
                },
                'build_type': 'FUZZ_TARGET_BUILD_BUCKET_PATH',
                'build_buckets': {
                    'afl': 'clusterfuzz-builds-afl-dbg',
                    'dataflow': 'clusterfuzz-builds-dataflow-dbg',
                    'honggfuzz': 'clusterfuzz-builds-honggfuzz-dbg',
                    'googlefuzztest': 'clusterfuzz-builds-googlefuzztest-dbg',
                    'libfuzzer': 'clusterfuzz-builds-dbg',
                    'libfuzzer_i386': 'clusterfuzz-builds-i386-dbg',
                    'no_engine': 'clusterfuzz-builds-no-engine-dbg',
                },
                'additional_vars': {
                    'all': {
                        'STRING_VAR': 'VAL-dbg',
                        'BOOL_VAR': True,
                        'INT_VAR': 0,
                    },
                    'libfuzzer': {
                        'address': {
                            'ASAN_VAR': 'VAL-dbg',
                        },
                        'memory': {
                            'MSAN_VAR': 'VAL-dbg',
                        }
                    }
                }
            },
        ],
    })

    # Should be deleted.
    job = data_types.Job(
        name='libfuzzer_asan_c-d_dbg', environment_string='MANAGED = True')
    job.put()

  def test_execute(self):
    """Tests executing of cron job."""
    self.app.get('/setup')
    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_a-b').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket/a-b/libfuzzer/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //a/b\nSUMMARY_PREFIX = //a/b\nMANAGED = True\n'
        'ASAN_VAR = VAL\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'libfuzzer', 'prune'],
                         job.templates)
    self.assertEqual(None, job.external_reproduction_topic)
    self.assertEqual(None, job.external_updates_subscription)
    self.assertFalse(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_msan_a-b').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket/a-b/libfuzzer/memory/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //a/b\nSUMMARY_PREFIX = //a/b\nMANAGED = True\n'
        'EXPERIMENTAL = True\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'MSAN_VAR = VAL\n'
        'STRING_VAR = VAL\n', job.environment_string)
    six.assertCountEqual(self, ['engine_msan', 'libfuzzer'], job.templates)
    self.assertEqual(None, job.external_reproduction_topic)
    self.assertEqual(None, job.external_updates_subscription)
    self.assertFalse(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_c-d').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket/c-d/libfuzzer/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //c/d\nSUMMARY_PREFIX = //c/d\nMANAGED = True\n'
        'ASAN_VAR = VAL\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'libfuzzer', 'prune'],
                         job.templates)
    self.assertEqual(None, job.external_reproduction_topic)
    self.assertEqual(None, job.external_updates_subscription)
    self.assertFalse(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_c-d_dbg').get()
    self.assertIsNone(job)

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_a-b_dbg').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket-dbg/a-b/libfuzzer/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //a/b\nSUMMARY_PREFIX = //a/b\nMANAGED = True\n'
        'ASAN_VAR = VAL-dbg\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL-dbg\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'libfuzzer', 'prune'],
                         job.templates)
    self.assertEqual('projects/proj/topics/reproduction',
                     job.external_reproduction_topic)
    self.assertEqual('projects/proj/subscriptions/updates',
                     job.external_updates_subscription)
    self.assertTrue(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'honggfuzz_asan_a-b').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket/a-b/honggfuzz/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //a/b\nSUMMARY_PREFIX = //a/b\nMANAGED = True\n'
        'MINIMIZE_JOB_OVERRIDE = libfuzzer_asan_a-b\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'honggfuzz'], job.templates)
    self.assertEqual(None, job.external_reproduction_topic)
    self.assertEqual(None, job.external_updates_subscription)
    self.assertFalse(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'honggfuzz_asan_a-b_dbg').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket-dbg/a-b/honggfuzz/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //a/b\nSUMMARY_PREFIX = //a/b\nMANAGED = True\n'
        'MINIMIZE_JOB_OVERRIDE = libfuzzer_asan_a-b_dbg\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL-dbg\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'honggfuzz'], job.templates)
    self.assertEqual('projects/proj/topics/reproduction',
                     job.external_reproduction_topic)
    self.assertEqual('projects/proj/subscriptions/updates',
                     job.external_updates_subscription)
    self.assertTrue(job.is_external())

    job = data_types.Job.query(
        data_types.Job.name == 'googlefuzztest_asan_c-d').get()
    self.assertEqual(
        'FUZZ_TARGET_BUILD_BUCKET_PATH = '
        'gs://bucket/c-d/googlefuzztest/address/%TARGET%/([0-9]+).zip\n'
        'PROJECT_NAME = //c/d\nSUMMARY_PREFIX = //c/d\nMANAGED = True\n'
        'BOOL_VAR = True\n'
        'INT_VAR = 0\n'
        'STRING_VAR = VAL\n', job.environment_string)
    six.assertCountEqual(self, ['engine_asan', 'googlefuzztest'], job.templates)
    self.assertEqual(None, job.external_reproduction_topic)
    self.assertEqual(None, job.external_updates_subscription)
    self.assertFalse(job.is_external())

    libfuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'libFuzzer').get()
    six.assertCountEqual(self, [
        'libfuzzer_asan_a-b',
        'libfuzzer_asan_c-d',
        'libfuzzer_msan_a-b',
        'old_unmanaged',
    ], libfuzzer.jobs)

    afl = data_types.Fuzzer.query(data_types.Fuzzer.name == 'afl').get()
    six.assertCountEqual(self, [], afl.jobs)

    honggfuzz = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'honggfuzz').get()
    six.assertCountEqual(self, [
        'honggfuzz_asan_a-b',
    ], honggfuzz.jobs)

    gft = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'googlefuzztest').get()
    six.assertCountEqual(self, ['googlefuzztest_asan_c-d'], gft.jobs)
