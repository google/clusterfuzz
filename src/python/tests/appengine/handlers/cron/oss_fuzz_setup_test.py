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
"""Tests for oss_fuzz_setup."""
import ast
import copy
import googleapiclient
import mock
import os
import unittest
import webapp2
import webtest

from google.appengine.api import app_identity

from config import db_config
from datastore import data_types
from datastore import ndb
from google_cloud_utils import pubsub
from handlers.cron import oss_fuzz_setup
from tests.test_libs import helpers
from tests.test_libs import test_utils

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'oss_fuzz_setup_data')

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
      raise googleapiclient.errors.HttpError(mock.Mock(status=404), '')

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

  if (bucket == 'lib1-logs.clusterfuzz-external.appspot.com' or
      bucket == 'lib3-logs.clusterfuzz-external.appspot.com'):
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
    return super(CopyingMock, self).__call__(*args, **kwargs)


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
class OssFuzzSetupTest(unittest.TestCase):
  """Test LoadBigQueryStatsTest."""

  def setUp(self):
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/setup', oss_fuzz_setup.Handler)]))

    helpers.patch_environ(self)
    data_types.Config(
        revision_vars_url=('libfuzzer_asan_lib2;url\n'
                           'blah;url2\n')).put()

    data_types.Job(
        name='libfuzzer_asan_old_job',
        environment_string=('MANAGED = True\n'
                            'PROJECT_NAME = old\n')).put()
    data_types.Job(
        name='libfuzzer_msan_old_job',
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

    helpers.patch(self, [
        'base.utils.is_oss_fuzz',
        ('get_application_id_1',
         'google.appengine.api.app_identity.get_application_id'),
        ('get_application_id_2', 'base.utils.get_application_id'),
        'google_cloud_utils.storage.build',
        'time.sleep',
        'handlers.base_handler.Handler.is_cron',
        'handlers.cron.oss_fuzz_setup.get_projects',
        'handlers.cron.service_accounts.get_or_create_service_account',
        'handlers.cron.service_accounts.set_service_account_roles',
    ])

    self.mock.get_or_create_service_account.side_effect = (
        _mock_get_or_create_service_account)

    self.mock.is_oss_fuzz.return_value = True

  def test_execute(self):
    """Tests executing of cron job."""
    mock_storage = mock.MagicMock()
    mock_storage.buckets().insert().execute.return_value = 'timeCreated'
    self.mock.get_application_id_1.return_value = 'clusterfuzz-external'
    self.mock.get_application_id_2.return_value = 'clusterfuzz-external'
    self.mock.build.return_value = mock_storage

    pubsub_client = pubsub.PubSubClient()
    unmanaged_topic_name = pubsub.topic_name(app_identity.get_application_id(),
                                             'jobs-linux')
    old_topic_name = pubsub.topic_name(app_identity.get_application_id(),
                                       'jobs-shouldbedeleted')
    old_subscription_name = pubsub.subscription_name(
        app_identity.get_application_id(), 'jobs-shouldbedeleted')
    other_topic_name = pubsub.topic_name(app_identity.get_application_id(),
                                         'other')

    pubsub_client.create_topic(unmanaged_topic_name)
    pubsub_client.create_topic(old_topic_name)
    pubsub_client.create_topic(other_topic_name)
    pubsub_client.create_subscription(old_subscription_name, old_topic_name)

    self.mock.get_projects.return_value = [
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
        }),
        ('lib4', {
            'homepage': 'http://example4.com',
            'sanitizers': ['address'],
            'auto_ccs': 'User@example.com',
            'fuzzing_engines': ['none',],
        }),
        ('lib5', {
            'homepage': 'http://example5.com',
            'sanitizers': ['address'],
            'fuzzing_engines': ['libfuzzer',],
            'experimental': True,
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
    self.assertEqual(job.platform, 'LIB1_LINUX')
    self.assertItemsEqual(job.templates, ['asan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib1/lib1-address-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib1-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib1-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib1-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib1-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib1,Engine-libfuzzer\n'
        'PROJECT_NAME = lib1\n'
        'SUMMARY_PREFIX = lib1\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib1/lib1-address-%s.srcmap.json\n'
        'MANAGED = True\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib2').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.platform, 'LIB2_LINUX')
    self.assertItemsEqual(job.templates, ['asan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib2/lib2-address-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib2-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib2-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib2-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib2-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib2,Engine-libfuzzer\n'
        'PROJECT_NAME = lib2\n'
        'SUMMARY_PREFIX = lib2\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib2/lib2-address-%s.srcmap.json\n'
        'MANAGED = True\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.platform, 'LIB3_LINUX')
    self.assertItemsEqual(job.templates, ['asan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-address-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-address-%s.srcmap.json\n'
        'MANAGED = True\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_msan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.platform, 'LIB3_LINUX')
    self.assertItemsEqual(job.templates, ['msan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-memory-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-memory-%s.srcmap.json\n'
        'MANAGED = True\n'
        'EXPERIMENTAL = True\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_ubsan_lib3').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.platform, 'LIB3_LINUX')
    self.assertItemsEqual(job.templates, ['ubsan', 'libfuzzer'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib3/lib3-undefined-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib3-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib3-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib3-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib3-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib3,Engine-libfuzzer\n'
        'PROJECT_NAME = lib3\n'
        'SUMMARY_PREFIX = lib3\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-undefined-%s.srcmap.json\n'
        'MANAGED = True\n'
        'ISSUE_VIEW_RESTRICTIONS = none\n')

    job = data_types.Job.query(data_types.Job.name == 'afl_asan_lib1').get()
    self.assertIsNotNone(job)
    self.assertEqual(job.platform, 'LIB1_LINUX')
    self.assertItemsEqual(job.templates, ['asan', 'afl'])
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds-afl/lib1/lib1-address-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib1-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib1-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib1-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib1-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib1,Engine-afl\n'
        'PROJECT_NAME = lib1\n'
        'SUMMARY_PREFIX = lib1\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds-afl/lib1/lib1-address-%s.srcmap.json\n'
        'MANAGED = True\n'
        'MINIMIZE_JOB_OVERRIDE = libfuzzer_asan_lib1\n')

    # Engine-less job. Manually managed.
    job = data_types.Job.query(data_types.Job.name == 'asan_lib4').get()
    self.assertIsNone(job)

    job = data_types.Job.query(
        data_types.Job.name == 'libfuzzer_asan_lib5').get()
    self.assertEqual(job.platform, 'LIB5_LINUX')
    self.assertEqual(
        job.environment_string, 'RELEASE_BUILD_BUCKET_PATH = '
        'gs://clusterfuzz-builds/lib5/lib5-address-([0-9]+).zip\n'
        'FUZZ_LOGS_BUCKET = lib5-logs.clusterfuzz-external.appspot.com\n'
        'CORPUS_BUCKET = lib5-corpus.clusterfuzz-external.appspot.com\n'
        'QUARANTINE_BUCKET = lib5-quarantine.clusterfuzz-external.appspot.com\n'
        'BACKUP_BUCKET = lib5-backup.clusterfuzz-external.appspot.com\n'
        'AUTOMATIC_LABELS = Proj-lib5,Engine-libfuzzer\n'
        'PROJECT_NAME = lib5\n'
        'SUMMARY_PREFIX = lib5\n'
        'REVISION_VARS_URL = https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib5/lib5-address-%s.srcmap.json\n'
        'MANAGED = True\n'
        'EXPERIMENTAL = True\n')

    config = db_config.get()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.assertItemsEqual(config.revision_vars_url.splitlines(), [
        u'libfuzzer_asan_lib2;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib2/lib2-address-%s.srcmap.json',
        u'libfuzzer_asan_lib3;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-address-%s.srcmap.json',
        u'libfuzzer_asan_lib1;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib1/lib1-address-%s.srcmap.json',
        u'libfuzzer_ubsan_lib1;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib1/lib1-undefined-%s.srcmap.json',
        u'libfuzzer_ubsan_lib2;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib2/lib2-undefined-%s.srcmap.json',
        u'afl_asan_lib1;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds-afl/lib1/lib1-address-%s.srcmap.json',
        u'blah;url2',
        u'libfuzzer_ubsan_lib3;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-undefined-%s.srcmap.json',
        u'libfuzzer_msan_lib3;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib3/lib3-memory-%s.srcmap.json',
        u'asan_lib4;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds-no-engine/lib4/lib4-address-%s.srcmap.json',
        u'libfuzzer_asan_lib5;https://commondatastorage.googleapis.com/'
        'clusterfuzz-builds/lib5/lib5-address-%s.srcmap.json',
    ])

    libfuzzer = data_types.Fuzzer.query(
        data_types.Fuzzer.name == 'libFuzzer').get()
    self.assertItemsEqual(libfuzzer.jobs, [
        'libfuzzer_asan_lib1',
        'libfuzzer_asan_lib3',
        'libfuzzer_asan_lib5',
        'libfuzzer_msan_lib3',
        'libfuzzer_ubsan_lib1',
        'libfuzzer_ubsan_lib3',
    ])

    afl = data_types.Fuzzer.query(data_types.Fuzzer.name == 'afl').get()
    self.assertItemsEqual(afl.jobs, [
        'afl_asan_lib1',
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
        'cpu_weight': 1.0,
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
            bucket='artifacts.clusterfuzz-images.appspot.com'),
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
            bucket='artifacts.clusterfuzz-images.appspot.com'),
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
            bucket='artifacts.clusterfuzz-images.appspot.com'),
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
            bucket=u'global-corpus.clusterfuzz-external.appspot.com')
    ])

    mappings = data_types.FuzzerJob.query()
    tags_fuzzers_and_jobs = [(m.platform, m.fuzzer, m.job) for m in mappings]
    self.assertItemsEqual(tags_fuzzers_and_jobs, [
        ('LIB1_LINUX', 'afl', 'afl_asan_lib1'),
        ('LIB1_LINUX', 'libFuzzer', 'libfuzzer_asan_lib1'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_asan_lib3'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_msan_lib3'),
        ('LIB1_LINUX', 'libFuzzer', 'libfuzzer_ubsan_lib1'),
        ('LIB3_LINUX', 'libFuzzer', 'libfuzzer_ubsan_lib3'),
        ('LIB5_LINUX', 'libFuzzer', 'libfuzzer_asan_lib5'),
    ])

    all_permissions = [
        entity.to_dict()
        for entity in data_types.ExternalUserPermission.query()
    ]

    self.assertItemsEqual(all_permissions, [{
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
    }])

    expected_topics = [
        'projects/clusterfuzz-external/topics/jobs-linux',
        'projects/clusterfuzz-external/topics/other',
        'projects/clusterfuzz-external/topics/jobs-lib1-linux',
        'projects/clusterfuzz-external/topics/jobs-lib2-linux',
        'projects/clusterfuzz-external/topics/jobs-lib3-linux',
        'projects/clusterfuzz-external/topics/jobs-lib4-linux',
        'projects/clusterfuzz-external/topics/jobs-lib5-linux',
    ]
    self.assertItemsEqual(
        expected_topics,
        list(
            pubsub_client.list_topics('projects/' +
                                      app_identity.get_application_id())))

    for i, topic in enumerate(expected_topics[2:]):
      self.assertItemsEqual([
          'projects/clusterfuzz-external/subscriptions/'
          'jobs-lib{}-linux'.format(i + 1),
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


class MockUrlopen(object):
  """Mock urlopen."""

  def __init__(self, url):
    self.contents = None
    if url in URL_RESULTS:
      self.contents = URL_RESULTS[url]

  def read(self):
    return self.contents


@test_utils.with_cloud_emulators('datastore')
class GetLibrariesTest(unittest.TestCase):
  """Test get_projects()."""

  def setUp(self):
    data_types.Config(github_credentials='client_id;client_secret').put()

  @mock.patch('urllib2.urlopen')
  def test_get_projects(self, mock_urlopen):
    """Tests get_projects()."""
    mock_urlopen.side_effect = MockUrlopen
    libraries = oss_fuzz_setup.get_projects()
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
