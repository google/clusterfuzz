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
"""Tests for corpus_pruning_task."""
# pylint: disable=unused-argument
# pylint: disable=protected-access

import datetime
import mock
import os
import shutil
import tempfile
import unittest

from bot.tasks import corpus_pruning_task
from datastore import data_handler
from datastore import data_types
from fuzzing import corpus_manager
from google_cloud_utils import gsutil
from system import environment
from tests.test_libs import helpers
from tests.test_libs import test_utils
from tests.test_libs import untrusted_runner_helpers

TEST_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'corpus_pruning_task_data')


# TODO(unassigned): Support macOS.
@test_utils.supported_platforms('LINUX')
@test_utils.with_cloud_emulators('datastore')
class CorpusPruningTest(unittest.TestCase):
  """Corpus pruning tests."""

  def setUp(self):
    helpers.patch(self, [
        'bot.fuzzers.engine_common.unpack_seed_corpus_if_needed',
        'bot.tasks.task_creation.create_tasks',
        'bot.tasks.setup.update_fuzzer_and_data_bundles',
        'build_management.build_manager.setup_build',
        'fuzzing.corpus_manager.backup_corpus',
        'fuzzing.corpus_manager.GcsCorpus.rsync_to_disk',
        'fuzzing.corpus_manager.FuzzTargetCorpus.rsync_from_disk',
        'datastore.ndb.transaction',
        'google_cloud_utils.blobs.write_blob',
        'google_cloud_utils.storage.write_data',
    ])

    helpers.patch_environ(self)
    self.mock.setup_build.side_effect = self._mock_setup_build
    self.mock.rsync_to_disk.side_effect = self._mock_rsync_to_disk
    self.mock.rsync_from_disk.side_effect = self._mock_rsync_from_disk
    self.mock.update_fuzzer_and_data_bundles.return_value = True
    self.mock.write_blob.return_value = 'key'
    self.mock.backup_corpus.return_value = 'backup_link'

    def mocked_unpack_seed_corpus_if_needed(*args, **kwargs):
      """Mock's assert called methods are not powerful enough to ensure that
      unpack_seed_corpus_if_needed was called once with force_unpack=True.
      Instead, just assert that it was called once and during the call assert
      that it was called correctly.
      """
      self.assertTrue(kwargs.get('force_unpack', False))

    self.mock.unpack_seed_corpus_if_needed.side_effect = (
        mocked_unpack_seed_corpus_if_needed)

    data_types.FuzzTarget(
        engine='libFuzzer', binary='test_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer',
        engine='libFuzzer',
        job='libfuzzer_asan_job').put()

    self.fuzz_inputs_disk = tempfile.mkdtemp()
    self.bot_tmpdir = tempfile.mkdtemp()
    self.corpus_bucket = tempfile.mkdtemp()
    self.corpus_dir = os.path.join(self.corpus_bucket, 'corpus')
    self.quarantine_dir = os.path.join(self.corpus_bucket, 'quarantine')
    self.shared_corpus_dir = os.path.join(self.corpus_bucket, 'shared')

    shutil.copytree(os.path.join(TEST_DIR, 'corpus'), self.corpus_dir)
    shutil.copytree(os.path.join(TEST_DIR, 'quarantine'), self.quarantine_dir)
    shutil.copytree(os.path.join(TEST_DIR, 'shared'), self.shared_corpus_dir)

    os.environ['BOT_TMPDIR'] = self.bot_tmpdir
    os.environ['FUZZ_INPUTS'] = self.fuzz_inputs_disk
    os.environ['FUZZ_INPUTS_DISK'] = self.fuzz_inputs_disk
    os.environ['CORPUS_BUCKET'] = 'bucket'
    os.environ['QUARANTINE_BUCKET'] = 'bucket-quarantine'
    os.environ['SHARED_CORPUS_BUCKET'] = 'bucket-shared'
    os.environ['JOB_NAME'] = 'libfuzzer_asan_job'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_REVISION'] = '1337'

    # ndb.transaction seems to cause hangs with testbed when run after another
    # test that uses testbed.
    self.mock.transaction.side_effect = lambda f, **_: f()

  def tearDown(self):
    shutil.rmtree(self.fuzz_inputs_disk, ignore_errors=True)
    shutil.rmtree(self.bot_tmpdir, ignore_errors=True)
    shutil.rmtree(self.corpus_bucket, ignore_errors=True)

  def _mock_setup_build(self, revision=None):
    os.environ['BUILD_DIR'] = os.path.join(TEST_DIR, 'build')

  def _mock_rsync_to_disk(self, _, sync_dir, timeout=None, delete=None):
    """Mock rsync_to_disk."""
    if 'quarantine' in sync_dir:
      corpus_dir = self.quarantine_dir
    elif 'shared' in sync_dir:
      corpus_dir = self.shared_corpus_dir
    else:
      corpus_dir = self.corpus_dir

    if os.path.exists(sync_dir):
      shutil.rmtree(sync_dir, ignore_errors=True)

    shutil.copytree(corpus_dir, sync_dir)
    return True

  def _mock_rsync_from_disk(self, _, sync_dir, timeout=None, delete=None):
    """Mock rsync_from_disk."""
    if 'quarantine' in sync_dir:
      corpus_dir = self.quarantine_dir
    else:
      corpus_dir = self.corpus_dir

    if os.path.exists(corpus_dir):
      shutil.rmtree(corpus_dir, ignore_errors=True)

    shutil.copytree(sync_dir, corpus_dir)
    return True

  def test_prune(self):
    """Basic pruning test."""
    corpus_pruning_task.execute_task('libFuzzer_test_fuzzer@1337',
                                     'libfuzzer_asan_job')

    quarantined = os.listdir(self.quarantine_dir)
    self.assertEqual(1, len(quarantined))
    self.assertEqual(quarantined[0],
                     'crash-7acd6a2b3fe3c5ec97fa37e5a980c106367491fa')

    corpus = os.listdir(self.corpus_dir)
    self.assertEqual(4, len(corpus))
    self.assertItemsEqual([
        '39e0574a4abfd646565a3e436c548eeb1684fb57',
        '7d157d7c000ae27db146575c08ce30df893d3a64',
        '31836aeaab22dc49555a97edb4c753881432e01d',
        '6fa8c57336628a7d733f684dc9404fbd09020543',
    ], corpus)

    testcases = list(data_types.Testcase.query())
    self.assertEqual(1, len(testcases))
    self.assertEqual('Null-dereference WRITE', testcases[0].crash_type)
    self.assertEqual('Foo\ntest_fuzzer.cc\n', testcases[0].crash_state)
    self.assertEqual(1337, testcases[0].crash_revision)
    self.assertEqual('test_fuzzer',
                     testcases[0].get_metadata('fuzzer_binary_name'))

    today = datetime.datetime.utcnow().date()
    # get_coverage_information on test_fuzzer rather than libFuzzer_test_fuzzer
    # since the libfuzzer_ prefix is removed when saving coverage info.
    coverage_info = data_handler.get_coverage_information('test_fuzzer', today)

    self.assertDictEqual(
        {
            'corpus_backup_location':
                u'backup_link',
            'corpus_location':
                u'gs://bucket/libFuzzer/test_fuzzer/',
            'corpus_size_bytes':
                8,
            'corpus_size_units':
                4,
            'date':
                today,
            # Coverage numbers are expected to be None as they come from fuzzer
            # coverage cron task (see src/go/server/cron/coverage.go).
            'edges_covered':
                None,
            'edges_total':
                None,
            'functions_covered':
                None,
            'functions_total':
                None,
            'fuzzer':
                u'test_fuzzer',
            'html_report_url':
                None,
            'quarantine_location':
                u'gs://bucket-quarantine/libFuzzer/test_fuzzer/',
            'quarantine_size_bytes':
                2,
            'quarantine_size_units':
                1,
        },
        coverage_info.to_dict())

    self.assertEqual(self.mock.unpack_seed_corpus_if_needed.call_count, 1)


class CorpusPruningTestMinijail(CorpusPruningTest):
  """Tests for corpus pruning (minijail)."""

  def setUp(self):
    if environment.platform() != 'LINUX':
      self.skipTest('Minijail tests are only applicable for linux platform.')

    super(CorpusPruningTestMinijail, self).setUp()
    os.environ['USE_MINIJAIL'] = 'True'


class CorpusPruningTestUntrusted(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Tests for corpus pruning (untrusted)."""

  def setUp(self):
    """Set up."""
    super(CorpusPruningTestUntrusted, self).setUp()
    environment.set_value('JOB_NAME', 'libfuzzer_asan_job')

    helpers.patch(self, [
        'bot.fuzzers.libFuzzer.fuzzer.LibFuzzer.fuzzer_directory',
        'base.tasks.add_task',
        'datastore.data_handler.get_data_bundle_bucket_name',
    ])

    self.mock.fuzzer_directory.return_value = os.path.join(
        environment.get_value('ROOT_DIR'), 'src', 'python', 'bot', 'fuzzers',
        'libFuzzer')

    self.corpus_bucket = os.environ['CORPUS_BUCKET']
    self.quarantine_bucket = os.environ['QUARANTINE_BUCKET']
    self.backup_bucket = os.environ['BACKUP_BUCKET']

    job = data_types.Job(
        name='libfuzzer_asan_job',
        environment_string=('APP_NAME = test_fuzzer\n'
                            'CORPUS_BUCKET = {corpus_bucket}\n'
                            'QUARANTINE_BUCKET = {quarantine_bucket}\n'
                            'BACKUP_BUCKET={backup_bucket}\n'
                            'RELEASE_BUILD_BUCKET_PATH = '
                            'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
                            'test-libfuzzer-build-([0-9]+).zip\n'
                            'REVISION_VARS_URL = gs://clusterfuzz-test-data/'
                            'test_libfuzzer_builds/'
                            'test-libfuzzer-build-%s.srcmap.json\n'.format(
                                corpus_bucket=self.corpus_bucket,
                                quarantine_bucket=self.quarantine_bucket,
                                backup_bucket=self.backup_bucket)))
    job.put()

    job = data_types.Job(
        name='libfuzzer_asan_job2',
        environment_string=('APP_NAME = test2_fuzzer\n'
                            'BACKUP_BUCKET = clusterfuzz-test2-backup-bucket\n'
                            'CORPUS_FUZZER_NAME_OVERRIDE = libfuzzer\n'))
    job.put()

    os.environ['PROJECT_NAME'] = 'oss-fuzz'
    data_types.FuzzTarget(
        engine='libFuzzer', project='test', binary='test_fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test_fuzzer',
        engine='libFuzzer',
        job='libfuzzer_asan_job',
        last_run=datetime.datetime.now()).put()

    data_types.FuzzTarget(
        engine='libFuzzer', project='test2', binary='fuzzer').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_test2_fuzzer',
        engine='libFuzzer',
        job='libfuzzer_asan_job2',
        last_run=datetime.datetime.now()).put()

    environment.set_value('USE_MINIJAIL', True)
    environment.set_value('SHARED_CORPUS_BUCKET',
                          'clusterfuzz-test-shared-corpus')

    # Set up remote corpora.
    self.corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'test_fuzzer')
    self.corpus.rsync_from_disk(os.path.join(TEST_DIR, 'corpus'), delete=True)

    self.quarantine_corpus = corpus_manager.FuzzTargetCorpus(
        'libFuzzer', 'test_fuzzer', quarantine=True)
    self.quarantine_corpus.rsync_from_disk(
        os.path.join(TEST_DIR, 'quarantine'), delete=True)

    self.mock.get_data_bundle_bucket_name.return_value = (
        'clusterfuzz-test-global-bundle')
    data_types.DataBundle(
        name='bundle', is_local=True, sync_to_worker=True).put()

    data_types.Fuzzer(
        revision=1,
        file_size='builtin',
        source='builtin',
        name='libFuzzer',
        max_testcases=4,
        builtin=True,
        data_bundle_name='bundle').put()

    self.temp_dir = tempfile.mkdtemp()

    # Copy corpus backup in the older date format.
    corpus_backup_date = (
        datetime.datetime.utcnow().date() -
        datetime.timedelta(days=data_types.CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS))
    corpus_backup_dir = (
        'gs://clusterfuzz-test2-backup-bucket/corpus/libfuzzer/test2_fuzzer/')
    gsutil.GSUtilRunner().run_gsutil([
        'cp', (corpus_backup_dir + 'backup.zip'),
        (corpus_backup_dir + '%s.zip' % corpus_backup_date)
    ])

  def tearDown(self):
    super(CorpusPruningTestUntrusted, self).tearDown()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_prune(self):
    """Test pruning."""
    self._setup_env(job_type='libfuzzer_asan_job')
    corpus_pruning_task.execute_task('libFuzzer_test_fuzzer@1337',
                                     'libfuzzer_asan_job')

    corpus_dir = os.path.join(self.temp_dir, 'corpus')
    os.mkdir(corpus_dir)
    self.corpus.rsync_to_disk(corpus_dir)

    self.assertItemsEqual([
        '39e0574a4abfd646565a3e436c548eeb1684fb57',
        '7d157d7c000ae27db146575c08ce30df893d3a64',
        '31836aeaab22dc49555a97edb4c753881432e01d',
        '6fa8c57336628a7d733f684dc9404fbd09020543',
    ], os.listdir(corpus_dir))

    quarantine_dir = os.path.join(self.temp_dir, 'quarantine')
    os.mkdir(quarantine_dir)
    self.quarantine_corpus.rsync_to_disk(quarantine_dir)

    self.assertItemsEqual(['crash-7acd6a2b3fe3c5ec97fa37e5a980c106367491fa'],
                          os.listdir(quarantine_dir))

    testcases = list(data_types.Testcase.query())
    self.assertEqual(1, len(testcases))
    self.assertEqual('Null-dereference WRITE', testcases[0].crash_type)
    self.assertEqual('Foo\ntest_fuzzer.cc\n', testcases[0].crash_state)
    self.assertEqual(1337, testcases[0].crash_revision)
    self.assertEqual('test_fuzzer',
                     testcases[0].get_metadata('fuzzer_binary_name'))

    self.mock.add_task.assert_has_calls([
        mock.call('minimize', testcases[0].key.id(), u'libfuzzer_asan_job'),
    ])

    today = datetime.datetime.utcnow().date()
    coverage_info = data_handler.get_coverage_information('test_fuzzer', today)
    coverage_info_without_backup = coverage_info.to_dict()
    del coverage_info_without_backup['corpus_backup_location']

    self.assertDictEqual(
        {
            'corpus_location':
                u'gs://{}/libFuzzer/test_fuzzer/'.format(self.corpus_bucket),
            'corpus_size_bytes':
                8,
            'corpus_size_units':
                4,
            'date':
                today,
            # Coverage numbers are expected to be None as they come from fuzzer
            # coverage cron task (see src/go/server/cron/coverage.go).
            'edges_covered':
                None,
            'edges_total':
                None,
            'functions_covered':
                None,
            'functions_total':
                None,
            'fuzzer':
                u'test_fuzzer',
            'html_report_url':
                None,
            'quarantine_location':
                u'gs://{}/libFuzzer/test_fuzzer/'.format(self.quarantine_bucket
                                                        ),
            'quarantine_size_bytes':
                2,
            'quarantine_size_units':
                1,
        },
        coverage_info_without_backup)

    self.assertEqual(
        coverage_info.corpus_backup_location,
        'gs://{}/corpus/libFuzzer/test_fuzzer/'.format(
            self.backup_bucket) + '%s.zip' % today)
