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
import os
import shutil
import tempfile
import unittest
from unittest import mock

from clusterfuzz._internal.bot.fuzzers import options
from clusterfuzz._internal.bot.fuzzers.libFuzzer import \
    engine as libFuzzer_engine
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.bot.tasks.utasks import corpus_pruning_task
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import gsutil
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import untrusted_runner_helpers

TEST_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'corpus_pruning_task_data')

TEST_GLOBAL_BUCKET = 'clusterfuzz-test-global-bundle'
TEST2_BACKUP_BUCKET = 'clusterfuzz-test2-backup-bucket'


class BaseTest:
  """Base corpus pruning tests."""

  def setUp(self):
    """Setup."""
    helpers.patch_environ(self)
    self.local_gcs_buckets_path = tempfile.mkdtemp()
    os.environ['LOCAL_GCS_BUCKETS_PATH'] = self.local_gcs_buckets_path
    os.environ['TEST_BLOBS_BUCKET'] = 'blobs-bucket'
    storage._provider().create_bucket('blobs-bucket', None, None)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.unpack_seed_corpus_if_needed',
        'clusterfuzz._internal.bot.tasks.task_creation.create_tasks',
        'clusterfuzz._internal.bot.tasks.setup.update_fuzzer_and_data_bundles',
        'clusterfuzz._internal.bot.tasks.setup.preprocess_update_fuzzer_and_data_bundles',
        'clusterfuzz._internal.fuzzing.corpus_manager.backup_corpus',
        'clusterfuzz._internal.fuzzing.corpus_manager.FuzzTargetCorpus.rsync_to_disk',
        ('proto_rsync_to_disk',
         'clusterfuzz._internal.fuzzing.corpus_manager.ProtoFuzzTargetCorpus.rsync_to_disk'
        ),
        'clusterfuzz._internal.fuzzing.corpus_manager.FuzzTargetCorpus.rsync_from_disk',
        ('proto_rsync_from_disk',
         'clusterfuzz._internal.fuzzing.corpus_manager.ProtoFuzzTargetCorpus.rsync_from_disk'
        ),
        'clusterfuzz.fuzz.engine.get',
    ])
    self.mock.get.return_value = libFuzzer_engine.Engine()
    self.mock.rsync_to_disk.side_effect = self._mock_rsync_to_disk
    self.mock.proto_rsync_to_disk.side_effect = self._mock_rsync_to_disk
    self.mock.rsync_from_disk.side_effect = self._mock_rsync_from_disk
    self.mock.proto_rsync_from_disk.side_effect = self._mock_rsync_from_disk
    self.mock.update_fuzzer_and_data_bundles.return_value = True
    self.mock.preprocess_update_fuzzer_and_data_bundles.return_value = None
    self.mock.backup_corpus.return_value = True

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
    self.build_dir = os.path.join(TEST_DIR, 'build')
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
    os.environ['JOB_NAME'] = 'libfuzzer_asan_job'
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['APP_REVISION'] = '1337'

  def tearDown(self):
    shutil.rmtree(self.fuzz_inputs_disk, ignore_errors=True)
    shutil.rmtree(self.bot_tmpdir, ignore_errors=True)
    shutil.rmtree(self.corpus_bucket, ignore_errors=True)
    shutil.rmtree(self.local_gcs_buckets_path, ignore_errors=True)

  def _mock_setup_build(self, revision=None):
    os.environ['BUILD_DIR'] = self.build_dir
    return True

  def _mock_rsync_to_disk(self, _, sync_dir, timeout=None, delete=None):
    """Mock rsync_to_disk."""
    if 'quarantine' in sync_dir:
      corpus_dir = self.quarantine_dir
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


@test_utils.supported_platforms('LINUX')
@test_utils.with_cloud_emulators('datastore')
class CorpusPruningTest(unittest.TestCase, BaseTest):
  """Corpus pruning tests."""

  def setUp(self):
    BaseTest.setUp(self)
    helpers.patch(self, [
        'clusterfuzz._internal.build_management.build_manager.setup_build',
        'clusterfuzz._internal.base.utils.get_application_id',
        'clusterfuzz._internal.datastore.data_handler.update_task_status',
        'clusterfuzz._internal.datastore.data_handler.get_task_status',
    ])
    self.mock.setup_build.side_effect = self._mock_setup_build
    self.mock.get_application_id.return_value = 'project'
    self.maxDiff = None
    self.backup_bucket = os.environ['BACKUP_BUCKET'] or ''

  def test_preprocess_existing_task_running(self):
    """Preprocess test when another task is running."""
    self.mock.update_task_status.return_value = False
    self.assertIsNone(
        corpus_pruning_task.utask_preprocess('libFuzzer_test_fuzzer',
                                             'libfuzzer_asan_job', {}))

  def test_preprocess(self):
    """Basic preprocess test."""
    fuzzer_name = 'libFuzzer_test_fuzzer'
    job_type = 'libfuzzer_asan_job'
    self.mock.update_task_status.return_value = True
    self.mock.get_task_status.return_value = data_types.TaskStatus(
        status=data_types.TaskState.ERROR)
    uworker_input = corpus_pruning_task.utask_preprocess(
        fuzzer_name, job_type, {})
    self.assertEqual(uworker_input.job_type, job_type)
    self.assertEqual(uworker_input.fuzzer_name, fuzzer_name)
    fuzz_target = data_handler.get_fuzz_target(fuzzer_name)
    self.assertEqual(
        uworker_io.entity_from_protobuf(
            uworker_input.corpus_pruning_task_input.fuzz_target,
            data_types.FuzzTarget), fuzz_target)
    self.assertTrue(
        uworker_input.corpus_pruning_task_input.last_execution_failed)

  def test_fuzzer_setup_failure(self):
    """CORPUS_PRUNING_FUZZER_SETUP_FAILED test."""
    self.mock.update_fuzzer_and_data_bundles.return_value = False
    uworker_input = corpus_pruning_task.utask_preprocess(
        job_type='libfuzzer_asan_job',
        fuzzer_name='libFuzzer_test_fuzzer',
        uworker_env={})
    result = corpus_pruning_task.utask_main(uworker_input)
    self.assertEqual(result.error_type,
                     uworker_msg_pb2.CORPUS_PRUNING_FUZZER_SETUP_FAILED)

  def test_prune(self):
    """Basic pruning test."""
    uworker_input = corpus_pruning_task.utask_preprocess(
        job_type='libfuzzer_asan_job',
        fuzzer_name='libFuzzer_test_fuzzer',
        uworker_env={})
    output = corpus_pruning_task.utask_main(uworker_input)
    self.assertFalse(output.HasField('error_type'))
    output.uworker_input.CopyFrom(uworker_input)
    corpus_pruning_task.utask_postprocess(output)
    quarantined = os.listdir(self.quarantine_dir)
    self.assertEqual(quarantined,
                     ['crash-7acd6a2b3fe3c5ec97fa37e5a980c106367491fa'])

    corpus = os.listdir(self.corpus_dir)
    self.assertCountEqual([
        '7d157d7c000ae27db146575c08ce30df893d3a64',
        '6fa8c57336628a7d733f684dc9404fbd09020543',
    ], corpus)

    testcases = list(data_types.Testcase.query())
    self.assertEqual(1, len(testcases))
    self.assertEqual('Null-dereference WRITE', testcases[0].crash_type)
    self.assertEqual('Foo\ntest_fuzzer.cc\n', testcases[0].crash_state)
    self.assertEqual(1337, testcases[0].crash_revision)
    self.assertEqual('test_fuzzer',
                     testcases[0].get_metadata('fuzzer_binary_name'))
    self.assertEqual('label1,label2', testcases[0].get_metadata('issue_labels'))

    today = datetime.datetime.utcnow().date()
    # get_coverage_information on test_fuzzer rather than libFuzzer_test_fuzzer
    # since the libfuzzer_ prefix is removed when saving coverage info.
    coverage_info = data_handler.get_coverage_information('test_fuzzer', today)

    self.assertDictEqual(
        {
            'corpus_backup_location':
                uworker_input.corpus_pruning_task_input.dated_backup_gcs_url,
            'corpus_location':
                'gs://bucket/libFuzzer/test_fuzzer/',
            'corpus_size_bytes':
                4,
            'corpus_size_units':
                2,
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
                'test_fuzzer',
            'html_report_url':
                None,
            'quarantine_location':
                'gs://bucket-quarantine/libFuzzer/test_fuzzer/',
            'quarantine_size_bytes':
                2,
            'quarantine_size_units':
                1,
        },
        coverage_info.to_dict())

    self.assertEqual(self.mock.unpack_seed_corpus_if_needed.call_count, 1)

  def test_get_libfuzzer_flags(self):
    """Test get_libfuzzer_flags logic."""
    fuzz_target = data_handler.get_fuzz_target('libFuzzer_test_fuzzer')
    context = corpus_pruning_task.Context(uworker_msg_pb2.Input(), fuzz_target,
                                          [])

    runner = corpus_pruning_task.Runner(self.build_dir, context)
    flags = runner.get_libfuzzer_flags()
    expected_default_flags = [
        '-timeout=5', '-rss_limit_mb=2560', '-max_len=5242880',
        '-detect_leaks=1', '-use_value_profile=1'
    ]
    self.assertCountEqual(flags, expected_default_flags)

    runner.fuzzer_options = options.FuzzerOptions(
        os.path.join(self.build_dir, 'test_get_libfuzzer_flags.options'))
    flags = runner.get_libfuzzer_flags()
    expected_custom_flags = [
        '-timeout=5', '-rss_limit_mb=31337', '-max_len=1337', '-detect_leaks=0',
        '-use_value_profile=1'
    ]
    self.assertCountEqual(flags, expected_custom_flags)


class CorpusPruningTestMinijail(CorpusPruningTest):
  """Tests for corpus pruning (minijail)."""

  def setUp(self):
    if environment.platform() != 'LINUX':
      self.skipTest('Minijail tests are only applicable for linux platform.')

    super().setUp()
    os.environ['USE_MINIJAIL'] = 'True'


@unittest.skipIf(
    not environment.get_value('FUCHSIA_TESTS'),
    'Temporarily disabling the Fuchsia test until build size reduced.')
@test_utils.with_cloud_emulators('datastore')
@test_utils.integration
class CorpusPruningTestFuchsia(unittest.TestCase, BaseTest):
  """Corpus pruning test for fuchsia."""

  def setUp(self):
    BaseTest.setUp(self)
    self.fuchsia_corpus_dir = os.path.join(self.corpus_bucket, 'fuchsia')
    shutil.copytree(os.path.join(TEST_DIR, 'fuchsia'), self.fuchsia_corpus_dir)
    self.temp_dir = tempfile.mkdtemp()
    builds_dir = os.path.join(self.temp_dir, 'builds')
    os.mkdir(builds_dir)
    urls_dir = os.path.join(self.temp_dir, 'urls')
    os.mkdir(urls_dir)

    environment.set_value('BUILDS_DIR', builds_dir)
    environment.set_value('BUILD_URLS_DIR', urls_dir)
    environment.set_value('QUEUE_OVERRIDE', 'FUCHSIA')
    environment.set_value('OS_OVERRIDE', 'FUCHSIA')

    env_string = ('RELEASE_BUILD_BUCKET_PATH = '
                  'gs://clusterfuchsia-builds-test/libfuzzer/'
                  'fuchsia-([0-9]+).zip')
    commands.update_environment_for_job(env_string)

    data_types.Job(
        name='libfuzzer_asan_fuchsia',
        platform='FUCHSIA',
        environment_string=env_string).put()
    data_types.FuzzTarget(
        binary='example-fuzzers/crash_fuzzer',
        engine='libFuzzer',
        project='fuchsia').put()

    environment.set_value('UNPACK_ALL_FUZZ_TARGETS_AND_FILES', True)
    helpers.patch(self, [
        'clusterfuzz._internal.system.shell.clear_temp_directory',
    ])

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_prune(self):
    """Basic pruning test."""
    self.corpus_dir = self.fuchsia_corpus_dir
    uworker_input = corpus_pruning_task.utask_preprocess(
        job_type='libfuzzer_asan_fuchsia',
        fuzzer_name='libFuzzer_fuchsia_example-fuzzers-crash_fuzzer',
        uworker_env={})
    corpus_pruning_task.utask_main(uworker_input)
    corpus = os.listdir(self.corpus_dir)
    self.assertEqual(2, len(corpus))
    self.assertCountEqual([
        '801c34269f74ed383fc97de33604b8a905adb635',
        '7cf184f4c67ad58283ecb19349720b0cae756829'
    ], corpus)
    quarantine = os.listdir(self.quarantine_dir)
    self.assertEqual(1, len(quarantine))
    self.assertCountEqual(['crash-7a8dc3985d2a90fb6e62e94910fc11d31949c348'],
                          quarantine)


class CorpusPruningTestUntrusted(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Tests for corpus pruning (untrusted)."""

  def setUp(self):
    """Set up."""
    super().setUp()
    environment.set_value('JOB_NAME', 'libfuzzer_asan_job')

    helpers.patch(self, [
        'clusterfuzz._internal.bot.tasks.setup.get_fuzzer_directory',
        'clusterfuzz._internal.base.tasks.add_task',
        'clusterfuzz.fuzz.engine.get',
    ])
    self.mock.get.return_value = libFuzzer_engine.Engine()
    self.mock.get_fuzzer_directory.return_value = os.path.join(
        environment.get_value('ROOT_DIR'), 'src', 'clusterfuzz', '_internal',
        'bot', 'fuzzers', 'libFuzzer')
    self.corpus_bucket = os.environ['CORPUS_BUCKET']
    self.quarantine_bucket = os.environ['QUARANTINE_BUCKET']
    self.backup_bucket = os.environ['BACKUP_BUCKET']

    job = data_types.Job(
        name='libfuzzer_asan_job',
        environment_string=('APP_NAME = test_fuzzer\n'
                            f'CORPUS_BUCKET = {self.corpus_bucket}\n'
                            f'QUARANTINE_BUCKET = {self.quarantine_bucket}\n'
                            f'BACKUP_BUCKET={self.backup_bucket}\n'
                            'RELEASE_BUILD_BUCKET_PATH = '
                            'gs://clusterfuzz-test-data/test_libfuzzer_builds2/'
                            'test-libfuzzer-build-([0-9]+).zip\n'
                            'REVISION_VARS_URL = gs://clusterfuzz-test-data/'
                            'test_libfuzzer_builds2/'
                            'test-libfuzzer-build-%s.srcmap.json\n'))
    job.put()

    job = data_types.Job(
        name='libfuzzer_asan_job2',
        environment_string=('APP_NAME = test2_fuzzer\n'
                            f'BACKUP_BUCKET = {self.backup_bucket}\n'
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

    # Set up remote corpora.
    self.corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'test_fuzzer')
    self.corpus.rsync_from_disk(os.path.join(TEST_DIR, 'corpus'), delete=True)

    self.quarantine_corpus = corpus_manager.FuzzTargetCorpus(
        'libFuzzer', 'test_fuzzer', quarantine=True)
    self.quarantine_corpus.rsync_from_disk(
        os.path.join(TEST_DIR, 'quarantine'), delete=True)

    self.mock.get_data_bundle_bucket_name.return_value = TEST_GLOBAL_BUCKET
    data_types.DataBundle(name='bundle', sync_to_worker=True).put()

    self.fuzzer = data_types.Fuzzer(
        revision=1,
        file_size='builtin',
        source='builtin',
        name='libFuzzer',
        max_testcases=4,
        builtin=True,
        data_bundle_name='bundle')
    self.fuzzer.put()

    self.temp_dir = tempfile.mkdtemp()

    # Copy corpus backup in the older date format.
    corpus_backup_date = (
        datetime.datetime.utcnow().date() -
        datetime.timedelta(days=data_types.CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS))
    gsutil.GSUtilRunner().run_gsutil([
        'cp',
        f'gs://{TEST2_BACKUP_BUCKET}/corpus/libfuzzer/test2_fuzzer/backup.zip',
        (f'gs://{self.backup_bucket}/corpus/libfuzzer/'
         f'test2_fuzzer/{corpus_backup_date}.zip')
    ])

  def tearDown(self):
    super().tearDown()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  @unittest.skip('Non-deterministic, impossible to tell why failing.')
  def test_prune(self):
    """Test pruning."""
    self._setup_env(job_type='libfuzzer_asan_job')
    uworker_input = corpus_pruning_task.utask_preprocess(
        job_type='libfuzzer_asan_job',
        fuzzer_name='libFuzzer_test_fuzzer',
        uworker_env={})
    corpus_pruning_task.utask_main(uworker_input)

    corpus_dir = os.path.join(self.temp_dir, 'corpus')
    os.mkdir(corpus_dir)

    self.corpus.rsync_to_disk(corpus_dir)
    self.assertCountEqual([
        '31836aeaab22dc49555a97edb4c753881432e01d',
        '39e0574a4abfd646565a3e436c548eeb1684fb57',
    ], os.listdir(corpus_dir))

    quarantine_dir = os.path.join(self.temp_dir, 'quarantine')
    os.mkdir(quarantine_dir)
    self.quarantine_corpus.rsync_to_disk(quarantine_dir)

    self.assertCountEqual(['crash-7acd6a2b3fe3c5ec97fa37e5a980c106367491fa'],
                          os.listdir(quarantine_dir))

    testcases = list(data_types.Testcase.query())
    self.assertEqual(1, len(testcases))
    self.assertEqual('Null-dereference WRITE', testcases[0].crash_type)
    self.assertEqual('Foo\ntest_fuzzer.cc\n', testcases[0].crash_state)
    self.assertEqual(1337, testcases[0].crash_revision)
    self.assertEqual('test_fuzzer',
                     testcases[0].get_metadata('fuzzer_binary_name'))

    self.mock.add_task.assert_has_calls([
        mock.call('minimize', testcases[0].key.id(), 'libfuzzer_asan_job'),
    ])

    today = datetime.datetime.utcnow().date()
    coverage_info = data_handler.get_coverage_information('test_fuzzer', today)
    coverage_info_without_backup = coverage_info.to_dict()
    del coverage_info_without_backup['corpus_backup_location']

    self.assertDictEqual(
        {
            'corpus_location':
                f'gs://{self.corpus_bucket}/libFuzzer/test_fuzzer/',
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
                'test_fuzzer',
            'html_report_url':
                None,
            'quarantine_location':
                f'gs://{self.quarantine_bucket}/libFuzzer/test_fuzzer/',
            'quarantine_size_bytes':
                2,
            'quarantine_size_units':
                1,
        },
        coverage_info_without_backup)

    self.assertEqual(
        coverage_info.corpus_backup_location,
        f'gs://{self.backup_bucket}/corpus/libFuzzer/test_fuzzer/{today}.zip')

  def get_mock_record_compare(self, project_qualified_name, sources,
                              initial_corpus_size, corpus_size,
                              initial_edge_coverage, edge_coverage,
                              initial_feature_coverage, feature_coverage):
    """Given all of the expected stats, returns a function
    that will compare them to an instance of CorpusPruningStats."""

    def compare(stats):
      """Mock record_cross_pollination_stats. Make sure function was called
      with the correct arguments."""
      self.assertEqual(project_qualified_name, stats.project_qualified_name)
      self.assertEqual(sources, stats.sources)
      self.assertEqual(initial_corpus_size, stats.initial_corpus_size)
      self.assertEqual(corpus_size, stats.corpus_size)
      self.assertEqual(initial_edge_coverage, stats.initial_edge_coverage)
      self.assertEqual(edge_coverage, stats.edge_coverage)
      self.assertEqual(initial_feature_coverage, stats.initial_feature_coverage)
      self.assertEqual(stats.feature_coverage, feature_coverage)

    return compare


@test_utils.supported_platforms('LINUX')
@test_utils.with_cloud_emulators('datastore')
class CrashProcessingTest(unittest.TestCase, BaseTest):
  """Tests uploading corpus crashes zip from utask_main."""

  def setUp(self):
    """Set up."""
    BaseTest.setUp(self)
    helpers.patch_environ(self)
    (self.corpus_crashes_blob_name,
     self.corpus_crashes_upload_url) = blobs.get_blob_signed_upload_url()
    self.temp_dir = tempfile.mkdtemp()

  def test_upload_corpus_crashes_zip(self):
    """Test that _upload_corpus_crashes_zip works as expected."""

    os.makedirs('a/b')
    unit1_path = 'a/b/unit1'
    with open(unit1_path, 'w') as f:
      f.write('unit1_contents')

    crash1 = corpus_pruning_task.CorpusCrash(
        'crash_state1', 'crash_type1', 'crash_address1', 'crash_stacktrace1',
        unit1_path, False)

    os.makedirs('c/d')
    unit2_path = 'c/d/unit2'
    with open(unit2_path, 'w') as f:
      f.write('unit2_contents')

    crash2 = corpus_pruning_task.CorpusCrash(
        'crash_state2', 'crash_type2', 'crash_address2', 'crash_stacktrace2',
        unit2_path, False)

    result = corpus_pruning_task.CorpusPruningResult(
        coverage_info=None,
        crashes=[crash1, crash2],
        fuzzer_binary_name='fuzzer_binary_name',
        revision='1234',
        cross_pollination_stats=None)

    corpus_pruning_task._upload_corpus_crashes_zip(
        None, result, self.corpus_crashes_blob_name,
        self.corpus_crashes_upload_url)

    corpus_crashes_zip_local_path = os.path.join(
        self.temp_dir, f'{self.corpus_crashes_blob_name}.zip')
    storage.copy_file_from(
        blobs.get_gcs_path(self.corpus_crashes_blob_name),
        corpus_crashes_zip_local_path)

    with archive.open(corpus_crashes_zip_local_path) as zip_reader:
      members = zip_reader.list_members()
      self.assertEqual(2, len(members))
      zip_reader.extract_all(self.temp_dir)

      with open(os.path.join(self.temp_dir, os.path.basename(unit1_path)),
                'r') as f:
        self.assertEqual('unit1_contents', f.read())

      with open(os.path.join(self.temp_dir, os.path.basename(unit2_path)),
                'r') as f:
        self.assertEqual('unit2_contents', f.read())

  def tearDown(self):
    """Tear Down."""
    super().tearDown()
    shutil.rmtree('a')
    shutil.rmtree('c')
    shutil.rmtree(self.temp_dir)
