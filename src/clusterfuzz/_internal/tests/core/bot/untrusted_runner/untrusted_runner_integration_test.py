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
"""Tests for untrusted_runner_integration."""

import filecmp
import os
import shutil
import subprocess
import sys
import tempfile

import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.bot.untrusted_runner import \
    environment as untrusted_env
from clusterfuzz._internal.bot.untrusted_runner import config
from clusterfuzz._internal.bot.untrusted_runner import corpus_manager
from clusterfuzz._internal.bot.untrusted_runner import file_host
from clusterfuzz._internal.bot.untrusted_runner import host
from clusterfuzz._internal.bot.untrusted_runner import remote_process_host
from clusterfuzz._internal.bot.untrusted_runner import symbolize_host
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import untrusted_runner_helpers

TEST_FILE_CONTENTS = (b'A' * config.FILE_TRANSFER_CHUNK_SIZE +
                      b'B' * config.FILE_TRANSFER_CHUNK_SIZE +
                      b'C' * (config.FILE_TRANSFER_CHUNK_SIZE // 2))

TEST_BUNDLE_BUCKET = 'clusterfuzz-test-bundle'


def _dirs_equal(dircmp):
  if dircmp.left_only or dircmp.right_only or dircmp.diff_files:
    return False

  return all(
      _dirs_equal(sub_dircmp) for sub_dircmp in six.itervalues(dircmp.subdirs))


class UntrustedRunnerIntegrationTest(
    untrusted_runner_helpers.UntrustedRunnerIntegrationTest):
  """Integration tests for untrusted_runner."""

  def assert_dirs_equal(self, dir1, dir2):
    """Assert that 2 dirs are equal."""
    self.assertTrue(_dirs_equal(filecmp.dircmp(dir1, dir2)))

  def setUp(self):
    """Set up."""
    super(UntrustedRunnerIntegrationTest, self).setUp()
    data_types.Config().put()

    environment_string = ('APP_NAME = app\n'
                          'RELEASE_BUILD_BUCKET_PATH = '
                          'gs://clusterfuzz-test-data/test_builds/'
                          'test-build-([0-9]+).zip\n')
    data_types.Job(name='job', environment_string=environment_string).put()

    environment_string = ('RELEASE_BUILD_BUCKET_PATH = '
                          'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
                          'test-libfuzzer-build-([0-9]+).zip\n'
                          'UNPACK_ALL_FUZZ_TARGETS_AND_FILES = True')
    data_types.Job(
        name='libfuzzer_asan_job', environment_string=environment_string).put()

    data_types.Fuzzer(name='fuzzer', data_bundle_name='bundle').put()

    data_types.DataBundle(
        name='bundle', is_local=True, sync_to_worker=True).put()

  def test_run_process(self):
    """Tests remote run_process."""
    expected_output = subprocess.check_output(['ls', '/']).decode('utf-8')

    return_code, _, output = (
        remote_process_host.run_process('ls', current_working_directory='/'))
    self.assertEqual(return_code, 0)
    # run_process adds extra newlines.
    self.assertEqual(output.strip(), expected_output.strip())

  def test_run_and_wait(self):
    """Tests remote run_and_wait."""
    expected_output = subprocess.check_output(['ls', '/'])

    runner = remote_process_host.RemoteProcessRunner('/bin/ls')
    result = runner.run_and_wait(cwd='/')
    self.assertEqual(result.return_code, 0)
    self.assertEqual(result.output, expected_output)

  def test_run_process_env(self):
    """Test environment passing when running processes."""
    environment.set_value('ASAN_OPTIONS', 'host_value')
    runner = remote_process_host.RemoteProcessRunner('/bin/sh', ['-c'])
    result = runner.run_and_wait(['echo $ASAN_OPTIONS'])
    self.assertEqual(result.output, b'host_value\n')

    result = runner.run_and_wait(
        ['echo $ASAN_OPTIONS $UBSAN_OPTIONS'],
        env={
            'UBSAN_OPTIONS': 'ubsan',
            'NOT_PASSED': 'blah'
        })
    self.assertEqual(result.output, b'ubsan\n')

    _, _, output = process_handler.run_process(
        '/bin/sh -c \'echo $ASAN_OPTIONS $MSAN_OPTIONS\'',
        testcase_run=True,
        env_copy={
            'MSAN_OPTIONS': 'msan',
            'NOT_PASSED': 'blah'
        })
    self.assertEqual(output, 'host_value msan')

  def test_create_directory(self):
    """Tests remote create_directory."""
    path = os.path.join(self.tmp_dir, 'dir1')
    self.assertTrue(file_host.create_directory(path))
    self.assertTrue(os.path.isdir(path))

    path = os.path.join(self.tmp_dir, 'dir2', 'dir2')
    self.assertFalse(file_host.create_directory(path))
    self.assertFalse(os.path.exists(path))

    path = os.path.join(self.tmp_dir, 'dir2', 'dir2')
    self.assertTrue(file_host.create_directory(path, True))
    self.assertTrue(os.path.isdir(path))

  def test_remove_directory(self):
    """Tests remote remove_directory."""
    path = os.path.join(self.tmp_dir, 'dir1')
    os.mkdir(path)

    self.assertTrue(file_host.remove_directory(path))
    self.assertFalse(os.path.exists(path))

    os.mkdir(path)
    file_path = os.path.join(path, 'file')
    with open(file_path, 'w') as f:
      f.write('output')

    self.assertTrue(file_host.remove_directory(path, recreate=True))
    self.assertTrue(os.path.isdir(path))
    self.assertFalse(os.path.exists(file_path))

  def test_list_files(self):
    """Tests remote list_files."""
    fuzz_inputs = file_host.rebase_to_worker_root(os.environ['FUZZ_INPUTS'])

    with open(os.path.join(fuzz_inputs, 'a'), 'w') as f:
      f.write('')

    with open(os.path.join(fuzz_inputs, 'b'), 'w') as f:
      f.write('')

    os.mkdir(os.path.join(fuzz_inputs, 'c'))
    with open(os.path.join(fuzz_inputs, 'c', 'c'), 'w') as f:
      f.write('')

    six.assertCountEqual(self, [
        os.path.join(fuzz_inputs, 'a'),
        os.path.join(fuzz_inputs, 'b'),
        os.path.join(fuzz_inputs, 'c'),
    ], file_host.list_files(fuzz_inputs))

    six.assertCountEqual(self, [
        os.path.join(fuzz_inputs, 'a'),
        os.path.join(fuzz_inputs, 'b'),
        os.path.join(fuzz_inputs, 'c', 'c'),
    ], file_host.list_files(fuzz_inputs, recursive=True))

  def test_copy_file_to_worker(self):
    """Tests remote copy_file_to_worker."""
    src_path = os.path.join(self.tmp_dir, 'src')
    with open(src_path, 'wb') as f:
      f.write(TEST_FILE_CONTENTS)

    dest_path = os.path.join(self.tmp_dir, 'dst')
    self.assertTrue(file_host.copy_file_to_worker(src_path, dest_path))

    with open(dest_path, 'rb') as f:
      self.assertEqual(f.read(), TEST_FILE_CONTENTS)

  def test_copy_file_to_worker_intermediate(self):
    """Tests remote copy_file_to_worker creating intermediate paths."""
    src_path = os.path.join(self.tmp_dir, 'src')
    with open(src_path, 'wb') as f:
      f.write(TEST_FILE_CONTENTS)

    dest_path = os.path.join(self.tmp_dir, 'dir1', 'dir2', 'dst')
    self.assertTrue(file_host.copy_file_to_worker(src_path, dest_path))

    with open(dest_path, 'rb') as f:
      self.assertEqual(f.read(), TEST_FILE_CONTENTS)

  def test_write_data_to_worker(self):
    """Tests remote write_data_to_worker."""
    dest_path = os.path.join(self.tmp_dir, 'dst')
    self.assertTrue(
        file_host.write_data_to_worker(b'write_data_to_worker', dest_path))

    with open(dest_path, 'rb') as f:
      self.assertEqual(f.read(), b'write_data_to_worker')

  def test_copy_file_from_worker(self):
    """Tests remote copy_file_from_worker."""
    src_path = os.path.join(self.tmp_dir, 'src')
    with open(src_path, 'wb') as f:
      f.write(TEST_FILE_CONTENTS)

    dest_path = os.path.join(self.tmp_dir, 'dst')
    self.assertTrue(file_host.copy_file_from_worker(src_path, dest_path))

    with open(dest_path, 'rb') as f:
      self.assertEqual(f.read(), TEST_FILE_CONTENTS)

  def test_copy_file_from_worker_does_not_exist(self):
    """Tests remote copy_file_from_worker (does not exist)."""
    src_path = os.path.join(self.tmp_dir, 'DOES_NOT_EXIST')
    dest_path = os.path.join(self.tmp_dir, 'dst')
    self.assertFalse(file_host.copy_file_from_worker(src_path, dest_path))
    self.assertFalse(os.path.exists(dest_path))

  def test_copy_directory_to_worker(self):
    """Tests remote copy_directory_to_worker."""
    src_dir = os.path.join(self.tmp_dir, 'src_dir')
    nested_src_dir = os.path.join(self.tmp_dir, 'src_dir', 'nested')
    os.mkdir(src_dir)
    os.mkdir(nested_src_dir)

    with open(os.path.join(src_dir, 'file1'), 'w') as f:
      f.write('1')

    with open(os.path.join(nested_src_dir, 'file2'), 'w') as f:
      f.write('2')

    dest_dir = os.path.join(self.tmp_dir, 'dst_dir')
    os.mkdir(dest_dir)
    old_file_path = os.path.join(dest_dir, 'old_file')
    with open(old_file_path, 'w') as f:
      f.write('old')

    self.assertTrue(file_host.copy_directory_to_worker(src_dir, dest_dir))
    self.assertTrue(os.path.exists(old_file_path))

    os.remove(old_file_path)
    self.assert_dirs_equal(src_dir, dest_dir)

  def test_copy_directory_to_worker_replace(self):
    """Tests remote copy_directory_to_worker (replacing old dir)"""
    src_dir = os.path.join(self.tmp_dir, 'src_dir')
    os.mkdir(src_dir)

    with open(os.path.join(src_dir, 'file1'), 'w') as f:
      f.write('1')

    dest_dir = os.path.join(self.tmp_dir, 'dst_dir')
    os.mkdir(dest_dir)
    with open(os.path.join(dest_dir, 'old_file'), 'w') as f:
      f.write('old')

    self.assertTrue(
        file_host.copy_directory_to_worker(src_dir, dest_dir, replace=True))
    self.assert_dirs_equal(src_dir, dest_dir)

  def test_setup_regular_build(self):
    """Test setting up a regular build."""
    self._setup_env(job_type='job')
    build = build_manager.setup_build()
    self.assertIsNotNone(build)

    worker_root_dir = os.environ['WORKER_ROOT_DIR']
    expected_build_dir = os.path.join(
        worker_root_dir, 'bot', 'builds', 'clusterfuzz-test-data_test_builds_'
        '2b6ddd7575e9b06b20306183720c65fff3ce318d', 'revisions')
    expected_app_dir = os.path.join(
        worker_root_dir, 'bot', 'builds', 'clusterfuzz-test-data_test_builds_'
        '2b6ddd7575e9b06b20306183720c65fff3ce318d', 'revisions', 'test_build')

    self.assertEqual(
        os.path.join(expected_app_dir, 'app'), os.environ['APP_PATH'])
    self.assertEqual('12345', os.environ['APP_REVISION'])
    self.assertEqual('', os.environ['APP_PATH_DEBUG'])
    self.assertEqual(expected_build_dir, os.environ['BUILD_DIR'])
    self.assertEqual(expected_app_dir, os.environ['APP_DIR'])
    self.assertEqual('', os.environ['FUZZ_TARGET'])

  def test_setup_regular_build_fuzz_target(self):
    """Test setting up a regular build."""
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('TASK_ARGUMENT', 'libFuzzer')

    launcher_dir = os.path.join('src', 'clusterfuzz', '_internal', 'bot',
                                'fuzzers', 'libFuzzer')
    environment.set_value('FUZZER_DIR',
                          os.path.join(os.environ['ROOT_DIR'], launcher_dir))

    self._setup_env(job_type='libfuzzer_asan_job')
    build = build_manager.setup_build(target_weights={})
    self.assertIsNotNone(build)

    worker_root_dir = os.environ['WORKER_ROOT_DIR']
    expected_build_dir = os.path.join(
        worker_root_dir, 'bot', 'builds',
        'clusterfuzz-test-data_test_libfuzzer_builds_'
        '41a87efdd470c6f00e8babf61548bf6c7de57137', 'revisions')

    self.assertEqual('', os.environ['APP_PATH'])
    self.assertEqual('1337', os.environ['APP_REVISION'])
    self.assertEqual('', os.environ['APP_PATH_DEBUG'])
    self.assertEqual(expected_build_dir, os.environ['BUILD_DIR'])
    self.assertEqual('', os.environ['APP_DIR'])
    self.assertEqual('test_fuzzer', os.environ['FUZZ_TARGET'])

  def test_run_process_testcase(self):
    """Test run_process for testcase runs."""
    return_code, _, output = process_handler.run_process(
        '/bin/sh -c \'echo $UNTRUSTED_WORKER\'', testcase_run=True)
    self.assertEqual(return_code, 0)
    self.assertEqual(output, 'True')

    return_code, _, output = process_handler.run_process(
        '/bin/sh -c \'echo $TRUSTED_HOST\'', testcase_run=True)
    self.assertEqual(return_code, 0)
    self.assertEqual(output, '')

  def test_run_process_non_testcase(self):
    """Test run_process for non-testcase runs."""
    return_code, _, output = process_handler.run_process(
        '/bin/sh -c \'echo $TRUSTED_HOST\'', testcase_run=False)
    self.assertEqual(return_code, 0)
    self.assertEqual(output, 'True')

    return_code, _, output = process_handler.run_process(
        '/bin/sh -c \'echo $UNTRUSTED_WORKER\'', testcase_run=False)
    self.assertEqual(return_code, 0)
    self.assertEqual(output, '')

  def test_clear_testcase_directories(self):
    """Test clearing test directories."""
    fuzz_inputs = os.environ['FUZZ_INPUTS']
    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)

    fuzz_inputs_disk = os.environ['FUZZ_INPUTS_DISK']
    worker_fuzz_inputs_disk = file_host.rebase_to_worker_root(fuzz_inputs_disk)

    with open(os.path.join(worker_fuzz_inputs, 'file'), 'w') as f:
      f.write('blah')

    with open(os.path.join(worker_fuzz_inputs_disk, 'file'), 'w') as f:
      f.write('blah2')

    shell.clear_testcase_directories()
    self.assertEqual(len(os.listdir(worker_fuzz_inputs)), 0)
    self.assertEqual(len(os.listdir(worker_fuzz_inputs_disk)), 0)

  def test_push_testcases_to_worker(self):
    """Test pushing testcases to the worker."""
    fuzz_inputs = os.environ['FUZZ_INPUTS']
    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)

    with open(os.path.join(worker_fuzz_inputs, 'will_be_replaced'), 'w') as f:
      f.write('blah')

    with open(os.path.join(fuzz_inputs, 'file'), 'w') as f:
      f.write('file')

    subdir = os.path.join(fuzz_inputs, 'subdir')
    os.mkdir(subdir)

    with open(os.path.join(subdir, 'file2'), 'w') as f:
      f.write('file2')

    self.assertTrue(file_host.push_testcases_to_worker())
    self.assert_dirs_equal(fuzz_inputs, worker_fuzz_inputs)

  def test_pulling_testcases_from_worker(self):
    """Test pulling testcases from the worker."""
    fuzz_inputs = os.environ['FUZZ_INPUTS']
    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)

    with open(os.path.join(fuzz_inputs, 'will_be_replaced'), 'w') as f:
      f.write('blah')

    with open(os.path.join(worker_fuzz_inputs, 'file'), 'w') as f:
      f.write('file')

    subdir = os.path.join(worker_fuzz_inputs, 'subdir')
    os.mkdir(subdir)

    with open(os.path.join(subdir, 'file2'), 'w') as f:
      f.write('file2')

    self.assertTrue(file_host.pull_testcases_from_worker())
    self.assert_dirs_equal(fuzz_inputs, worker_fuzz_inputs)

  def test_setup_testcase(self):
    """Test setup_testcase."""
    job_type = 'job'
    self._setup_env(job_type=job_type)
    fuzz_inputs = os.environ['FUZZ_INPUTS']

    testcase = data_types.Testcase()
    testcase.job_type = job_type
    testcase.absolute_path = os.path.join(fuzz_inputs, 'testcase.ext')

    with tempfile.NamedTemporaryFile() as f:
      f.write(b'contents')
      f.seek(0)
      testcase.fuzzed_keys = blobs.write_blob(f)

    testcase.put()

    file_list, input_directory, testcase_file_path = (
        setup.setup_testcase(testcase, job_type))

    six.assertCountEqual(self, file_list, [
        testcase.absolute_path,
    ])
    self.assertEqual(input_directory, fuzz_inputs)
    self.assertEqual(testcase_file_path, testcase.absolute_path)

    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)
    self.assert_dirs_equal(fuzz_inputs, worker_fuzz_inputs)

  def test_get_command_line_for_application(self):
    """Test get_command_line_for_application."""
    self._setup_env(job_type='job')
    self.assertIsNotNone(build_manager.setup_build())

    fuzz_inputs = os.environ['FUZZ_INPUTS']
    file_to_run = os.path.join(fuzz_inputs, 'file_to_run')

    os.environ['APP_ARGS'] = '%TESTCASE% %TESTCASE_FILE_URL%'
    command_line = testcase_manager.get_command_line_for_application(
        file_to_run)

    app_path = os.environ['APP_PATH']
    worker_fuzz_inputs = file_host.rebase_to_worker_root(fuzz_inputs)
    worker_file_to_run = os.path.join(worker_fuzz_inputs, 'file_to_run')

    self.assertEqual(
        command_line,
        '%s %s %s' % (app_path, worker_file_to_run,
                      utils.file_path_to_file_url(worker_file_to_run)))

    launcher_path = os.path.join(os.environ['FUZZERS_DIR'], 'test',
                                 'launcher.py')
    os.environ['LAUNCHER_PATH'] = launcher_path
    worker_launcher_path = file_host.rebase_to_worker_root(launcher_path)
    command_line = testcase_manager.get_command_line_for_application(
        file_to_run)
    self.assertEqual(
        command_line,
        '%s %s %s %s %s' % (sys.executable, worker_launcher_path, app_path,
                            worker_file_to_run, worker_file_to_run))

  def test_corpus_sync(self):
    """Test syncing corpus."""
    environment.set_value('CORPUS_BUCKET', 'clusterfuzz-test-data')
    corpus = corpus_manager.RemoteFuzzTargetCorpus('corpus_test_fuzzer',
                                                   'child_fuzzer')
    worker_root = environment.get_value('WORKER_ROOT_DIR')
    test_corpus_directory = os.path.join(worker_root, 'corpus')
    os.mkdir(test_corpus_directory)

    try:
      self.assertTrue(corpus.rsync_to_disk(test_corpus_directory))
      six.assertCountEqual(self, os.listdir(test_corpus_directory),
                           ['123', '456', 'abc'])
    finally:
      if os.path.exists(test_corpus_directory):
        shutil.rmtree(test_corpus_directory, ignore_errors=True)

  def test_symbolize(self):
    """Test symbolize."""
    self._setup_env(job_type='job')
    self.assertIsNotNone(build_manager.setup_build())

    app_dir = environment.get_value('APP_DIR')
    unsymbolized_stacktrace = (
        '#0 0x4f1eb4  ({0}/app+0x4f1eb4)\n'
        '#1 0x4f206e  ({0}/app+0x4f206e)\n').format(app_dir)

    expected_symbolized_stacktrace = (
        '    #0 0x4f1eb4 in Vuln(char*, unsigned long) /usr/local/google/home/'
        'ochang/crashy_binary/test.cc:9:15\n'
        '    #1 0x4f206e in main /usr/local/google/home/ochang/crashy_binary/'
        'test.cc:32:3\n')
    symbolized_stacktrace = symbolize_host.symbolize_stacktrace(
        unsymbolized_stacktrace)
    self.assertEqual(expected_symbolized_stacktrace, symbolized_stacktrace)

  def test_update_data_bundle(self):
    """Test update_data_bundle."""
    self.mock.get_data_bundle_bucket_name.return_value = TEST_BUNDLE_BUCKET
    fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == 'fuzzer').get()
    bundle = data_types.DataBundle.query(
        data_types.DataBundle.name == 'bundle').get()

    self.assertTrue(setup.update_data_bundle(fuzzer, bundle))

    data_bundle_directory = file_host.rebase_to_worker_root(
        setup.get_data_bundle_directory('fuzzer'))
    self.assertTrue(os.path.exists(os.path.join(data_bundle_directory, 'a')))
    self.assertTrue(os.path.exists(os.path.join(data_bundle_directory, 'b')))

    self.assertTrue(setup.update_data_bundle(fuzzer, bundle))

  def test_get_fuzz_targets(self):
    """Test get_fuzz_targets."""
    worker_root = os.environ['WORKER_ROOT_DIR']
    worker_test_build_dir = os.path.join(
        worker_root, 'src', 'clusterfuzz', '_internal', 'tests', 'core', 'bot',
        'untrusted_runner', 'test_data', 'test_build')
    fuzz_target_paths = file_host.get_fuzz_targets(worker_test_build_dir)
    six.assertCountEqual(self, [
        os.path.join(worker_test_build_dir, 'do_stuff_fuzzer'),
        os.path.join(worker_test_build_dir, 'target'),
    ], fuzz_target_paths)

  def test_large_message(self):
    """Tests that large messages work."""
    expected_output = b'A' * 1024 * 1024 * 5 + b'\n'

    runner = remote_process_host.RemoteProcessRunner('/usr/bin/python3')
    result = runner.run_and_wait(
        additional_args=['-c', 'print("A"*5*1024*1024)'])
    self.assertEqual(result.return_code, 0)
    self.assertEqual(result.output, expected_output)

  def test_terminate_stale_application_instances(self):
    """Test terminating stale application instances."""
    # TODO(ochang): Improve this test once we use Docker.
    process_handler.terminate_stale_application_instances()

  def test_reset_environment(self):
    """Test resetting environment."""
    environment.set_value('ASAN_OPTIONS', 'saved_options')
    untrusted_env.reset_environment()
    environment.set_value('ASAN_OPTIONS', 'replaced')
    untrusted_env.reset_environment()

    runner = remote_process_host.RemoteProcessRunner('/bin/sh', ['-c'])
    result = runner.run_and_wait(['echo $ASAN_OPTIONS'])
    self.assertEqual(result.output, b'saved_options\n')

  # The "zzz" is a hack to make this test run last (tests are run in
  # alphabetical order).
  # TODO(ochang): Find a better way.
  def test_zzz_update(self):
    """Test updating."""
    host.update_worker()
    self.assertEqual(self.__class__.bot_proc.wait(), 0)
