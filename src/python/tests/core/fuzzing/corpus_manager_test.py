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
"""Tests for corpus_manager."""

from builtins import object
import datetime
import mock
import os
import unittest

from pyfakefs import fake_filesystem_unittest

from base import utils
from fuzzing import corpus_manager
from system import new_process
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class GcsCorpusTest(unittest.TestCase):
  """GcsCorpus tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'fuzzing.corpus_manager._count_corpus_files',
        'multiprocessing.cpu_count',
        'subprocess.Popen',
    ])

    self.mock.Popen.return_value.poll.return_value = 0
    self.mock.Popen.return_value.communicate.return_value = (None, None)
    self.mock._count_corpus_files.return_value = 1  # pylint: disable=protected-access

    os.environ['GSUTIL_PATH'] = '/gsutil_path'

  def test_rsync_to_disk(self):
    """Test rsync_to_disk."""
    self.mock.cpu_count.return_value = 1
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_to_disk('/dir', timeout=60))

    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-o', 'GSUtil:parallel_thread_count=16',
        '-q', 'rsync', '-r', '-d', 'gs://bucket/', '/dir'
    ])

    self.mock.cpu_count.return_value = 2
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_to_disk('/dir', timeout=60))
    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-q', 'rsync', '-r', '-d', 'gs://bucket/',
        '/dir'
    ])

  def test_rsync_from_disk(self):
    """Test rsync_from_disk."""
    self.mock.cpu_count.return_value = 1
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_from_disk('/dir'))

    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-o', 'GSUtil:parallel_thread_count=16',
        '-q', 'rsync', '-r', '-d', '/dir', 'gs://bucket/'
    ])

    self.mock.cpu_count.return_value = 2
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_from_disk('/dir'))
    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-q', 'rsync', '-r', '-d', '/dir',
        'gs://bucket/'
    ])

  def test_upload_files(self):
    """Test upload_files."""
    mock_popen = self.mock.Popen.return_value

    self.mock.cpu_count.return_value = 1
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.upload_files(['/dir/a', '/dir/b']))

    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-o', 'GSUtil:parallel_thread_count=16',
        'cp', '-I', 'gs://bucket/'
    ])

    mock_popen.communicate.assert_called_with('/dir/a\n/dir/b')

    self.mock.cpu_count.return_value = 2
    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.upload_files(['/dir/a', '/dir/b']))
    self.assertEqual(self.mock.Popen.call_args[0][0],
                     ['/gsutil_path/gsutil', '-m', 'cp', '-I', 'gs://bucket/'])


class RsyncErrorHandlingTest(unittest.TestCase):
  """Rsync error handling tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'fuzzing.corpus_manager._count_corpus_files',
        'google_cloud_utils.gsutil.GSUtilRunner.run_gsutil',
    ])

  def test_rsync_error_below_threshold(self):
    """Test rsync returning errors (but they're below threshold)."""
    output = (
        'blah\n'
        'blah\n'
        'CommandException: 10 files/objects could not be copied/removed.\n')

    self.mock._count_corpus_files.return_value = 10  # pylint: disable=protected-access
    self.mock.run_gsutil.return_value = new_process.ProcessResult(
        command=['/fake'],
        return_code=1,
        output=output,
        time_executed=10.0,
        timed_out=False,
    )

    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_to_disk('/dir', timeout=60))

    self.mock.run_gsutil.return_value = new_process.ProcessResult(
        command=['/fake'],
        return_code=1,
        output=output,
        time_executed=30.0,
        timed_out=True,
    )
    self.assertFalse(corpus.rsync_to_disk('/dir', timeout=60))

  def test_rsync_error_below_threshold_with_not_found_errors(self):
    """Test rsync returning errors (below threshold, but with not found errors
    and overall error count more than threshold)."""
    output = (
        'blah\n' +
        'NotFoundException: 404 gs://bucket/file001 does not exist.\n' * 190 +
        'CommandException: 200 files/objects could not be copied/removed.\n')

    self.mock._count_corpus_files.return_value = 10  # pylint: disable=protected-access
    self.mock.run_gsutil.return_value = new_process.ProcessResult(
        command=['/fake'],
        return_code=1,
        output=output,
        time_executed=10.0,
        timed_out=False,
    )

    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertTrue(corpus.rsync_to_disk('/dir', timeout=60))

    self.mock.run_gsutil.return_value = new_process.ProcessResult(
        command=['/fake'],
        return_code=1,
        output=output,
        time_executed=30.0,
        timed_out=True,
    )
    self.assertFalse(corpus.rsync_to_disk('/dir', timeout=60))

  def test_rsync_error_above_threshold(self):
    """Test rsync returning errors (above threshold)."""
    output = (
        'blah\n'
        'blah\n'
        'CommandException: 11 files/objects could not be copied/removed.\n')

    self.mock.run_gsutil.return_value = new_process.ProcessResult(
        command=['/fake'],
        return_code=1,
        output=output,
        time_executed=10.0,
        timed_out=False,
    )

    corpus = corpus_manager.GcsCorpus('bucket')
    self.assertFalse(corpus.rsync_to_disk('/dir', timeout=60))


class FuzzTargetCorpusTest(fake_filesystem_unittest.TestCase):
  """FuzzTargetCorpus tests."""

  def setUp(self):
    test_helpers.patch_environ(self)

    os.environ['GSUTIL_PATH'] = '/gsutil_path'
    os.environ['CORPUS_BUCKET'] = 'bucket'

    test_helpers.patch(self, [
        'fuzzing.corpus_manager._count_corpus_files',
        'multiprocessing.cpu_count',
        'subprocess.Popen',
    ])

    self.mock.Popen.return_value.poll.return_value = 0
    self.mock.Popen.return_value.communicate.return_value = (None, None)
    self.mock.cpu_count.return_value = 2
    self.mock._count_corpus_files.return_value = 1  # pylint: disable=protected-access
    test_utils.set_up_pyfakefs(self)
    self.fs.CreateDirectory('/dir')

  def test_rsync_to_disk(self):
    """Test rsync_to_disk."""
    corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'fuzzer')
    self.assertTrue(corpus.rsync_to_disk('/dir', timeout=60))

    commands = [call_arg[0][0] for call_arg in self.mock.Popen.call_args_list]

    self.assertEqual(commands, [
        [
            '/gsutil_path/gsutil',
            '-m',
            '-q',
            'rsync',
            '-r',
            '-d',
            'gs://bucket/libFuzzer/fuzzer/',
            '/dir',
        ],
        [
            '/gsutil_path/gsutil',
            '-m',
            '-q',
            'rsync',
            '-r',
            'gs://bucket/libFuzzer/fuzzer_static/',
            '/dir',
        ],
    ])

  def test_rsync_from_disk(self):
    """Test rsync_from_disk."""
    corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'fuzzer')
    self.assertTrue(corpus.rsync_from_disk('/dir'))

    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', '-q', 'rsync', '-r', '-d', '/dir',
        'gs://bucket/libFuzzer/fuzzer/'
    ])

  def test_upload_files(self):
    """Test upload_files."""
    mock_popen = self.mock.Popen.return_value

    corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'fuzzer')
    self.assertTrue(corpus.upload_files(['/dir/a', '/dir/b']))
    mock_popen.communicate.assert_called_with('/dir/a\n/dir/b')

    self.assertEqual(self.mock.Popen.call_args[0][0], [
        '/gsutil_path/gsutil', '-m', 'cp', '-I', 'gs://bucket/libFuzzer/fuzzer/'
    ])


class CorpusBackupTest(fake_filesystem_unittest.TestCase):
  """Corpus backup tests."""

  def _mock_make_archive(self, archive_path, backup_format, _):
    path = archive_path + '.' + backup_format
    self.fs.CreateFile(path)

    return path

  def setUp(self):
    test_helpers.patch_environ(self)

    test_utils.set_up_pyfakefs(self)
    self.fs.CreateDirectory('/dir')

    os.environ['GSUTIL_PATH'] = '/gsutil_path'
    os.environ['CORPUS_BUCKET'] = 'bucket'

    test_helpers.patch(self, [
        'base.utils.utcnow',
        'google_cloud_utils.storage.copy_blob',
        'google_cloud_utils.storage.copy_file_to',
        'multiprocessing.cpu_count',
        'shutil.make_archive',
    ])

    self.mock.copy_blob.return_value = True
    self.mock.copy_file_to.return_value = True
    self.mock.cpu_count.return_value = 2
    self.mock.make_archive.side_effect = self._mock_make_archive
    self.mock.utcnow.return_value = datetime.datetime(2017, 1, 1)

  def test_backup_corpus(self):
    """Test backup_corpus."""
    libfuzzer_corpus = corpus_manager.FuzzTargetCorpus('libFuzzer', 'fuzzer')

    corpus_manager.backup_corpus('backup_bucket', libfuzzer_corpus, '/dir')

    self.mock.copy_file_to.assert_has_calls([
        mock.call('/2017-01-01.zip',
                  'gs://backup_bucket/corpus/libFuzzer/fuzzer/2017-01-01.zip')
    ])

    self.mock.copy_blob.assert_has_calls([
        mock.call('gs://backup_bucket/corpus/libFuzzer/fuzzer/2017-01-01.zip',
                  'gs://backup_bucket/corpus/libFuzzer/fuzzer/latest.zip'),
    ])


class FileMixin(object):
  """Mixin with a setUp implementation and attributes that are useful for test
  classes dealing with cleaning filenames for Windows."""
  # Make the content greater than chunk size.
  FILE_CONTENTS = 'hello' * 30000
  FILE_SHA1SUM = 'bf720c91eb988c589a486407d7912da17bdb201f'
  DIRECTORY = '/corpus'
  FILE_PATH = os.path.join(DIRECTORY, 'illegaly:named:file')

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir(self.DIRECTORY)
    self.fs.create_file(self.FILE_PATH, contents=self.FILE_CONTENTS)


class FileHashTest(FileMixin, fake_filesystem_unittest.TestCase):
  """Tests utils.file_hash works as expected."""

  def test_sha1sum(self):
    """Test that the correct sha1sum is calculated."""
    self.assertEqual(self.FILE_SHA1SUM, utils.file_hash(self.FILE_PATH))


class LegalizeFilenamesTest(FileMixin, fake_filesystem_unittest.TestCase):
  """Tests for legalize_filenames."""

  def test_rename_illegal(self):
    """Test that illegally named files are renamed."""
    legally_named = corpus_manager.legalize_filenames([self.FILE_PATH])
    self.assertEqual([os.path.join(self.DIRECTORY, self.FILE_SHA1SUM)],
                     [file_path for file_path in legally_named])
    with open(os.path.join(self.DIRECTORY, self.FILE_SHA1SUM)) as file_handle:
      self.assertEqual(self.FILE_CONTENTS, file_handle.read())

  def test_does_not_rename_legal(self):
    """Test that legally named files are not renamed."""
    new_file_path_1 = os.path.join(self.DIRECTORY, 'new_file')
    os.rename(self.FILE_PATH, new_file_path_1)
    initial_files = os.listdir(self.DIRECTORY)
    new_file_path_2 = '/other_new_file'
    initial_files.append(new_file_path_2)
    legal_files = corpus_manager.legalize_filenames(initial_files)
    self.assertEqual(initial_files, legal_files)
    with open(new_file_path_1) as file_handle:
      self.assertEqual(self.FILE_CONTENTS, file_handle.read())

  def test_logs_errors(self):
    """Test that errors are logged when we fail to rename a file."""
    test_helpers.patch(self, ['shutil.move', 'metrics.logs.log_error'])

    def mock_move(*args, **kwargs):  # pylint: disable=unused-argument
      raise OSError

    self.mock.move.side_effect = mock_move
    legal_files = corpus_manager.legalize_filenames([self.FILE_PATH])
    self.assertEqual([], legal_files)
    failed_to_move_files = [(self.FILE_PATH,
                             os.path.join(self.DIRECTORY, self.FILE_SHA1SUM))]

    self.mock.log_error.assert_called_with(
        'Failed to rename files.', failed_to_move_files=failed_to_move_files)
