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
"""utils tests."""
import datetime
import os
import shutil
import sys
import tempfile
import time
import unittest

from google.cloud import ndb
import mock
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GetSizeStringTest(unittest.TestCase):
  """Test get_size_string."""

  def test_size_bytes(self):
    """Test size returned in bytes."""
    self.assertEqual(utils.get_size_string(10), '10 B')
    self.assertEqual(utils.get_size_string(1023), '1023 B')

  def test_size_kilobytes(self):
    """Test size returned in kilobytes."""
    self.assertEqual(utils.get_size_string(1024), '1 KB')
    self.assertEqual(utils.get_size_string(1048575), '1023 KB')

  def test_size_megabytes(self):
    """Test size returned in megabytes."""
    self.assertEqual(utils.get_size_string(1048576), '1 MB')
    self.assertEqual(utils.get_size_string(1073741823), '1023 MB')

  def test_size_gigabytes(self):
    """Test size returned in gigabytes."""
    self.assertEqual(utils.get_size_string(1073741824), '1 GB')
    self.assertEqual(utils.get_size_string(5000000000), '4 GB')


class GetLineCountString(unittest.TestCase):
  """Test get_line_count_string."""

  def test_line_count_0(self):
    """Test line count string for 0 lines."""
    self.assertEqual(utils.get_line_count_string(0), 'empty')

  def test_line_count_1(self):
    """Test line count string for 1 line."""
    self.assertEqual(utils.get_line_count_string(1), '1 line')

  def test_line_count_10(self):
    """Test line count string for more than 1 line."""
    self.assertEqual(utils.get_line_count_string(10), '10 lines')


@test_utils.with_cloud_emulators('datastore')
class HashTest(unittest.TestCase):
  """Tests for hash helper functions."""

  class DummyEntity(ndb.Model):
    string_property = ndb.StringProperty()
    datetime_property = ndb.DateTimeProperty()
    integer_property = ndb.IntegerProperty()

  def setUp(self):
    entity_1 = HashTest.DummyEntity()
    entity_1.string_proprety = 'abc'
    entity_1.datetime_property = datetime.datetime(2018, 1, 1)
    entity_1.integer_property = 1
    entity_1.put()

    entity_2 = HashTest.DummyEntity()
    entity_2.string_proprety = 'abcd'
    entity_2.datetime_property = datetime.datetime(2018, 1, 1)
    entity_2.integer_property = 2
    entity_2.put()

  def test_hash_equal_for_identical_entities(self):
    """Ensure that two equivalent entities have the same hash value."""
    entity_1 = HashTest.DummyEntity.query(
        HashTest.DummyEntity.integer_property == 1).get()
    hash_1 = utils.entity_hash(entity_1)

    entity_2 = HashTest.DummyEntity.query(
        HashTest.DummyEntity.integer_property == 1).get()
    hash_2 = utils.entity_hash(entity_2)

    self.assertEqual(hash_1, hash_2)

  def test_hash_different_for_different_entities(self):
    """Ensure that two different entities have different hash values."""
    entity_1 = HashTest.DummyEntity.query(
        HashTest.DummyEntity.integer_property == 1).get()
    hash_1 = utils.entity_hash(entity_1)

    entity_2 = HashTest.DummyEntity.query(
        HashTest.DummyEntity.integer_property == 2).get()
    hash_2 = utils.entity_hash(entity_2)

    self.assertNotEqual(hash_1, hash_2)


@test_utils.integration
class TimeoutTest(unittest.TestCase):
  """Test timeout decorator."""

  def setUp(self):
    self.real_time_sleep = time.sleep

    patcher = mock.patch('time.sleep', autospec=True)
    self.time_sleep = patcher.start()
    self.addCleanup(patcher.stop)

  @utils.timeout(1)
  def _func(self, duration):
    self.real_time_sleep(duration)

  def test_exceed_timeout(self):
    """Test function that executes longer than the timeout."""
    self._func(0)

    with self.assertRaises(SystemExit):
      self._func(5)

  @utils.timeout(5)
  @utils.timeout(5)
  def _nested_func(self):
    pass

  def test_nested_does_not_deadlock(self):
    """Test nesting the timeout decorator doesn't cause a deadlock."""
    self._nested_func()


class FilePathToFileUrlTest(unittest.TestCase):
  """Tests file_path_to_file_url."""

  def test_empty(self):
    """Tests empty path."""
    self.assertEqual('', utils.file_path_to_file_url(''))

  def test_window_prefix(self):
    """Tests path with windows prefix."""
    self.assertIn(
        utils.file_path_to_file_url('\\\\?\\c:\\test\\test2.html'),
        [
            'file:///c:/test/test2.html',  # On windows.
            'file:///c%3A%5Ctest%5Ctest2.html',  # On Posix.
        ])


class NormalizePathTest(unittest.TestCase):
  """Tests normalize_path."""

  def test_redundant_path(self):
    """Tests redundant paths."""
    self.assertEqual('/test/test2/test3',
                     utils.normalize_path('/test/./test2/test3'))
    self.assertEqual('/test/test2/test3',
                     utils.normalize_path('/test//test2/test3'))

  def test_normalize_case(self):
    """Tests normalize case for windows."""
    if sys.platform.startswith('win'):
      self.assertEqual(
          utils.normalize_path('C:\\test\\test2\\test3'),
          # Notice that the path starts with a lowercase c.
          utils.normalize_path('c:\\test\\test2\\test3'))
    else:
      self.assertEqual('/mnt/Test', utils.normalize_path('/mnt/Test'))


class NormalizeEmailTest(unittest.TestCase):
  """Tests email normalization."""

  def test_normalize_email(self):
    """Test normalize email."""
    self.assertEqual('a@b.com', utils.normalize_email('a@b.com'))
    self.assertEqual('a@b.com', utils.normalize_email('A@B.com'))

  def test_email_equals(self):
    """Test email comparison."""
    self.assertTrue(utils.emails_equal('a@b.com', 'a@b.com'))
    self.assertTrue(utils.emails_equal('A@b.com', 'a@B.com'))


class RandomWeightedChoiceTest(unittest.TestCase):
  """Tests random_weighted_choice."""

  def setUp(self):
    helpers.patch(self, ['random.SystemRandom.uniform'])

    class O(object):

      def __init__(self, data, weight):
        self.data = data
        self.weight = weight

    self.list = [O('A1', 0), O('A2', 1), O('A3', 3), O('A4', 0), O('A5', 5)]

  def test_1(self):
    self.mock.uniform.return_value = 0
    self.assertNotEqual('A1', utils.random_weighted_choice(self.list).data)

  def test_2(self):
    self.mock.uniform.return_value = 0
    self.assertEqual('A2', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 0.4
    self.assertEqual('A2', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 1
    self.assertEqual('A2', utils.random_weighted_choice(self.list).data)

  def test_3(self):
    self.mock.uniform.return_value = 1.1
    self.assertEqual('A3', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 2
    self.assertEqual('A3', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 4
    self.assertEqual('A3', utils.random_weighted_choice(self.list).data)

  def test_4(self):
    self.mock.uniform.return_value = 4.1
    self.assertNotEqual('A4', utils.random_weighted_choice(self.list).data)

  def test_5(self):
    self.mock.uniform.return_value = 4.1
    self.assertEqual('A5', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 7
    self.assertEqual('A5', utils.random_weighted_choice(self.list).data)

    self.mock.uniform.return_value = 9
    self.assertEqual('A5', utils.random_weighted_choice(self.list).data)


class GetCrashStacktraceOutputTest(unittest.TestCase):
  """Tests get_crash_stacktrace_output."""

  def setUp(self):
    helpers.patch_environ(self)

    os.environ['TOOL_NAME'] = 'ASAN'
    os.environ['JOB_NAME'] = 'linux_asan_chrome'

    self.start_separator = '+' + '-' * 40
    self.end_separator = '-' * 40 + '+'

  def test_env_settings(self):
    """Tests that environment settings are added."""
    os.environ['ASAN_OPTIONS'] = 'setting1=value1:setting2=value_2'
    self.assertEqual(
        '[Environment] ASAN_OPTIONS=setting1=value1:setting2=value_2\n'
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Release Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output('cmd_line', 'sym_stack'))

  def test_release_sym_stack(self):
    """Tests release build with a symbolized stack, with build type not
    explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line_release\n\n' + self.start_separator +
        'Release Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output('cmd_line_release', 'sym_stack'))

  def test_debug_sym_stack(self):
    """Tests debug build with a symbolized stack, with build type explicitly
    passed."""
    self.assertEqual(
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Debug Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output(
            'cmd_line', 'sym_stack', build_type='debug'))

  def test_debug_sym_stack_2(self):
    """Tests debug build with a symbolized stack, with build type not explicitly
    passed."""
    self.assertEqual(
        '[Command line] cmd_line_dbg\n\n' + self.start_separator +
        'Debug Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output('cmd_line_dbg', 'sym_stack'))

  def test_stable_sym_stack(self):
    """Tests stable build with a symbolized stack, with build type not
    explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line_stable\n\n' + self.start_separator +
        'Stable Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output('cmd_line_stable', 'sym_stack'))

  def test_beta_sym_stack(self):
    """Tests beta build with a symbolized stack, with build type not
    explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line_beta\n\n' + self.start_separator +
        'Beta Build Stacktrace' + self.end_separator + '\nsym_stack',
        utils.get_crash_stacktrace_output('cmd_line_beta', 'sym_stack'))

  def test_release_sym_and_unsym_stacks(self):
    """Tests release build with symbolized and unsymbolized stacks, with build
    type not explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Release Build Stacktrace' + self.end_separator + '\nsym_stack\n\n' +
        self.start_separator + 'Release Build Unsymbolized Stacktrace (diff)' +
        self.end_separator + '\n\nunsym_stack',
        utils.get_crash_stacktrace_output('cmd_line', 'sym_stack',
                                          'unsym_stack'))

  def test_debug_sym_and_unsym_stacks(self):
    """Tests debug build with symbolized and unsymbolized stacks, with build
    type explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Debug Build Stacktrace' + self.end_separator + '\nsym_stack\n\n' +
        self.start_separator + 'Debug Build Unsymbolized Stacktrace (diff)' +
        self.end_separator + '\n\nunsym_stack',
        utils.get_crash_stacktrace_output(
            'cmd_line', 'sym_stack', 'unsym_stack', build_type='debug'))

  def test_release_sym_and_unsym_diff_stacks(self):
    """Tests release build with symbolized and unsymbolized stacks, having some
    common frames, and build type not explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Release Build Stacktrace' + self.end_separator +
        '\nc1\nc2\nc3\nsym_stack\nc4\nc5\nc6\n\n' + self.start_separator +
        'Release Build Unsymbolized Stacktrace (diff)' + self.end_separator +
        '\n\nc2\nc3\nunsym_stack\nc4\nc5',
        utils.get_crash_stacktrace_output(
            'cmd_line', 'c1\nc2\nc3\nsym_stack\nc4\nc5\nc6',
            'c1\nc2\nc3\nunsym_stack\nc4\nc5\nc6'))

  def test_debug_sym_and_unsym_diff_stacks(self):
    """Tests debug build with symbolized and unsymbolized stacks, having some
    common frames, and build type explicitly passed."""
    self.assertEqual(
        '[Command line] cmd_line\n\n' + self.start_separator +
        'Debug Build Stacktrace' + self.end_separator +
        '\nc1\nc2\nc3\nsym_stack\nc4\nc5\nc6\n\n' + self.start_separator +
        'Debug Build Unsymbolized Stacktrace (diff)' + self.end_separator +
        '\n\nc2\nc3\nunsym_stack\nc4\nc5',
        utils.get_crash_stacktrace_output(
            'cmd_line',
            'c1\nc2\nc3\nsym_stack\nc4\nc5\nc6',
            'c1\nc2\nc3\nunsym_stack\nc4\nc5\nc6',
            build_type='debug'))


class GetApplicationIDTest(unittest.TestCase):
  """Tests get_application_id."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_no_app_id(self):
    """Test with no app id set in environment."""
    del os.environ['APPLICATION_ID']
    self.assertEqual(None, utils.get_application_id())

  def test_simple_app_id(self):
    """Test simple app id without domain or partition separator."""
    os.environ['APPLICATION_ID'] = 'app_id'
    self.assertEqual('app_id', utils.get_application_id())

  def test_app_id_with_partition(self):
    """Test app id with partition separator, but no domain separator."""
    os.environ['APPLICATION_ID'] = 'dev~app_id'
    self.assertEqual('app_id', utils.get_application_id())

  def test_app_id_with_domain(self):
    """Test app id with domain separator, but no partition separator."""
    os.environ['APPLICATION_ID'] = 'company:app_id'
    self.assertEqual('company:app_id', utils.get_application_id())

  def test_app_id_with_domain_and_partition(self):
    """Test app id with domain and partition separator."""
    os.environ['APPLICATION_ID'] = 's~company:app_id'
    self.assertEqual('company:app_id', utils.get_application_id())


class DefaultProjectNameTest(unittest.TestCase):
  """Tests default_project_name."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_default(self):
    """Test that it returns default project with no environment changes."""
    self.assertEqual('test-project', utils.default_project_name())

  def test_overridden(self):
    """Test that env variable PROJECT_NAME does not affect default project
    name and we still default project."""
    os.environ['PROJECT_NAME'] = 'other-project'
    self.assertEqual('test-project', utils.default_project_name())


class CurrentProjectTest(unittest.TestCase):
  """Tests current_project."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_default(self):
    """Test that it returns default project with no environment changes."""
    self.assertEqual('test-project', utils.current_project())

  def test_overridden(self):
    """Test that env variable PROJECT_NAME is used for current project."""
    os.environ['PROJECT_NAME'] = 'other-project'
    self.assertEqual('other-project', utils.current_project())


class FileHashTest(fake_filesystem_unittest.TestCase):
  """Test file_hash."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.test_file = '/test'

  def test_empty_string(self):
    with open(self.test_file, 'wb'):
      pass
    self.assertEqual('da39a3ee5e6b4b0d3255bfef95601890afd80709',
                     utils.file_hash(self.test_file))

  def test_shorter_than_one_chunk(self):
    with open(self.test_file, 'wb') as file_handle:
      file_handle.write(b'ABC')
    self.assertEqual('3c01bdbb26f358bab27f267924aa2c9a03fcfdb8',
                     utils.file_hash(self.test_file))

  def test_longer_than_one_chunk(self):
    with open(self.test_file, 'wb') as file_handle:
      file_handle.write(b'A' * 60000)
    self.assertEqual('8360c01cef8aa7001d1dd8964b9921d4c187da29',
                     utils.file_hash(self.test_file))


class ServiceAccountEmailTest(unittest.TestCase):
  """Tests service_account_email"""

  def setUp(self):
    helpers.patch_environ(self)

  def test_plain_project_id(self):
    """Test with a plain project ID."""
    os.environ['APPLICATION_ID'] = 'project-id'
    self.assertEqual('project-id@appspot.gserviceaccount.com',
                     utils.service_account_email())

  def test_with_domain(self):
    """Test with a project ID with a domain."""
    os.environ['APPLICATION_ID'] = 'domain.com:project-id'
    self.assertEqual('project-id.domain.com@appspot.gserviceaccount.com',
                     utils.service_account_email())


class SearchBytesInFileTest(unittest.TestCase):
  """Tests search_bytes_in_file."""

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp()
    self.test_path = os.path.join(self.temp_dir, 'file')
    with open(self.test_path, 'wb') as f:
      f.write(b'A' * 16 + b'B' * 16 + b'C' + b'D' * 16)

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_exists(self):
    """Test exists."""
    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'A', f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'B', f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'C', f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'D', f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'A' * 16, f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'B' * 16, f))

    with open(self.test_path, 'rb') as f:
      self.assertTrue(utils.search_bytes_in_file(b'D' * 16, f))

  def test_not_exists(self):
    """Test not exists."""
    with open(self.test_path, 'rb') as f:
      self.assertFalse(utils.search_bytes_in_file(b'A' * 17, f))

    with open(self.test_path, 'rb') as f:
      self.assertFalse(utils.search_bytes_in_file(b'B' * 17, f))

    with open(self.test_path, 'rb') as f:
      self.assertFalse(utils.search_bytes_in_file(b'C' * 2, f))

    with open(self.test_path, 'rb') as f:
      self.assertFalse(utils.search_bytes_in_file(b'D' * 17, f))

    with open(self.test_path, 'rb') as f:
      self.assertFalse(utils.search_bytes_in_file(b'ABCD', f))
