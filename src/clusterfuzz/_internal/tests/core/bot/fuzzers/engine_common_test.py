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
"""Tests fuzzers.engine_common."""

import os
import unittest

import parameterized
from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class GetIssueOwnersTest(fake_filesystem_unittest.TestCase):
  """get_issue_owners tests."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/test')

  def test_no_file(self):
    self.assertEqual([], engine_common.get_issue_owners('/test/does_not_exist'))

  def test_empty_file(self):
    self.fs.create_file('/test/fuzz_target.owners', contents='')
    self.assertEqual([], engine_common.get_issue_owners('/test/fuzz_target'))

  def test_all_allowed(self):
    self.fs.create_file('/test/fuzz_target.owners', contents='*')
    self.assertEqual([], engine_common.get_issue_owners('/test/fuzz_target'))

  def test_sections(self):
    """Test sections."""
    self.fs.create_file(
        '/test/fuzz_target.owners',
        contents=('file://ENG_REVIEW_OWNERS\n'
                  '  \n'
                  '#ignore me\n'
                  'dev1@example.com\n'
                  '\n'
                  'per-file PRESUBMIT*.py=dev2@chromium.org\n'
                  'dev3@example.com\n'
                  '  dev4@example.com    \n'))
    self.assertEqual(
        ['dev1@example.com', 'dev3@example.com', 'dev4@example.com'],
        engine_common.get_issue_owners('/test/fuzz_target'))
    self.assertEqual(
        ['dev1@example.com', 'dev3@example.com', 'dev4@example.com'],
        engine_common.get_issue_owners('/test/fuzz_target.exe'))


class GetIssueLabelsTest(fake_filesystem_unittest.TestCase):
  """get_issue_labels tests."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/test')

  def test_no_file(self):
    """Test no labels file."""
    self.assertEqual([], engine_common.get_issue_labels('/test/does_not_exist'))

  def test_empty_file(self):
    """Test empty file."""
    self.fs.create_file('/test/fuzz_target.labels', contents='')
    self.assertEqual([], engine_common.get_issue_labels('/test/fuzz_target'))

  def test_well_formed(self):
    """Test well formed labels file."""
    self.fs.create_file(
        '/test/fuzz_target.labels', contents='label1\nlabel2\nlabel3\n')
    self.assertEqual(['label1', 'label2', 'label3'],
                     engine_common.get_issue_labels('/test/fuzz_target'))

  def test_empty_lines(self):
    """Test labels file with empty lines."""
    self.fs.create_file(
        '/test/fuzz_target.labels', contents='label1\n\t\nlabel2\n \nlabel3\n')
    self.assertEqual(['label1', 'label2', 'label3'],
                     engine_common.get_issue_labels('/test/fuzz_target'))


class GetTimeoutTestBase(unittest.TestCase):
  """Base class providing common functionality for TestCases that test the
  get_*_timeout() functions."""

  @staticmethod
  def function():
    raise NotImplementedError(
        'Children must override function() to use helper functions')

  def setUp(self):
    test_helpers.patch_environ(self)
    self.valid_hard_timeout = 500
    self.valid_merge_timeout = 15

  def _set_environment_values(self, environment_variable_values):
    """Set environment variable values based on the key, value pairs in
    |environment_variable_values|.
    """
    for key, value in six.iteritems(environment_variable_values):
      environment.set_value(key, value)

  def validation_helper(self, environment_variable_values):
    """Call self.function() and assert that it throws an AssertionError. Set
    environment variables based on |environment_variable_values| before calling
    self.function.
    """
    self._set_environment_values(environment_variable_values)
    with self.assertRaises(AssertionError):
      self.function()

  def call_helper(self, expected_value, environment_variable_values):
    """Test that self.function() == expected_value. Use
    |environment_variable_values| to mock environment.get_value before calling
    self.function."""
    self._set_environment_values(environment_variable_values)
    self.assertEqual(expected_value, self.function())


class GetHardTimeoutTest(GetTimeoutTestBase):
  """Get hard timeout tests."""
  # Use staticmethod to prevent python from passing self to
  # GetHardTimeoutTest.function().
  @staticmethod
  def function():
    return engine_common.get_hard_timeout()

  def test_hard_timeout_override_validation(self):
    """Test that get_hard_timeout rejects invalid values of
    HARD_TIMEOUT_OVERRIDE."""
    # Test that a negative HARD_TIMEOUT_OVERRIDE is rejected.
    self.validation_helper({
        'FUZZ_TEST_TIMEOUT': self.valid_hard_timeout,
        'HARD_TIMEOUT_OVERRIDE': -1
    })

  def test_hard_timeout_override_correctness(self):
    """Test that get_hard_timeout returns what we expect when we set
    HARD_TIMEOUT_OVERRIDE."""
    self.call_helper(self.valid_hard_timeout, {
        'HARD_TIMEOUT_OVERRIDE': self.valid_hard_timeout,
        'FUZZ_TEST_TIMEOUT': -1
    })

  def test_fuzz_test_timeout_correctness(self):
    """Test that get_hard_timeout returns what we expect when we set
    FUZZ_TEST_TIMEOUT."""
    self.call_helper(self.valid_hard_timeout,
                     {'FUZZ_TEST_TIMEOUT': self.valid_hard_timeout})


class GetMergeTimeoutTest(GetTimeoutTestBase):
  """Get merge timeout tests."""

  @staticmethod
  def function():
    return

  def test_validation(self):
    """Test that get_merge_timeout rejects invalid values of
    MERGE_TIMEOUT_OVERRIDE."""
    self._set_environment_values({
        'HARD_TIMEOUT_OVERRIDE': self.valid_hard_timeout,
        'MERGE_TIMEOUT_OVERRIDE': -1
    })

    with self.assertRaises(AssertionError):
      engine_common.get_merge_timeout(self.valid_merge_timeout)

  def test_correctness(self):
    """Test that get_merge_timeout returns what we expect."""
    # Basic sanity test.
    self.assertEqual(self.valid_merge_timeout,
                     engine_common.get_merge_timeout(self.valid_merge_timeout))

    # Test override works.
    override = 10
    self._set_environment_values({'MERGE_TIMEOUT_OVERRIDE': override})
    self.assertEqual(override,
                     engine_common.get_merge_timeout(self.valid_merge_timeout))


class FindFuzzerPathTest(fake_filesystem_unittest.TestCase):
  """find_fuzzer_path tests."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    test_helpers.patch_environ(self)
    self.build_dir = '/test'
    self.fuzzer_name = 'fuzz_target'
    self.fs.create_dir(self.build_dir)

  def _setup_fuzzer(self, fuzzer_name=None):
    """Create a file to represent the fuzzer."""
    if fuzzer_name is None:
      fuzzer_name = self.fuzzer_name
    fuzzer_path = os.path.join(self.build_dir, fuzzer_name)
    self.fs.create_file(fuzzer_path)
    return fuzzer_path

  def _find_fuzzer_path(self, fuzzer_name=None):
    """Return the result of a call to find_fuzzer_path with standard arguments.
    """
    if fuzzer_name is None:
      fuzzer_name = self.fuzzer_name
    return engine_common.find_fuzzer_path(self.build_dir, fuzzer_name)

  def test_finds_fuzzer(self):
    """Test common case of finding fuzzer in root of build directory."""
    self.assertEqual(self._setup_fuzzer(), self._find_fuzzer_path())

  def test_finds_fuzzer_with_legacy_prefix(self):
    """Test finding fuzzer, with legacy prefix."""
    environment.set_value('PROJECT_NAME', 'chromeos')
    self.assertEqual(self._setup_fuzzer(), self._find_fuzzer_path())

  def test_finds_fuzzer_with_legacy_prefix_in_name_and_env(self):
    """Test finding fuzzer, when legacy is set to the prefix in
    fuzzer_name."""
    environment.set_value('PROJECT_NAME', 'chromeos')
    fuzzer_name = 'chromeos_' + self.fuzzer_name
    self.assertEqual(
        self._setup_fuzzer(fuzzer_name), self._find_fuzzer_path(fuzzer_name))

  def test_only_finds_file(self):
    """Test that a directory is never returned."""
    self.fs.create_dir(os.path.join(self.build_dir, self.fuzzer_name))
    self.assertIsNone(self._find_fuzzer_path())

  def test_no_build_directory(self):
    """Test that no exception occurs when there is no build directory set."""
    self.assertIsNone(engine_common.find_fuzzer_path(None, self.fuzzer_name))


class GetStrategyProbabilityTest(unittest.TestCase):
  """Tests get_strategy_probability."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_default_probability(self):
    """Test default probability is returned when |FUZZING_STRATEGIES| is not
    set."""
    self.assertEqual(0.33, engine_common.get_strategy_probability('foo', 0.33))

  def test_env_var_not_dict(self):
    """Test default probability is returned when |FUZZING_STRATEGIES| is not
     a dict."""
    environment.set_value('FUZZING_STRATEGIES', 'bad')
    self.assertEqual(0.33, engine_common.get_strategy_probability('foo', 0.33))

  def test_strategy_not_specified(self):
    """Test 0.0 weight is return when strategy is not defined in
    |FUZZING_STRATEGIES|."""
    environment.set_value('FUZZING_STRATEGIES',
                          '{"strategy_1": 0.5, "strategy_3": 0.3}')
    self.assertEqual(0.0,
                     engine_common.get_strategy_probability('strategy_2', 0.33))

  def test_strategy_specified(self):
    """Test weight is returned when strategy is defined in
    |FUZZING_STRATEGIES|."""
    environment.set_value('FUZZING_STRATEGIES',
                          '{"strategy_1": 0.5, "strategy_3": 1.0}')
    self.assertEqual(0.5,
                     engine_common.get_strategy_probability('strategy_1', 0.33))
    self.assertEqual(1.0,
                     engine_common.get_strategy_probability('strategy_3', 0.33))


class GetSeedCorpusPath(fake_filesystem_unittest.TestCase):
  """Tests get_seed_corpus_path."""
  FUZZ_TARGET_PATH = '/fuzz_target'
  FUZZ_TARGET_PATH_WITH_EXTENSION = FUZZ_TARGET_PATH + '.exe'

  def setUp(self):
    self.archive_path_without_extension = (
        self.FUZZ_TARGET_PATH + engine_common.SEED_CORPUS_ARCHIVE_SUFFIX)
    test_utils.set_up_pyfakefs(self)

  def _create_seed_corpus(self, extension):
    seed_corpus_archive_path = self.archive_path_without_extension + extension
    self.fs.create_file(seed_corpus_archive_path)
    return seed_corpus_archive_path

  def _get_seed_corpus_path(self, fuzz_target_path):
    return engine_common.get_seed_corpus_path(fuzz_target_path)

  @parameterized.parameterized.expand([
      ('.zip', FUZZ_TARGET_PATH),
      ('.tar.gz', FUZZ_TARGET_PATH),
      ('.zip', FUZZ_TARGET_PATH_WITH_EXTENSION),
      ('.tar.gz', FUZZ_TARGET_PATH_WITH_EXTENSION),
  ])
  def test_get_archive(self, extension, fuzz_target_path):
    """Tests that get_seed_corpus_path can find a seed corpus with
    |extension|."""
    self.assertEqual(
        self._create_seed_corpus(extension),
        self._get_seed_corpus_path(fuzz_target_path))

  @parameterized.parameterized.expand(
      [FUZZ_TARGET_PATH, FUZZ_TARGET_PATH_WITH_EXTENSION])
  def test_multiple_corpora(self, fuzz_target_path):
    """Tests that the function logs an error when target has multiple seed
    corpora."""
    test_helpers.patch(self, ['clusterfuzz._internal.metrics.logs.log_error'])
    self._create_seed_corpus('.tar.gz')
    self._create_seed_corpus('.zip')
    self.assertIsNotNone(self._get_seed_corpus_path(fuzz_target_path))
    self.assertEqual(self.mock.log_error.call_count, 1)

  @parameterized.parameterized.expand(
      [FUZZ_TARGET_PATH, FUZZ_TARGET_PATH_WITH_EXTENSION])
  def test_no_seed_corpus(self, fuzz_target_path):
    """Tests that the function returns None when target has no seed corpus."""
    self.assertIsNone(self._get_seed_corpus_path(fuzz_target_path))

  @parameterized.parameterized.expand(
      [FUZZ_TARGET_PATH, FUZZ_TARGET_PATH_WITH_EXTENSION])
  def test_invalid_extension(self, fuzz_target_path):
    """Tests that the function returns None when target has a seed corpus with
    an invalid file extension."""
    self._create_seed_corpus('.tar.invalid')
    self.assertIsNone(self._get_seed_corpus_path(fuzz_target_path))


class UnpackSeedCorpusIfNeededTest(fake_filesystem_unittest.TestCase):
  """Tests for unpack_seed_corpus_if_needed."""
  CORPUS_DIRECTORY = '/corpus'
  FUZZ_TARGET_PATH = '/fuzz_target'
  NUM_CORPUS_FILES = engine_common.MAX_FILES_FOR_UNPACK + 1

  def setUp(self):
    """Setup for unpack seed corpus if needed test."""
    self.data_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'data')

    zip_seed_corpus_path = os.path.join(self.data_path, 'seed_corpus.zip')
    with open(zip_seed_corpus_path, 'rb') as zip_seed_corpus_handle:
      self.zip_seed_corpus_contents = zip_seed_corpus_handle.read()

    targz_seed_corpus_path = os.path.join(self.data_path, 'seed_corpus.tar.gz')
    with open(targz_seed_corpus_path, 'rb') as targz_seed_corpus_handle:
      self.targz_seed_corpus_contents = targz_seed_corpus_handle.read()

    seed_corpus_with_subdirectories_path = os.path.join(
        self.data_path, 'seed_corpus_with_subdirectories.zip')
    with open(seed_corpus_with_subdirectories_path, 'rb') as seed_corpus_handle:
      self.seed_corpus_subdirs_contents = seed_corpus_handle.read()

    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir(self.CORPUS_DIRECTORY)

  def _unpack_seed_corpus_if_needed(self, *args, **kwargs):
    return engine_common.unpack_seed_corpus_if_needed(
        self.FUZZ_TARGET_PATH, self.CORPUS_DIRECTORY, *args, **kwargs)

  def _list_corpus_dir(self):
    return os.listdir(self.CORPUS_DIRECTORY)

  def _assert_elements_equal(self, l1, l2):
    """Assert that the elements of |l1| and |l2| are equal. Modifies |l1| and
    |l2| by sorting them."""
    self.assertEqual(list(sorted(l1)), list(sorted(l2)))

  def _write_seed_corpus(self, data, extension):
    """Writes an archive seed corpus to the proper location."""
    seed_corpus_path = (
        self.FUZZ_TARGET_PATH + engine_common.SEED_CORPUS_ARCHIVE_SUFFIX +
        extension)

    with open(seed_corpus_path, 'wb+') as seed_corpus_handle:
      seed_corpus_handle.write(data)

  def _create_corpus_files(self, num_files):
    """Creates |num_files| files in the corpus directory."""
    filenames = []
    for file_num in range(num_files):
      file_num = str(file_num)
      self.fs.create_file(os.path.join(self.CORPUS_DIRECTORY, file_num))
      filenames.append(file_num)
    return filenames

  def test_no_seed_corpus(self):
    """Test that unpack_seed_corpus_if_needed does nothing when there is no seed
    corpus."""
    self._unpack_seed_corpus_if_needed()
    self._assert_elements_equal([], self._list_corpus_dir())

  def test_unpack_zip_seed_corpus_if_needed(self):
    """Tests unpack_seed_corpus_if_needed can unpack a seed corpus."""
    self._write_seed_corpus(self.zip_seed_corpus_contents, extension='.zip')
    expected_dir_contents = [
        '0000000000000000', '0000000000000001', '0000000000000002'
    ]
    self._unpack_seed_corpus_if_needed()
    self._assert_elements_equal(expected_dir_contents, self._list_corpus_dir())

  def test_unpack_targz_seed_corpus_if_needed(self):
    """Tests unpack_seed_corpus_if_needed can unpack a seed corpus."""
    self._write_seed_corpus(self.targz_seed_corpus_contents, '.tar.gz')
    expected_dir_contents = [
        '0000000000000000', '0000000000000001', '0000000000000002'
    ]
    self._unpack_seed_corpus_if_needed()
    self._assert_elements_equal(expected_dir_contents, self._list_corpus_dir())

  def test_max_files_for_unpack(self):
    """Tests unpack_seed_corpus_if_needed does not unpack a seed corpus if there
    are more than enough files in the corpus directory."""
    self._write_seed_corpus(self.zip_seed_corpus_contents, '.zip')
    corpus_files = self._create_corpus_files(self.NUM_CORPUS_FILES)
    self._unpack_seed_corpus_if_needed()
    self._assert_elements_equal(corpus_files, self._list_corpus_dir())

  def test_force_unpack(self):
    """Tests unpack_seed_corpus_if_needed unpacks a seed corpus even if there
    are more than files in the corpus directory, when the |force_unpack|
    argument is True."""
    self._write_seed_corpus(self.zip_seed_corpus_contents, '.zip')
    initial_corpus_files = self._create_corpus_files(self.NUM_CORPUS_FILES)
    seed_corpus_files = [
        '0000000000000000', '0000000000000001', '0000000000000002'
    ]
    expected_corpus_files = initial_corpus_files + seed_corpus_files
    self._unpack_seed_corpus_if_needed(force_unpack=True)
    self._assert_elements_equal(expected_corpus_files, self._list_corpus_dir())

  def test_unpack_seed_corpus_subdirs(self):
    """Test unpack_seed_corpus_if_needed method flattens a
    seed corpus with subdirectories."""
    expected_dir_contents = [
        '0000000000000000', '0000000000000001', '0000000000000002',
        '0000000000000003'
    ]
    self._write_seed_corpus(self.seed_corpus_subdirs_contents, '.zip')
    self._unpack_seed_corpus_if_needed()
    self._assert_elements_equal(expected_dir_contents, self._list_corpus_dir())


class GetRadamsaOutputFilenameTest(unittest.TestCase):
  """get_radamsa_output_filename tests."""

  def test_get_radamsa_output_filename(self):
    """Test get_radamsa_output_filename works as expected."""
    output_filename = engine_common.get_radamsa_output_filename('file', 0)
    self.assertEqual('radamsa-00001-file', output_filename)

  def test_no_double_prefix(self):
    """Test get_radamsa_output_filename strips an existing prefix before adding
    a new one."""
    output_filename = engine_common.get_radamsa_output_filename(
        'radamsa-00002-file', 0)
    self.assertEqual('radamsa-00001-file', output_filename)

  def test_filename_length_limit(self):
    """Test get_radamsa_output_filename does not return filenames that are too
    long."""
    filename_length_limit = 255
    output_filename = engine_common.get_radamsa_output_filename(
        filename_length_limit * 2 * 'a', 0)
    self.assertLessEqual(len(output_filename), filename_length_limit)


class ProcessSanitizerOptionsOverridesTest(fake_filesystem_unittest.TestCase):
  """process_sanitizer_options_overrides tests."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    self.fuzz_target = '/test'
    self.fuzz_target_options_file = self.fuzz_target + '.options'

  @parameterized.parameterized.expand([
      ('ASAN_OPTIONS', 'asan'),
      ('MSAN_OPTIONS', 'msan'),
      ('UBSAN_OPTIONS', 'ubsan'),
      ('HWASAN_OPTIONS', 'hwasan'),
  ])
  def test_sanitizer_options_changed(self, options_name, section_name):
    """Test that sanitizer options set in .options file are added to the
    environment variable."""
    environment.set_value(options_name, 'a=1:b=2:c=1')
    self.fs.create_file(
        self.fuzz_target_options_file,
        contents='[{section_name}]\nc=3:d=4'.format(section_name=section_name))
    engine_common.process_sanitizer_options_overrides(self.fuzz_target)
    self.assertEqual('a=1:b=2:c=3:d=4', environment.get_value(options_name))

  @parameterized.parameterized.expand([
      ('ASAN_OPTIONS', 'msan'),
      ('MSAN_OPTIONS', 'asan'),
      ('UBSAN_OPTIONS', 'msan'),
      ('HWASAN_OPTIONS', 'msan'),
  ])
  def test_sanitizer_options_not_changed_unrelated_section(
      self, options_name, section_name):
    """Test that sanitizer options are not changed when provided an unrelated
    sanitizer section name."""
    environment.set_value(options_name, 'a=1:b=2:c=1')
    self.fs.create_file(
        self.fuzz_target_options_file,
        contents='[{section_name}]\nc=3:d=4'.format(section_name=section_name))
    engine_common.process_sanitizer_options_overrides(self.fuzz_target)
    self.assertEqual('a=1:b=2:c=1', environment.get_value(options_name))

  @parameterized.parameterized.expand([
      ('ASAN_OPTIONS'),
      ('MSAN_OPTIONS'),
      ('UBSAN_OPTIONS'),
      ('HWASAN_OPTIONS'),
  ])
  def test_sanitizer_options_not_changed_no_options_file(self, options_name):
    """Test that sanitizer options are not changed and no exception occurs
    when .options file is not provided."""
    environment.set_value(options_name, 'a=1:b=2:c=1')
    engine_common.process_sanitizer_options_overrides(self.fuzz_target)
    self.assertEqual('a=1:b=2:c=1', environment.get_value(options_name))
