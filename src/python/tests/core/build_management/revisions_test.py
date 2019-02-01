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
"""Tests for the revisions module."""

import ast
import hashlib
import mock
import os
import unittest

from build_management import revisions
from datastore import data_types
from tests.test_libs import helpers
from tests.test_libs import test_utils

ANDROID_JOB_TYPE = 'android_asan_chrome'
BASIC_JOB_TYPE = 'linux_asan_chrome_mp'
SRCMAP_JOB_TYPE = 'linux_asan_libass'
DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'revisions_data')

# For simplicity, the mocked URLs all end with the revision. They do not match
# the ones in use in production exactly.
REVISION_VARS_URL = (
    'default;https://chromium.googlesource.com/'
    'chromium/src/+/%s/DEPS?format=text\n'
    'android_asan_chrome;https://commondatastorage.googleapis.com/'
    'chrome-test-builds/android/revisions/%s\n'
    'linux_asan_libass;'
    'https://commondatastorage.googleapis.com/blah-%s.srcmap.json')


@test_utils.with_cloud_emulators('datastore')
class RevisionsTestcase(unittest.TestCase):
  """Revisions tests."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'base.utils.default_project_name', 'base.memoize.FifoOnDisk.get',
        'base.memoize.FifoOnDisk.put'
    ])

    self.mock.get.return_value = None

    data_types.Job(
        name=ANDROID_JOB_TYPE,
        environment_string=('HELP_URL = help_url\n')).put()
    data_types.Job(
        name=BASIC_JOB_TYPE,
        environment_string=('HELP_URL = help_url\n')).put()
    data_types.Job(
        name=SRCMAP_JOB_TYPE,
        environment_string=('PROJECT_NAME = libass\n'
                            'HELP_URL = help_url\n')).put()

  # General helper functions.
  @staticmethod
  def _read_data_file(data_file):
    """Helper function to read the contents of a data file."""
    with open(os.path.join(DATA_DIRECTORY, data_file)) as handle:
      return handle.read()

  # Helper classes and functions for mocks.
  class MockConfigChromium(object):
    """Simple mocked configuration for chromium."""

    def __init__(self):
      self.revision_vars_url = REVISION_VARS_URL
      self.component_repository_mappings = 'default;chromium/src\nv8;v8/v8\n'

  class MockConfigOSSFuzz(object):
    """Simple mocked configuration."""

    def __init__(self):
      self.revision_vars_url = REVISION_VARS_URL
      self.component_repository_mappings = ''

  @staticmethod
  def mock_get_url_content(url):
    """Read a local file based on the specified URL."""
    # Check to see if the URL specified is based on the default url.
    for line in REVISION_VARS_URL.splitlines():
      prefix = line[:line.find(';')]
      current_url = line[len(prefix) + 1:]
      format_index = current_url.find('%s')
      if url[:format_index] != current_url[:format_index]:
        continue

      revision = url[format_index:].split('/')[0]
      deps_file = 'deps_%s_%s.txt' % (prefix, revision)
      data = RevisionsTestcase._read_data_file(deps_file)
      return data

    raise NotImplementedError(url)

  @staticmethod
  def mock_get_git_hash_for_git_commit_pos(git_commit_pos, _):
    """Return a fake git hash for a git commit position."""
    return hashlib.sha1(str(git_commit_pos)).hexdigest()

  # Tests.
  def test_convert_revision_to_integer_simple(self):
    """Test the simple revision case of convert_revision_to_integer."""
    revision = revisions.convert_revision_to_integer('12345')
    self.assertEqual(revision, 12345)

  @mock.patch('metrics.logs.log_error')
  def test_convert_revision_to_integer_version_string(self, _):
    """Test version string conversions in convert_revision_to_integer."""
    revision = revisions.convert_revision_to_integer('1.1.1.1')

    # See the full comment in convert_revision_to_integer, but we pad this with
    # zeros to allow sorting.
    self.assertEqual(revision, 1000010000100001)

    # Ensure that the max lengths for each part are supported.
    revision = revisions.convert_revision_to_integer('12345.67890.12345.67890')
    self.assertEqual(revision, 12345678901234567890)

    # Ensure that we raise an exception if any of the individual parts are too
    # long.
    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('123456.12345.12345.12345')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('12345.123456.12345.12345')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('12345.12345.123456.12345')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('12345.12345.12345.123456')

    # Ensure that junk strings also raise value errors.
    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('123junk')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('junk')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('junk123')

    with self.assertRaises(ValueError):
      revisions.convert_revision_to_integer('...')

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  @mock.patch(
      'build_management.revisions._git_commit_position_to_git_hash_for_chromium'
  )
  def test_get_component_range_list_chromium(
      self, mock_get_git_hash, mock_get_url_content, mock_get_config):
    """Test that get_component_range_list works properly for the Chromium
    repo."""
    mock_get_config.return_value = self.MockConfigChromium()
    self.mock.default_project_name.return_value = 'chromium'
    mock_get_url_content.side_effect = self.mock_get_url_content
    mock_get_git_hash.side_effect = self.mock_get_git_hash_for_git_commit_pos

    result = revisions.get_component_range_list(336903, 336983, BASIC_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result)

    expected_html = self._read_data_file('chromium_expected_html.txt')
    self.assertEqual(result_as_html, expected_html)

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  @mock.patch(
      'build_management.revisions._git_commit_position_to_git_hash_for_chromium'
  )
  def test_get_component_range_list_clank(
      self, mock_get_git_hash, mock_get_url_content, mock_get_config):
    """Test that get_component_range_list works properly for the Clank repo."""
    mock_get_config.return_value = self.MockConfigChromium()
    self.mock.default_project_name.return_value = 'chromium'
    mock_get_url_content.side_effect = self.mock_get_url_content
    mock_get_git_hash.side_effect = self.mock_get_git_hash_for_git_commit_pos

    result = revisions.get_component_range_list(260548, 260552,
                                                ANDROID_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result)

    expected_html = self._read_data_file('clank_expected_html.txt')
    self.assertEqual(result_as_html, expected_html)

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_git_hash_for_git_commit_pos(self, mock_get_url_content,
                                           mock_get_config):
    """Test git hash for git commit position."""
    mock_get_config.return_value = self.MockConfigChromium()
    self.mock.default_project_name.return_value = 'chromium'
    expected_hash = '95a3bc965ed80186215cea788caa5faae0898839'
    mock_get_url_content.return_value = ('{\n'
                                         '  "git_sha": "%s"\n'
                                         '}' % expected_hash)

    actual_hash = revisions._git_commit_position_to_git_hash_for_chromium(  # pylint: disable=protected-access
        '29124', 'v8/v8')
    self.assertEqual(actual_hash, expected_hash)

    # This is not perfect in that it assumes a specific order to the arguments,
    # but should be sufficient. A format string is not being used to make the
    # URL encoding easier to understand.
    mock_get_url_content.assert_called_once_with(
        revisions.CRREV_NUMBERING_URL +
        '?repo=v8%2Fv8&numbering_type=COMMIT_POSITION&fields=git_sha&'
        'number=29124&project=chromium&numbering_identifier='
        'refs%2Fheads%2Fmaster')

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  @mock.patch(
      'build_management.revisions._git_commit_position_to_git_hash_for_chromium'
  )
  def test_get_real_revision_chromium(self, mock_get_git_hash,
                                      mock_get_url_content, mock_get_config):
    """Test that get_real_revision works properly for chromium revisions."""
    mock_get_config.return_value = self.MockConfigChromium()
    self.mock.default_project_name.return_value = 'chromium'
    mock_get_url_content.side_effect = self.mock_get_url_content
    mock_get_git_hash.side_effect = self.mock_get_git_hash_for_git_commit_pos

    self.assertEqual('1d783bc2a3629b94c963debfa3feaee27092dd92',
                     revisions.get_real_revision(336903, BASIC_JOB_TYPE))

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_real_revision_oss_fuzz(self, mock_get_url_content,
                                      mock_get_config):
    """Test that get_real_revision works properly for non-chromium revisions."""
    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    self.assertEqual('35dc4dd0e14e3afb4a2c7e319a3f4110e20c7cf2',
                     revisions.get_real_revision(9002, SRCMAP_JOB_TYPE))
    self.assertEqual('54444451414e3efb4a4c7e319a3f4110e20c7cf2',
                     revisions.get_real_revision(9003, SRCMAP_JOB_TYPE))

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_src_map(self, mock_get_url_content, mock_get_config):
    """Test that get_src_map works."""
    os.environ['REVISION_VARS_URL'] = (
        'https://commondatastorage.googleapis.com/blah-%s.srcmap.json')

    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    self.assertDictEqual(
        revisions.get_src_map(1337), {
            u'/src/libass': {
                u'url': u'https://github.com/libass/libass.git',
                u'rev': u'35dc4dd0e14e3afb4a2c7e319a3f4110e20c7cf2',
                u'type': u'git'
            },
            u'/src/fribidi': {
                u'url': u'https://github.com/behdad/fribidi.git',
                u'rev': u'881b8d891cc61989ab8811b74d0e721f72bf913b',
                u'type': u'git'
            }
        })

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_component_revision_list_src_map(self, mock_get_url_content,
                                               mock_get_config):
    """Test get_component_range_list for srcmap jobs."""
    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    result = revisions.get_component_range_list(1337, 9001, SRCMAP_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result)
    expected_html = self._read_data_file('srcmap_expected_html.txt')
    self.assertEqual(result_as_html, expected_html)

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_component_revision_list_src_map_text(self, mock_get_url_content,
                                                    mock_get_config):
    """Test get_component_range_list for srcmap jobs (text only)."""
    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    result = revisions.get_component_range_list(1337, 9001, SRCMAP_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result, use_html=False)
    expected_html = self._read_data_file('srcmap_expected_text.txt')
    self.assertEqual(result_as_html, expected_html)

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_component_range_list_same_hash(self, mock_get_url_content,
                                              mock_get_config):
    """Test get_component_range_list for 2 builds that have different revision
    numbers, but same revision hash after mapping."""
    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    result = revisions.get_component_range_list(1337, 1338, SRCMAP_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result)
    expected_html = self._read_data_file('srcmap_expected_html_2.txt')
    self.assertEqual(result_as_html, expected_html)

  @mock.patch('config.db_config.get')
  @mock.patch('build_management.revisions._get_url_content')
  def test_get_component_range_list_0_start_custom(self, mock_get_url_content,
                                                   mock_get_config):
    """Test get_component_range_list with a '0' start_revision."""
    mock_get_config.return_value = self.MockConfigOSSFuzz()
    self.mock.default_project_name.return_value = 'oss-fuzz'
    mock_get_url_content.side_effect = self.mock_get_url_content

    result = revisions.get_component_range_list(0, 1338, SRCMAP_JOB_TYPE)
    result_as_html = revisions.format_revision_list(result)
    expected_html = self._read_data_file('srcmap_expected_html_3.txt')
    self.assertEqual(result_as_html, expected_html)

  def test_find_min_revision_index(self):
    """Tests find_min_revision_index()."""
    revisions_list = [1000, 2000, 3000, 4000]
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 1000), 0)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 2000), 1)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 3000), 2)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 4000), 3)

    self.assertIsNone(revisions.find_min_revision_index(revisions_list, 1))
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 1001), 0)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 2001), 1)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 3001), 2)
    self.assertEqual(revisions.find_min_revision_index(revisions_list, 4001), 3)

  def test_find_max_revision_index(self):
    """Tests find_max_revision_index()."""
    revisions_list = [1000, 2000, 3000, 4000]
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 1000), 0)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 2000), 1)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 3000), 2)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 4000), 3)

    self.assertEqual(revisions.find_max_revision_index(revisions_list, 1), 0)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 1001), 1)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 2001), 2)
    self.assertEqual(revisions.find_max_revision_index(revisions_list, 3001), 3)
    self.assertIsNone(revisions.find_max_revision_index(revisions_list, 4001))


@test_utils.with_cloud_emulators('datastore')
class GetComponentsListTest(unittest.TestCase):
  """Tests get_components_list."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_get_components_list(self):
    """Test get_components_list."""
    data_types.Job(
        name='libfuzzer_asan_libass',
        environment_string=('PROJECT_NAME = libass\n'
                            'HELP_URL = help_url\n')).put()
    revisions_dict = {
        u'/src/libass': {
            u'url': u'https://github.com/libass/libass.git',
            u'rev': u'35dc4dd0e14e3afb4a2c7e319a3f4110e20c7cf2',
        },
        u'/src/fribidi': {
            u'url': u'https://github.com/behdad/fribidi.git',
            u'rev': u'881b8d891cc61989ab8811b74d0e721f72bf913b',
        }
    }

    expected_components_list = [u'/src/libass', u'/src/fribidi']
    actual_components_list = revisions.get_components_list(
        revisions_dict, 'libfuzzer_asan_libass')
    self.assertEqual(expected_components_list, actual_components_list)


class DepsToRevisionsDictTest(unittest.TestCase):
  """Tests deps_to_revisions_dict"""

  # General helper function.
  @staticmethod
  def _read_data_file(data_file):
    """Helper function to read the contents of a data file."""
    with open(os.path.join(DATA_DIRECTORY, data_file)) as handle:
      return handle.read()

  def test(self):
    """Test that deps is correctly parsed without exceptions."""
    self.maxDiff = None  # pylint: disable=invalid-name
    deps_content = self._read_data_file('chromium_deps.txt')
    actual_revisions_dict = revisions.deps_to_revisions_dict(deps_content)
    expected_revisions_dict = ast.literal_eval(
        self._read_data_file('chromium_expected_deps_revisions_dict.txt'))
    self.assertEqual(expected_revisions_dict, actual_revisions_dict)

  def test_bad_deps(self):
    """Test that bad deps is correctly parsed without exceptions."""
    self.maxDiff = None  # pylint: disable=invalid-name
    deps_content = 'vars = {}'
    actual_revisions_dict = revisions.deps_to_revisions_dict(deps_content)
    self.assertEqual(None, actual_revisions_dict)
