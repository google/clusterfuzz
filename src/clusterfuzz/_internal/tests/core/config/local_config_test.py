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
"""Tests for local_config functions."""

import os
import unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


class GetTest(unittest.TestCase):
  """Tests get()."""

  def setUp(self):
    test_helpers.patch_environ(self)

    self.configs_directory = os.path.join(
        os.path.dirname(__file__), 'local_config_data')
    environment.set_value('CONFIG_DIR_OVERRIDE', self.configs_directory)

    self.config = local_config.Config()

  def test_get_with_non_existent_configs_directory(self):
    """Test with non-existent configs directory."""
    environment.set_value('CONFIG_DIR_OVERRIDE', 'non-existent')
    with self.assertRaises(errors.BadConfigError):
      local_config.Config().get('foo')

  def test_get_with_invalid_key_name(self):
    """Test with an invalid key name passed for a lookup."""
    for key in ['', None]:
      with self.assertRaises(errors.InvalidConfigKey):
        self.config.get(key)

  def test_get_with_bad_yaml_file(self):
    """Test with a unparseable yaml file."""
    with self.assertRaises(errors.ConfigParseError):
      self.config.get('bad')

  def test_get_with_root_yaml_file(self):
    """Test with a yaml file in root."""
    self.assertEqual({'b': {'c': 'd', 'e': 1}}, self.config.get('a'))
    self.assertEqual({'c': 'd', 'e': 1}, self.config.get('a.b'))
    self.assertEqual('d', self.config.get('a.b.c'))
    self.assertEqual(1, self.config.get('a.b.e'))
    self.assertEqual(
        os.path.join(self.configs_directory, '1'),
        self.config.get_absolute_path('a.b.e'))

  def test_get_with_subfolder_yaml_file(self):
    """Test with a yaml file in sub-folders."""
    # Use aa/bb/cc.yaml.
    self.assertEqual({'dd': 'ee'}, self.config.get('aa.bb.cc'))
    self.assertEqual('ee', self.config.get('aa.bb.cc.dd'))
    self.assertEqual(
        os.path.join(self.configs_directory, 'aa', 'bb', 'ee'),
        self.config.get_absolute_path('aa.bb.cc.dd'))

    with self.assertRaises(errors.InvalidConfigKey):
      self.config.get('ambiguous.a')

  def test_get_with_sub_config(self):
    """Test with a sub-config."""
    sub_config = local_config.Config().sub_config('aa.bb.cc')
    self.assertEqual('ee', sub_config.get('dd'))
    self.assertEqual({'dd': 'ee'}, sub_config.get())

    sub_config = local_config.Config('aa').sub_config('bb.cc')
    self.assertEqual('ee', sub_config.get('dd'))
    self.assertEqual({'dd': 'ee'}, sub_config.get())

    sub_config = local_config.Config('aa.bb').sub_config('cc')
    self.assertEqual('ee', sub_config.get('dd'))
    self.assertEqual({'dd': 'ee'}, sub_config.get())

  def test_get_with_invalid_keys(self):
    """Test with invalid keys."""
    # Invalid keys, are actually values.
    with self.assertRaises(errors.InvalidConfigKey):
      self.config.get('aa.bb.cc.dd.ee')

  def test_get_non_existent_attributes_without_default(self):
    """Tests non-existent attributes return None without default value."""
    self.assertIsNone(self.config.get('a.b.f'))
    self.assertIsNone(self.config.get('aa.bb.cc.ff'))
    self.assertIsNone(self.config.get('aa.bb.zz'))

    # Does not exist.
    self.assertIsNone(self.config.get('zz.aa'))

  def test_get_non_existent_attributes_with_default(self):
    """Tests non-existent attributes return default with default value."""
    self.assertEqual(2, self.config.get('a.b.f', default=2))
    self.assertEqual(2, self.config.get('aa.bb.cc.ff', default=2))
    self.assertEqual(2, self.config.get('aa.bb.zz', default=2))

    # Does not exist.
    self.assertEqual(2, self.config.get('zz.aa', default=2))

  def test_root_validation(self):
    """Test root validation."""
    _ = local_config.Config()
    _ = local_config.Config('a')
    _ = local_config.Config('aa')
    _ = local_config.Config('aa.bb')
    _ = local_config.Config('aa.bb.cc')
    _ = local_config.Config('aa.bb.cc.dd')

    with self.assertRaises(errors.BadConfigError):
      _ = local_config.Config('aa.b')

    with self.assertRaises(errors.BadConfigError):
      _ = local_config.Config('aa.bb.c')

    with self.assertRaises(errors.BadConfigError):
      _ = local_config.Config('aa.bb.cc.d')

    with self.assertRaises(errors.InvalidConfigKey):
      _ = local_config.Config('aa.bb.cc.dd.ee')


class GetTestWithCache(unittest.TestCase):
  """Tests get() with and without caching."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.config.local_config._search_key',
    ])
    self.mock._search_key.return_value = 'value'  # pylint: disable=protected-access

  def test_with_cache(self):
    """Test that we invoke _search_key once with caching enabled."""
    config = local_config.Config()
    for _ in range(10):
      self.assertEqual('value', config.get('a.b.c'))
    self.assertEqual(1, self.mock._search_key.call_count)  # pylint: disable=protected-access


class ProjectConfigTest(unittest.TestCase):
  """Tests ProjectConfig."""

  def setUp(self):
    test_helpers.patch_environ(self)

    environment.remove_key('PROJECT_NAME')
    environment.remove_key('ISSUE_TRACKER')
    environment.remove_key('UPDATE_WEB_TESTS')

    self.config = local_config.ProjectConfig()

  def test_set_environment_without_default(self):
    """Test that set_environment sets the variable from test config.."""
    self.config.set_environment()
    self.assertEqual('test-project', environment.get_value('PROJECT_NAME'))
    self.assertEqual('test-clusterfuzz',
                     environment.get_value('APPLICATION_ID'))

  def test_set_environment_with_default(self):
    """Test that set_environment sets the variable from test config, skipping
    the ones already set in environment."""
    environment.set_value('ISSUE_TRACKER', 'test-issue-tracker-override')
    environment.set_value('UPDATE_WEB_TESTS', True)
    self.config.set_environment()
    self.assertEqual('test-project', environment.get_value('PROJECT_NAME'))
    self.assertEqual('test-issue-tracker-override',
                     environment.get_value('ISSUE_TRACKER'))
    self.assertEqual(True, environment.get_value('UPDATE_WEB_TESTS'))
