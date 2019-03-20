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
"""Tests fuzzers.mutator_plugin."""

import os
import unittest
import shutil

from pyfakefs import fake_filesystem_unittest

from bot.fuzzers import mutator_plugin
from tests.test_libs import helpers
from tests.test_libs import test_utils


class SetMutatorPluginTest(fake_filesystem_unittest.TestCase):
  """Tests set_mutator_plugin."""

  def setUp(self):
    helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)
    self.plugins_root_dir = '/plugins'
    os.environ['MUTATOR_PLUGINS_DIR'] = self.plugins_root_dir

  def test_set_mutator_plugin_with_usable(self):
    """Tests that LD_PRELOAD is set properly by set_mutator_plugin when there is
    a usable mutator plugin available."""
    usable_plugin_path = os.path.join(
        self.plugins_root_dir, 'plugins',
        mutator_plugin.MUTATOR_SHARED_OBJECT_FILENAME)

    self.fs.CreateFile(usable_plugin_path)
    mutator_plugin.set_mutator_plugin()
    self.assertEqual(usable_plugin_path, os.environ['LD_PRELOAD'])

  def test_set_mutator_plugin_without_usable(self):
    """Tests that LD_PRELOAD is not set by set_mutator_plugin when there isn't a
    usable mutator plugin available."""
    self.assertIsNone(mutator_plugin.set_mutator_plugin())
    self.assertIsNone(os.getenv('LD_PRELOAD'))


# pylint: disable=protected-access
class GetDirectoryFunctionsTest(unittest.TestCase):
  """Tests functions for get plugin directories."""

  def setUp(self):
    helpers.patch_environ(self)
    self.plugins_root_dir = '/plugins'
    os.environ['MUTATOR_PLUGINS_DIR'] = self.plugins_root_dir

  def test_get_mutator_plugins_subdir(self):
    """Tests that _get_mutator_plugins_subdir returns the path to the correct
    subdirectory."""
    subdir = 'x'
    self.assertEqual(
        os.path.join(self.plugins_root_dir, subdir),
        mutator_plugin._get_mutator_plugins_subdir(subdir))

  def test_get_mutator_plugins_archives_dir(self):
    """Tests that _get_mutator_plugins_archives_dir returns the path to the
    mutator plugin archives directory."""
    self.assertEqual(
        os.path.join(self.plugins_root_dir,
                     mutator_plugin.ARCHIVES_SUBDIR_NAME),
        mutator_plugin._get_mutator_plugins_archives_dir())

  def test_get_mutator_plugins_unpacked_dir(self):
    """Tests that _get_mutator_plugins_unpacked_dir returns the path to the
    unpacked mutator plugin directory."""
    self.assertEqual(
        os.path.join(self.plugins_root_dir, mutator_plugin.PLUGINS_SUBDIR_NAME),
        mutator_plugin._get_mutator_plugins_unpacked_dir())


# pylint: disable=protected-access
class PluginGetterTest(fake_filesystem_unittest.TestCase):
  """Tests PluginGetter."""

  def setUp(self):
    helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)
    os.environ['JOB_NAME'] = 'libfuzzer_asan_test'
    self.fuzzer_binary_name = 'test_fuzzer'
    self.name = 'myplugin'
    self.plugins_root_dir = '/plugins'
    os.environ['MUTATOR_PLUGINS_DIR'] = self.plugins_root_dir
    self.plugin_getter = mutator_plugin.PluginGetter(self.fuzzer_binary_name)
    self.plugins_archives_dir = os.path.join(self.plugins_root_dir, 'archives')
    self.plugin_archive_filename = '%s-%s-%s.zip' % (
        self.name, os.environ['JOB_NAME'], self.fuzzer_binary_name)
    self.plugin_archive_path = os.path.join(self.plugins_archives_dir,
                                            self.plugin_archive_filename)
    self.plugins_dir = os.path.join(self.plugins_root_dir, 'plugins')

    helpers.patch(self, [
        'google_cloud_utils.gsutil.GSUtilRunner.download_file',
        'bot.fuzzers.mutator_plugin._get_mutator_plugins_from_bucket',
    ])

    def mocked_download_file(runner_self, gcs_url, file_path):  # pylint: disable=unused-argument
      expected_url = '%s/%s' % (mutator_plugin._get_mutator_plugins_bucket_url(
      ), self.plugin_archive_filename)

      self.assertEqual(expected_url, gcs_url)
      self.assertEqual(file_path, self.plugin_archive_path)
      return file_path

    self.mock.download_file.side_effect = mocked_download_file

  def test_create_directories(self):
    """Tests that create_directories creates the right directories."""
    shutil.rmtree(self.plugins_root_dir)
    self.plugin_getter.create_directories()
    directories = [
        self.plugins_root_dir,
        os.path.join(self.plugins_root_dir, 'plugins'),
        os.path.join(self.plugins_root_dir, 'archives')
    ]
    self.assertTrue(all(os.path.isdir(directory) for directory in directories))

  def test_extract_name_from_archive(self):
    """Tests that _extract_name_from_archive extracts the name from the
    archive."""
    name, job_and_fuzz_target = self.plugin_getter._extract_name_from_archive(
        self.plugin_archive_filename)

    self.assertEqual(self.name, name)
    expected_job_and_fuzz_target = '%s-%s' % (os.environ['JOB_NAME'],
                                              self.fuzzer_binary_name)
    self.assertEqual(expected_job_and_fuzz_target, job_and_fuzz_target)

  def test_recognizes_usable(self):
    """Tests that _is_plugin_usable recognizes a usable plugin archive."""
    self.assertTrue(
        self.plugin_getter._is_plugin_usable(self.plugin_archive_filename))

  def test_recognizes_unusable(self):
    """Tests that _is_plugin_usable recognizes an unusable plugin archive."""
    unusable_plugin_archive_filename = self.plugin_archive_filename.replace(
        self.fuzzer_binary_name, 'other_binary')
    self.assertFalse(
        self.plugin_getter._is_plugin_usable(unusable_plugin_archive_filename))

  def test_download_mutator_plugin_archive(self):
    """Tests that _download_mutator_plugin_archive downloads an archive to the
    correct location."""
    self.assertEqual(
        self.plugin_archive_path,
        mutator_plugin._download_mutator_plugin_archive(
            self.plugin_archive_filename))
