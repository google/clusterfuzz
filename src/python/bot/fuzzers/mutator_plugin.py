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
"""Getting and using custom mutator plugins for libFuzzer."""

import os

from base import utils
from google_cloud_utils import storage
from metrics import logs
from system import archive
from system import environment
from system import shell

MUTATOR_SHARED_OBJECT_FILENAME = 'mutator-plugin.so'
ARCHIVES_SUBDIR_NAME = 'archives'
PLUGINS_SUBDIR_NAME = 'plugins'


def _get_mutator_plugins_bucket_url():
  """Returns the url of the mutator plugin's cloud storage bucket."""
  mutator_plugins_bucket = environment.get_value('MUTATOR_PLUGINS_BUCKET')
  if not mutator_plugins_bucket:
    logs.log_warn('MUTATOR_PLUGINS_BUCKET is not set in project config, '
                  'skipping custom mutator strategy.')
    return None

  return 'gs://%s' % mutator_plugins_bucket


def _get_mutator_plugins_subdir(subdir):
  """Returns the path of the subdirectory named |subdir| in
  MUTATOR_PLUGINS_DIR."""
  return os.path.join(environment.get_value('MUTATOR_PLUGINS_DIR'), subdir)


def _get_mutator_plugins_archives_dir():
  """Returns path of the archives subdirectory in MUTATOR_PLUGINS_DIR"""
  return _get_mutator_plugins_subdir(ARCHIVES_SUBDIR_NAME)


def _get_mutator_plugins_unpacked_dir():
  """Returns path of the unpacked plugins subdirectory in MUTATOR_PLUGINS_DIR"""
  return _get_mutator_plugins_subdir(PLUGINS_SUBDIR_NAME)


def _get_mutator_plugins_from_bucket():
  """Returns list of the mutator plugin archives in the mutator plugin storage
  bucket."""
  mutator_plugins_bucket_url = _get_mutator_plugins_bucket_url()
  if not mutator_plugins_bucket_url:
    return None

  return storage.list_blobs(mutator_plugins_bucket_url)


def _download_mutator_plugin_archive(mutator_plugin_archive):
  """Downloads the |mutator_plugin_archive| from the mutator plugin storage
  bucket to the plugin archives directory. Returns the path that the archive was
  downloaded to."""
  file_path = os.path.join(_get_mutator_plugins_archives_dir(),
                           mutator_plugin_archive)
  url = '%s/%s' % (_get_mutator_plugins_bucket_url(), mutator_plugin_archive)
  if not storage.copy_file_from(url, file_path):
    logs.log_error(
        'Failed to copy plugin archive from %s to %s' % (url, file_path))
    return None

  return file_path


def _unpack_mutator_plugin(mutator_plugin_archive_path):
  """Unpacks |mutator_plugin_archive_path| in the unpacked plugins directory and
  returns the path it was unpacked into."""
  mutator_plugin_name = os.path.basename(
      os.path.splitext(mutator_plugin_archive_path)[0])
  unpacked_plugin_dir = os.path.join(_get_mutator_plugins_unpacked_dir(),
                                     mutator_plugin_name)
  archive.unpack(mutator_plugin_archive_path, unpacked_plugin_dir)
  return unpacked_plugin_dir


def _extract_name_from_archive(plugin_archive_filename):
  """Parses |plugin_archive_filename| which should be named using the schema:
  '$NAME-$JOB-$FUZZ_TARGET.zip'. Returns tuple containing
  ($NAME, $JOB-$FUZZ_TARGET)."""
  # TODO(metzman): Get rid of this when we create an upload page for custom
  # mutator plugins.
  plugin_archive_name = os.path.splitext(plugin_archive_filename)[0]
  idx = plugin_archive_name.index('-')
  plugin_name = plugin_archive_name[:idx]
  return plugin_name, plugin_archive_name[idx + 1:]


class PluginGetter(object):
  """Class that gets a usable mutator plugin for |fuzzer_binary_name| from
  GCS."""

  def __init__(self, fuzzer_binary_name):
    self.fuzzer_binary_name = fuzzer_binary_name
    self.job_name = environment.get_value('JOB_NAME')
    self.create_directories()

  def create_directories(self):
    """Creates directories needed to use mutator plugins."""
    # TODO(320): Change mutator plugin downloads so that they don't need to be
    # deleted and redownloaded on each run of launcher.py.
    shell.create_directory(
        environment.get_value('MUTATOR_PLUGINS_DIR'),
        create_intermediates=True,
        recreate=True)
    shell.create_directory(
        _get_mutator_plugins_archives_dir(),
        create_intermediates=True,
        recreate=True)
    shell.create_directory(
        _get_mutator_plugins_unpacked_dir(),
        create_intermediates=True,
        recreate=True)

  def _is_plugin_usable(self, plugin_archive_filename):
    """Returns True if |plugin_archive_filename| is a usable plugin for this
    job, fuzz target combination."""
    _, plugin_job_and_fuzzer = _extract_name_from_archive(
        plugin_archive_filename)
    expected_name = '%s-%s' % (self.job_name, self.fuzzer_binary_name)
    return expected_name == plugin_job_and_fuzzer

  def get_mutator_plugin(self):
    """Downloads and unpacks a usable mutator plugin for this job and fuzz
    target if one is available in GCS"""
    mutator_plugins = _get_mutator_plugins_from_bucket()
    if not mutator_plugins:
      # No plugins found or plugin url is not set.
      return None

    usable_mutator_plugins = [
        plugin_archive for plugin_archive in mutator_plugins
        if self._is_plugin_usable(plugin_archive)
    ]

    # Quit if no usable plugins are available.
    if not usable_mutator_plugins:
      return None

    plugin_archive_name = utils.random_element_from_list(usable_mutator_plugins)

    # Handle a failed download.
    plugin_archive_path = _download_mutator_plugin_archive(plugin_archive_name)
    if not plugin_archive_path:
      return None

    _unpack_mutator_plugin(plugin_archive_path)
    mutator_plugin_path = find_mutator_plugin()
    if mutator_plugin_path is None:
      logs.log_error('Could not find plugin in %s' % plugin_archive_path)

    return mutator_plugin_path


def find_mutator_plugin():
  """Sets LD_PRELOAD to the path of a usable mutator plugin shared object.
  This should only be called after a call to get_mutator_plugin."""
  paths = shell.get_files_list(_get_mutator_plugins_unpacked_dir())
  # This function should not be called unless there is an unpacked plugin.
  for path in paths:
    if os.path.basename(path) == MUTATOR_SHARED_OBJECT_FILENAME:
      return path
  return None


def get_mutator_plugin(fuzzer_binary_name):
  """Downloads and unpacks a mutator plugin if a usable one for
  |fuzzer_binary_name| is in the bucket."""
  plugin_getter = PluginGetter(fuzzer_binary_name)
  return plugin_getter.get_mutator_plugin()
