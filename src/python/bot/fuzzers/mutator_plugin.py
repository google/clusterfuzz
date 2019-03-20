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
from bot.fuzzers import utils as fuzzer_utils
from google_cloud_utils import gsutil
from google_cloud_utils import storage
from system import archive
from system import environment
from system import shell

MUTATOR_PLUGINS_BUCKET_ENV_VAR = 'MUTATOR_PLUGINS_BUCKET'
MUTATOR_SHARED_OBJECT_FILENAME = 'mutator-plugin.so'
ARCHIVES_SUBDIR_NAME = 'archives'
PLUGINS_SUBDIR_NAME = 'plugins'


def _get_mutator_plugins_bucket_url():
  """Returns the url of the mutator plugins' cloud storage bucket."""
  return 'gs://%s' % environment.get_value(MUTATOR_PLUGINS_BUCKET_ENV_VAR)


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
  return storage.list_blobs(_get_mutator_plugins_bucket_url())


def _download_mutator_plugin_archive(mutator_plugin_archive):
  """Downloads the |mutator_plugin_archive| from the mutator plugin storage
  bucket to self.mutator_plugin_archives_dir. Returns the path archive was
  downloaded to."""
  file_path = os.path.join(_get_mutator_plugins_archives_dir(),
                           mutator_plugin_archive)
  url = '%s/%s' % (_get_mutator_plugins_bucket_url(), mutator_plugin_archive)
  assert gsutil.GSUtilRunner().download_file(url, file_path)
  return file_path


def _unpack_mutator_plugin(mutator_plugin_archive_path):
  """Unpacks |mutator_plugin_archive_path| in self.mutator_plugin_unpacked_dir
  and returns the path it was unpacked into."""
  mutator_plugin_name = os.path.basename(
      os.path.splitext(mutator_plugin_archive_path)[0])
  unpacked_plugin_dir = os.path.join(_get_mutator_plugins_unpacked_dir(),
                                     mutator_plugin_name)
  archive.unpack(mutator_plugin_archive_path, unpacked_plugin_dir)
  return unpacked_plugin_dir


class PluginGetter(object):
  """Class that finds a usable mutator plugin for |fuzzer_binary_name|."""

  def __init__(self, fuzzer_binary_name):
    self.fuzzer_binary_name = fuzzer_binary_name
    self.job_name = environment.get_value('JOB_NAME')
    self.create_directories()

  def create_directories(self):
    """Creates directories needed to use mutator plugins."""
    shell.remove_directory(
        environment.get_value('MUTATOR_PLUGINS_DIR'), recreate=True)
    os.mkdir(_get_mutator_plugins_archives_dir())
    os.mkdir(_get_mutator_plugins_unpacked_dir())

  @staticmethod
  def _extract_name_from_archive(plugin_archive_filename):
    """Parses |plugin_archive_filename| which should be named using the schema:
    '$NAME-$JOB-$FUZZ_TARGET.zip'. Returns tuple containing
    ($NAME, $JOB-FUZZ_TARGET)."""
    # TODO(metzman): Get rid of this when we create an upload page for custom
    # mutator plugins.
    plugin_archive_name = os.path.splitext(plugin_archive_filename)[0]
    idx = plugin_archive_name.index('-')
    plugin_name = plugin_archive_name[:idx]
    return plugin_name, plugin_archive_name[idx + 1:]

  def _is_plugin_usable(self, plugin_archive_filename):
    """Returns True if |plugin_archive_filename| is a usable plugin for this
    job, fuzz target combination."""
    _, plugin_job_and_fuzzer = self._extract_name_from_archive(
        plugin_archive_filename)
    expected_name = '%s-%s' % (self.job_name, self.fuzzer_binary_name)
    return expected_name == plugin_job_and_fuzzer

  def get_mutator_plugin(self):
    """Downloads, unpacks, and sets the MUTATOR_PLUGIN_PATH_ENV_VAR environment
    variable to a usable mutator plugin for this job and fuzz target if one is
    available."""
    mutator_plugins = _get_mutator_plugins_from_bucket()
    usable_mutator_plugins = [
        plugin_archive for plugin_archive in mutator_plugins
        if self._is_plugin_usable(plugin_archive)
    ]

    # Quit if no usable plugins are available.
    if not usable_mutator_plugins:
      return

    plugin_archive_name = utils.random_element_from_list(usable_mutator_plugins)
    plugin_archive_path = _download_mutator_plugin_archive(plugin_archive_name)
    unpacked_plugin_dir = _unpack_mutator_plugin(plugin_archive_path)


def set_mutator_plugin():
  """Sets LD_PRELOAD to the path of a usable mutator plugin shared object.
  Should come after a call to get_mutator_plugin."""
  paths = shell.get_files_list(_get_mutator_plugins_unpacked_dir())
  # This function should not be called unless there is an unpacked plugin.
  for path in paths:
    if os.path.basename(path) == MUTATOR_SHARED_OBJECT_FILENAME:
      environment.set_value('LD_PRELOAD', path)
      return path
  return None


def unset_mutator_plugin():
  """Unsets LD_PRELOAD."""
  environment.remove_key('LD_PRELOAD')


def get_mutator_plugin(fuzzer_binary_name):
  """Downloads, unpacks, and saves the path of a mutator plugin if a usable one
  for |fuzzer_binary_name| is in the bucket. This can later be used by
  set_mutator_plugin for use during fuzzing."""
  plugin_getter = PluginGetter(fuzzer_binary_name)
  plugin_getter.get_mutator_plugin()
