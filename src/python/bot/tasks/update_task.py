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
"""Update task for updating source and tests."""

import datetime
import os
import platform
import sys
import time
import zipfile

from base import dates
from base import persistent_cache
from base import tasks
from base import utils
from bot.init_scripts import android as android_init
from bot.init_scripts import chromeos as chromeos_init
from bot.init_scripts import fuchsia as fuchsia_init
from bot.init_scripts import linux as linux_init
from bot.init_scripts import mac as mac_init
from bot.init_scripts import windows as windows_init
from config import local_config
from datastore import data_handler
from google_cloud_utils import storage
from metrics import logs
from metrics import monitoring_metrics
from system import archive
from system import environment
from system import process_handler
from system import shell

TESTS_LAST_UPDATE_KEY = 'tests_last_update'
TESTS_UPDATE_INTERVAL_DAYS = 1

MANIFEST_FILENAME = 'clusterfuzz-source.manifest'
if sys.version_info.major == 3:
  MANIFEST_FILENAME += '.3'


def _rename_dll_for_update(absolute_filepath):
  """Rename a DLL to allow for updates."""
  backup_filepath = absolute_filepath + '.bak.' + str(int(time.time()))
  os.rename(absolute_filepath, backup_filepath)


def _platform_deployment_filename():
  """Return the platform deployment filename."""
  platform_mappings = {
      'Linux': 'linux',
      'Windows': 'windows',
      'Darwin': 'macos'
  }

  base_filename = platform_mappings[platform.system()]
  if sys.version_info.major == 3:
    base_filename += '-3'

  return base_filename + '.zip'


def _deployment_file_url(filename):
  """Helper to return deployment file url."""
  deployment_bucket = local_config.ProjectConfig().get('deployment.bucket')
  if not deployment_bucket:
    return None

  return 'gs://{bucket}/{name}'.format(bucket=deployment_bucket, name=filename)


def get_source_url():
  """Return the source URL."""
  return _deployment_file_url(_platform_deployment_filename())


def get_source_manifest_url():
  """Return the source manifest URL."""
  return _deployment_file_url(MANIFEST_FILENAME)


def clear_old_files(directory, extracted_file_set):
  """Remove files from the directory that isn't in the given file list."""
  for root_directory, _, filenames in shell.walk(directory):
    for filename in filenames:
      file_path = os.path.join(root_directory, filename)
      if file_path not in extracted_file_set:
        shell.remove_file(file_path)

  shell.remove_empty_directories(directory)


def clear_pyc_files(directory):
  """Recursively remove all .pyc files from the given directory"""
  for root_directory, _, filenames in shell.walk(directory):
    for filename in filenames:
      if not filename.endswith('.pyc'):
        continue

      file_path = os.path.join(root_directory, filename)
      shell.remove_file(file_path)


def track_revision():
  """Get the local revision and report as a metric."""
  revision = get_local_source_revision() or ''
  monitoring_metrics.BOT_COUNT.set(1, {'revision': revision})


def get_local_source_revision():
  """Return the local source revision."""
  return utils.current_source_version()


def get_remote_source_revision(source_manifest_url):
  """Get remote revision. We refactor this method out, so that we can mock
    it."""
  return storage.read_data(source_manifest_url).decode('utf-8').strip()


def get_newer_source_revision():
  """Returns the latest source revision if there is an update, or None if the
  current source is up to date."""
  if (environment.get_value('LOCAL_SRC') or
      environment.get_value('LOCAL_DEVELOPMENT')):
    logs.log('Using local source, skipping source code update.')
    return None

  root_directory = environment.get_value('ROOT_DIR')
  temp_directory = environment.get_value('BOT_TMPDIR')
  source_manifest_url = get_source_manifest_url()
  if (not get_source_url() or not source_manifest_url or not temp_directory or
      not root_directory):
    logs.log('Skipping source code update.')
    return None

  logs.log('Checking source code for updates.')
  try:
    source_version = get_remote_source_revision(source_manifest_url)
  except Exception:
    logs.log_error('Error occurred while checking source version.')
    return None

  local_source_version = get_local_source_revision()
  if not local_source_version:
    logs.log('No manifest found. Forcing an update.')
    return source_version

  logs.log('Local source code version: %s.' % local_source_version)
  logs.log('Remote source code version: %s.' % source_version)
  if local_source_version >= source_version:
    logs.log('Remote souce code <= local source code. No update.')
    # No source code update found. Source code is current, bail out.
    return None

  return source_version


def run_platform_init_scripts():
  """Run platform specific initialization scripts."""
  logs.log('Running platform initialization scripts.')

  plt = environment.platform()
  if environment.is_android():
    android_init.run()
  elif plt == 'CHROMEOS':
    chromeos_init.run()
  elif plt == 'FUCHSIA':
    fuchsia_init.run()
  elif plt == 'LINUX':
    linux_init.run()
  elif plt == 'MAC':
    mac_init.run()
  elif plt == 'WINDOWS':
    windows_init.run()
  else:
    raise RuntimeError('Unsupported platform')

  logs.log('Completed running platform initialization scripts.')


def update_source_code():
  """Updates source code files with latest version from appengine."""
  process_handler.cleanup_stale_processes()
  shell.clear_temp_directory()

  root_directory = environment.get_value('ROOT_DIR')
  temp_directory = environment.get_value('BOT_TMPDIR')
  temp_archive = os.path.join(temp_directory, 'clusterfuzz-source.zip')
  try:
    storage.copy_file_from(get_source_url(), temp_archive)
  except Exception:
    logs.log_error('Could not retrieve source code archive from url.')
    return

  try:
    file_list = archive.get_file_list(temp_archive)
    zip_archive = zipfile.ZipFile(temp_archive, 'r')
  except Exception:
    logs.log_error('Bad zip file.')
    return

  src_directory = os.path.join(root_directory, 'src')
  output_directory = os.path.dirname(root_directory)
  error_occurred = False
  normalized_file_set = set()
  for filepath in file_list:
    filename = os.path.basename(filepath)

    # This file cannot be updated on the fly since it is running as server.
    if filename == 'adb':
      continue

    absolute_filepath = os.path.join(output_directory, filepath)
    if os.path.altsep:
      absolute_filepath = absolute_filepath.replace(os.path.altsep, os.path.sep)

    if os.path.realpath(absolute_filepath) != absolute_filepath:
      continue

    normalized_file_set.add(absolute_filepath)
    try:
      file_extension = os.path.splitext(filename)[1]

      # Remove any .so files first before overwriting, as they can be loaded
      # in the memory of existing processes. Overwriting them directly causes
      # segfaults in existing processes (e.g. run.py).
      if file_extension == '.so' and os.path.exists(absolute_filepath):
        os.remove(absolute_filepath)

      # On Windows, to update DLLs (and native .pyd extensions), we rename it
      # first so that we can install the new version.
      if (environment.platform() == 'WINDOWS' and
          file_extension in ['.dll', '.pyd'] and
          os.path.exists(absolute_filepath)):
        _rename_dll_for_update(absolute_filepath)
    except Exception:
      logs.log_error('Failed to remove or move %s before extracting new '
                     'version.' % absolute_filepath)

    try:
      extracted_path = zip_archive.extract(filepath, output_directory)
      external_attr = zip_archive.getinfo(filepath).external_attr
      mode = (external_attr >> 16) & 0o777
      mode |= 0o440
      os.chmod(extracted_path, mode)
    except:
      error_occurred = True
      logs.log_error(
          'Failed to extract file %s from source archive.' % filepath)

  zip_archive.close()

  if error_occurred:
    return

  clear_pyc_files(src_directory)
  clear_old_files(src_directory, normalized_file_set)

  local_manifest_path = os.path.join(root_directory,
                                     utils.LOCAL_SOURCE_MANIFEST)
  source_version = utils.read_data_from_file(
      local_manifest_path, eval_data=False).decode('utf-8').strip()
  logs.log('Source code updated to %s.' % source_version)


def update_tests_if_needed():
  """Updates layout tests every day."""
  data_directory = environment.get_value('FUZZ_DATA')
  error_occured = False
  expected_task_duration = 60 * 60  # 1 hour.
  retry_limit = environment.get_value('FAIL_RETRIES')
  temp_archive = os.path.join(data_directory, 'temp.zip')
  tests_url = environment.get_value('WEB_TESTS_URL')

  # Check if we have a valid tests url.
  if not tests_url:
    return

  # Layout test updates are usually disabled to speedup local testing.
  if environment.get_value('LOCAL_DEVELOPMENT'):
    return

  # |UPDATE_WEB_TESTS| env variable can be used to control our update behavior.
  if not environment.get_value('UPDATE_WEB_TESTS'):
    return

  last_modified_time = persistent_cache.get_value(
      TESTS_LAST_UPDATE_KEY, constructor=datetime.datetime.utcfromtimestamp)
  if (last_modified_time is not None and not dates.time_has_expired(
      last_modified_time, days=TESTS_UPDATE_INTERVAL_DAYS)):
    return

  logs.log('Updating layout tests.')
  tasks.track_task_start(
      tasks.Task('update_tests', '', ''), expected_task_duration)

  # Download and unpack the tests archive.
  for _ in range(retry_limit):
    try:
      shell.remove_directory(data_directory, recreate=True)
      storage.copy_file_from(tests_url, temp_archive)
      archive.unpack(temp_archive, data_directory, trusted=True)
      shell.remove_file(temp_archive)
      error_occured = False
      break
    except:
      logs.log_error(
          'Could not retrieve and unpack layout tests archive. Retrying.')
      error_occured = True

  if not error_occured:
    persistent_cache.set_value(
        TESTS_LAST_UPDATE_KEY, time.time(), persist_across_reboots=True)

  tasks.track_task_end()


def run():
  """Run update task."""
  # Since this code is particularly sensitive for bot stability, continue
  # execution but store the exception if anything goes wrong during one of these
  # steps.
  try:
    # Update heartbeat with current time.
    data_handler.update_heartbeat()

    # Check overall free disk space. If we are running too low, clear all
    # data directories like builds, fuzzers, data bundles, etc.
    shell.clear_data_directories_on_low_disk_space()

    # Download new layout tests once per day.
    update_tests_if_needed()
  except Exception:
    logs.log_error('Error occurred while running update task.')

  # Even if there is an exception in one of the other steps, we want to try to
  # update the source. If for some reason the source code update fails, it is
  # not necessary to run the init scripts.
  try:
    # If there is a newer revision, exit and let run.py update the source code.
    if get_newer_source_revision() is not None:
      if environment.is_trusted_host():
        from bot.untrusted_runner import host
        host.update_worker()

      sys.exit(0)

    # Run platform specific initialization scripts.
    run_platform_init_scripts()
  except Exception:
    logs.log_error('Error occurred while running update task.')
