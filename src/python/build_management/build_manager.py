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
"""Build manager."""

import os
import re
import subprocess
import time

from collections import namedtuple
from distutils import spawn

from base import errors
from base import utils
from build_management import revisions
from datastore import data_types
from datastore import ndb_utils
from fuzzing import fuzzer_selection
from google_cloud_utils import blobs
from google_cloud_utils import storage
from metrics import logs
from platforms import android
from system import archive
from system import environment
from system import shell

# The default environment variables for specifying build bucket paths.
DEFAULT_BUILD_BUCKET_PATH_ENV_VARS = (
    'RELEASE_BUILD_BUCKET_PATH',
    'SYM_RELEASE_BUILD_BUCKET_PATH',
    'SYM_DEBUG_BUILD_BUCKET_PATH',
)

# File name for storing current build revision.
REVISION_FILE_NAME = 'REVISION'

# Various build type mapping strings.
BUILD_TYPE_SUBSTRINGS = [
    '-beta', '-stable', '-debug', '-release', '-symbolized'
]

# Build eviction constants.
MAX_EVICTED_BUILDS = 100
MIN_FREE_DISK_SPACE_CHROMIUM = 10 * 1024 * 1024 * 1024  # 10 GB
MIN_FREE_DISK_SPACE_DEFAULT = 5 * 1024 * 1024 * 1024  # 5 GB
TIMESTAMP_FILE = '.timestamp'

# Indicates if this is a partial build (due to selected files copied from fuzz
# target).
PARTIAL_BUILD_FILE = '.partial_build'

# ICU data file.
ICU_DATA_FILENAME = 'icudtl.dat'

# Extensions to exclude when unarchiving a fuzz target. Note that fuzz target
# own files like seed corpus, options, etc are covered by its own regex.
FUZZ_TARGET_EXCLUDED_EXTENSIONS = [
    'exe', 'options', 'txt', 'zip', 'exe.pdb', 'par'
]

# Binaries to explicitly include when unarchiving a fuzz target.
FUZZ_TARGET_WHITELISTED_BINARIES = [
    'afl-cmin',
    'afl-fuzz',
    'afl-showmap',
    'afl-tmin',
    'honggfuzz',
    'llvm-symbolizer',
]

# Time for unpacking a build beyond which an error should be logged.
UNPACK_TIME_LIMIT = 60 * 20

PATCHELF_SIZE_LIMIT = 1.5 * 1024 * 1024 * 1024  # 1.5 GiB

TARGETS_LIST_FILENAME = 'targets.list'

BuildUrls = namedtuple('BuildUrls', ['bucket_path', 'urls_list'])


class BuildManagerException(Exception):
  """Build manager exceptions."""


def _base_build_dir(bucket_path):
  """Get the base directory for a build."""
  job_name = environment.get_value('JOB_NAME')
  return _get_build_directory(bucket_path, job_name)


def _make_space(requested_size, current_build_dir=None):
  """Try to make the requested number of bytes available by deleting builds."""
  if utils.is_chromium():
    min_free_disk_space = MIN_FREE_DISK_SPACE_CHROMIUM
  else:
    min_free_disk_space = MIN_FREE_DISK_SPACE_DEFAULT

  builds_directory = environment.get_value('BUILDS_DIR')

  error_message = 'Need at least %d GB of free disk space.' % ((
      (min_free_disk_space + requested_size) // 1024**3))
  for _ in range(MAX_EVICTED_BUILDS):
    free_disk_space = shell.get_free_disk_space(builds_directory)
    if free_disk_space is None:
      # Can't determine free disk space, bail out.
      return False

    if requested_size + min_free_disk_space < free_disk_space:
      return True

    if not _evict_build(current_build_dir):
      logs.log_error(error_message)
      return False

  free_disk_space = shell.get_free_disk_space(builds_directory)
  result = requested_size + min_free_disk_space < free_disk_space
  if not result:
    logs.log_error(error_message)
  return result


def _make_space_for_build(build_local_archive,
                          current_build_dir,
                          file_match_callback=None):
  """Make space for extracting the build archive by deleting the least recently
  used builds."""
  extracted_size = archive.extracted_size(
      build_local_archive, file_match_callback=file_match_callback)

  return _make_space(extracted_size, current_build_dir=current_build_dir)


def _evict_build(current_build_dir):
  """Remove the least recently used build to make room."""
  builds_directory = environment.get_value('BUILDS_DIR')
  least_recently_used = None
  least_recently_used_timestamp = None

  for build_directory in os.listdir(builds_directory):
    absolute_build_directory = os.path.join(builds_directory, build_directory)
    if not os.path.isdir(absolute_build_directory):
      continue

    if absolute_build_directory == current_build_dir:
      # Don't evict the build we're trying to extract.
      continue

    build = BaseBuild(absolute_build_directory)
    timestamp = build.last_used_time()

    if (least_recently_used_timestamp is None or
        timestamp < least_recently_used_timestamp):
      least_recently_used_timestamp = timestamp
      least_recently_used = build

  if not least_recently_used:
    return False

  logs.log(
      'Deleting build %s to save space.' % least_recently_used.base_build_dir)
  least_recently_used.delete()

  return True


def _handle_unrecoverable_error_on_windows():
  """Handle non-recoverable error on Windows. This is usually either due to disk
  corruption or processes failing to terminate using regular methods. Force a
  restart for recovery."""
  if environment.platform() != 'WINDOWS':
    return

  logs.log_error('Unrecoverable error, restarting machine...')
  time.sleep(60)
  utils.restart_machine()


def _get_file_match_callback():
  """Returns a file match callback to decide which files to unpack in an
  archive.
  """
  # Don't return a callback to decide what to selectively unpack if
  # UNPACK_ALL_FUZZ_TARGETS_AND_FILES is set. Otherwise we are not actually
  # going to unpack all.
  if environment.get_value('UNPACK_ALL_FUZZ_TARGETS_AND_FILES'):
    return None

  fuzz_target = environment.get_value('FUZZ_TARGET')
  if not fuzz_target:
    # File match regex is only applicable for libFuzzer and afl fuzz targets.
    return None

  logs.log('Extracting only files for target %s.' % fuzz_target)

  whitelisted_names = tuple([fuzz_target] + FUZZ_TARGET_WHITELISTED_BINARIES)
  blacklisted_extensions = tuple(
      '.' + extension for extension in FUZZ_TARGET_EXCLUDED_EXTENSIONS)

  def file_match_callback(filepath):
    """Returns True if any part (ie: directory or file) of the |filepath| starts
     with one of the |whitelisted_names| or has an extension but does not end
     with one of the |blacklisted_extensions|.
    """
    path_components = os.path.normpath(filepath).split(os.sep)
    # Is it a whitelisted binary?
    if any(
        component.startswith(whitelisted_names)
        for component in path_components):
      return True

    basename = os.path.basename(filepath)
    # Does it have a blacklisted extension?
    if basename.endswith(blacklisted_extensions):
      return False

    # Does it have an extension?
    if '.' in basename:
      return True

    return False

  return file_match_callback


def _remove_scheme(bucket_path):
  """Remove scheme from the bucket path."""
  if '://' not in bucket_path:
    raise BuildManagerException('Invalid bucket path: ' + bucket_path)

  return bucket_path.split('://')[1]


def _get_build_directory(bucket_path, job_name):
  """Return the build directory based on bucket path and job name."""
  builds_directory = environment.get_value('BUILDS_DIR')

  # In case we have a bucket path, we want those to share the same build
  # directory.
  if bucket_path:
    path = _remove_scheme(bucket_path).lstrip('/')
    bucket_path, file_pattern = path.rsplit('/', 1)
    bucket_path = bucket_path.replace('/', '_')

    # Remove similar build types to force them in same directory.
    file_pattern = utils.remove_sub_strings(file_pattern, BUILD_TYPE_SUBSTRINGS)

    file_pattern_hash = utils.string_hash(file_pattern)
    job_directory = '%s_%s' % (bucket_path, file_pattern_hash)
  else:
    job_directory = job_name

  return os.path.join(builds_directory, job_directory)


def _set_random_fuzz_target_for_fuzzing_if_needed(fuzz_targets, target_weights):
  """Sets a random fuzz target for fuzzing."""
  fuzz_target = environment.get_value('FUZZ_TARGET')
  if fuzz_target:
    logs.log('Use previously picked fuzz target %s for fuzzing.' % fuzz_target)
    return fuzz_target

  if not environment.is_engine_fuzzer_job():
    return None

  fuzz_targets = list(fuzz_targets)
  if not fuzz_targets:
    logs.log_error('No fuzz targets found. Unable to pick random one.')
    return None

  environment.set_value('FUZZ_TARGET_COUNT', len(fuzz_targets))

  fuzz_target = fuzzer_selection.select_fuzz_target(fuzz_targets,
                                                    target_weights)
  environment.set_value('FUZZ_TARGET', fuzz_target)
  logs.log('Picked fuzz target %s for fuzzing.' % fuzz_target)

  return fuzz_target


def _setup_build_directories(base_build_dir):
  """Set up build directories for a job."""
  # Create the root build directory for this job.
  shell.create_directory(base_build_dir, create_intermediates=True)

  custom_binary_directory = os.path.join(base_build_dir, 'custom')
  revision_build_directory = os.path.join(base_build_dir, 'revisions')
  sym_build_directory = os.path.join(base_build_dir, 'symbolized')
  sym_debug_build_directory = os.path.join(sym_build_directory, 'debug')
  sym_release_build_directory = os.path.join(sym_build_directory, 'release')
  build_directories = [
      custom_binary_directory, revision_build_directory, sym_build_directory,
      sym_debug_build_directory, sym_release_build_directory
  ]
  for build_directory in build_directories:
    shell.create_directory(build_directory)


def set_environment_vars(search_directories, app_path='APP_PATH',
                         env_prefix=''):
  """Set build-related environment variables (APP_PATH, APP_DIR etc) by walking
  through the build directory."""
  app_name = environment.get_value(env_prefix + 'APP_NAME')
  llvm_symbolizer_filename = environment.get_executable_filename(
      'llvm-symbolizer')
  llvm_symbolizer_path = None
  gn_args_filename = 'args.gn'
  gn_args_path = None
  platform = environment.platform()
  absolute_file_path = None
  app_directory = None

  # Chromium specific folder to ignore.
  initialexe_folder_path = '%sinitialexe' % os.path.sep

  for search_directory in search_directories:
    for root, _, files in shell.walk(search_directory):
      # .dSYM folder contain symbol files on Mac and should
      # not be searched for application binary.
      if platform == 'MAC' and '.dSYM' in root:
        continue

      # Ignore some folders on Windows.
      if (platform == 'WINDOWS' and (initialexe_folder_path in root)):
        continue

      for filename in files:
        if not absolute_file_path and filename == app_name:
          absolute_file_path = os.path.join(root, filename)
          app_directory = os.path.dirname(absolute_file_path)

          # We don't want to change the state of system binaries.
          if not environment.get_value('SYSTEM_BINARY_DIR'):
            os.chmod(absolute_file_path, 0o750)

          environment.set_value(env_prefix + app_path, absolute_file_path)
          environment.set_value(env_prefix + 'APP_DIR', app_directory)

        if not gn_args_path and filename == gn_args_filename:
          gn_args_path = os.path.join(root, gn_args_filename)
          environment.set_value(env_prefix + 'GN_ARGS_PATH', gn_args_path)

        if (not llvm_symbolizer_path and
            filename == llvm_symbolizer_filename and
            not environment.get_value('USE_DEFAULT_LLVM_SYMBOLIZER')):
          llvm_symbolizer_path = os.path.join(root, llvm_symbolizer_filename)
          environment.set_value(env_prefix + 'LLVM_SYMBOLIZER_PATH',
                                llvm_symbolizer_path)


class BaseBuild(object):
  """Represents a build."""

  def __init__(self, base_build_dir):
    self.base_build_dir = base_build_dir

  def last_used_time(self):
    """Return the last used time for the build."""
    timestamp_file_path = os.path.join(self.base_build_dir, TIMESTAMP_FILE)
    timestamp = utils.read_data_from_file(timestamp_file_path, eval_data=True)

    return timestamp or 0

  def delete(self):
    """Delete this build."""
    shell.remove_directory(self.base_build_dir)


class Build(BaseBuild):
  """Repesents a build type at a particular revision."""

  def __init__(self, base_build_dir, revision, build_prefix=''):
    super(Build, self).__init__(base_build_dir)
    self.revision = revision
    self.build_prefix = build_prefix
    self.env_prefix = build_prefix + '_' if build_prefix else ''

  def _reset_cwd(self):
    """Reset current working directory. Needed to clean up build
    without hitting dir-in-use exception on Windows."""
    root_directory = environment.get_value('ROOT_DIR')
    os.chdir(root_directory)

  def _delete_partial_build_file(self):
    """Deletes partial build file (if present). This is needed to make sure we
    clean up build directory if the previous build was partial."""
    partial_build_file_path = os.path.join(self.build_dir, PARTIAL_BUILD_FILE)
    if os.path.exists(partial_build_file_path):
      self.delete()

  def _pre_setup(self):
    """Common pre-setup."""
    self._reset_cwd()
    shell.clear_temp_directory()

    self._delete_partial_build_file()

    if self.base_build_dir:
      _setup_build_directories(self.base_build_dir)

    environment.set_value(self.env_prefix + 'APP_REVISION', self.revision)
    environment.set_value(self.env_prefix + 'APP_PATH', '')
    environment.set_value(self.env_prefix + 'APP_PATH_DEBUG', '')

  def _patch_rpath(self, binary_path, instrumented_library_paths):
    """Patch rpaths of a binary to point to instrumented libraries"""
    rpaths = get_rpaths(binary_path)
    # Discard all RPATHs that aren't relative to build.
    rpaths = [rpath for rpath in rpaths if '$ORIGIN' in rpath]

    for additional_path in reversed(instrumented_library_paths):
      if additional_path not in rpaths:
        rpaths.insert(0, additional_path)

    set_rpaths(binary_path, rpaths)

  def _patch_rpaths(self, instrumented_library_paths):
    """Patch rpaths of builds to point to instrumented libraries."""
    if environment.is_engine_fuzzer_job():
      # Import here as this path is not available in App Engine context.
      from bot.fuzzers import utils as fuzzer_utils

      for target_path in fuzzer_utils.get_fuzz_targets(self.build_dir):
        self._patch_rpath(target_path, instrumented_library_paths)
    else:
      app_path = environment.get_value('APP_PATH')
      if app_path:
        self._patch_rpath(app_path, instrumented_library_paths)

      app_path_debug = environment.get_value('APP_PATH_DEBUG')
      if app_path_debug:
        self._patch_rpath(app_path_debug, instrumented_library_paths)

  def _post_setup_success(self, update_revision=True):
    """Common post-setup."""
    if update_revision:
      self._write_revision()

    # Update timestamp to indicate when this build was last used.
    if self.base_build_dir:
      timestamp_file_path = os.path.join(self.base_build_dir, TIMESTAMP_FILE)
      utils.write_data_to_file(time.time(), timestamp_file_path)

    # Update rpaths if necessary (for e.g. instrumented libraries).
    instrumented_library_paths = environment.get_instrumented_libraries_paths()
    if instrumented_library_paths:
      self._patch_rpaths(instrumented_library_paths)

  def _unpack_build(self,
                    base_build_dir,
                    build_dir,
                    build_url,
                    target_weights=None):
    """Unpacks a build from a build url into the build directory."""
    # Track time taken to unpack builds so that it doesn't silently regress.
    start_time = time.time()

    # Free up memory.
    utils.python_gc()

    # Remove the current build.
    logs.log('Removing build directory %s.' % build_dir)
    if not shell.remove_directory(build_dir, recreate=True):
      logs.log_error('Unable to clear build directory %s.' % build_dir)
      _handle_unrecoverable_error_on_windows()
      return False

    # Decide whether to use cache build archives or not.
    use_cache = environment.get_value('CACHE_STORE', False)

    # Download build archive locally.
    build_local_archive = os.path.join(build_dir, os.path.basename(build_url))

    # Make the disk space necessary for the archive available.
    archive_size = storage.get_download_file_size(
        build_url, build_local_archive, use_cache=True)
    if archive_size is not None and not _make_space(archive_size,
                                                    base_build_dir):
      shell.clear_data_directories()
      logs.log_fatal_and_exit(
          'Failed to make space for download. '
          'Cleared all data directories to free up space, exiting.')

    logs.log('Downloading build from url %s.' % build_url)
    try:
      storage.copy_file_from(
          build_url, build_local_archive, use_cache=use_cache)
    except:
      logs.log_error('Unable to download build url %s.' % build_url)
      return False

    unpack_everything = environment.get_value(
        'UNPACK_ALL_FUZZ_TARGETS_AND_FILES')
    if not unpack_everything:
      # For fuzzing, pick a random fuzz target so that we only un-archive that
      # particular fuzz target and its dependencies and save disk space.  If we
      # are going to unpack everythng in archive based on
      # |UNPACK_ALL_FUZZ_TARGETS_AND_FILES| in the job defition, then don't set
      # a random fuzz target before we've unpacked the build. It won't actually
      # save us anything in this case and can be really expensive for large
      # builds (such as Chrome OS). Defer setting it until after the build has
      # been unpacked.
      _set_random_fuzz_target_for_fuzzing_if_needed(
          self._get_fuzz_targets_from_archive(build_local_archive),
          target_weights)

    # Actual list of files to unpack can be smaller if we are only unarchiving
    # a particular fuzz target.
    file_match_callback = _get_file_match_callback()
    assert not (unpack_everything and file_match_callback is not None)

    if not _make_space_for_build(build_local_archive, base_build_dir,
                                 file_match_callback):
      shell.clear_data_directories()
      logs.log_fatal_and_exit(
          'Failed to make space for build. '
          'Cleared all data directories to free up space, exiting.')

    # Unpack the local build archive.
    logs.log('Unpacking build archive %s.' % build_local_archive)
    trusted = not utils.is_oss_fuzz()
    try:
      archive.unpack(
          build_local_archive,
          build_dir,
          trusted=trusted,
          file_match_callback=file_match_callback)
    except:
      logs.log_error('Unable to unpack build archive %s.' % build_local_archive)
      return False

    if unpack_everything:
      # Set a random fuzz target now that the build has been unpacked, if we
      # didn't set one earlier. For an auxiliary build, fuzz target is already
      # specified during main build unpacking.
      _set_random_fuzz_target_for_fuzzing_if_needed(
          self._get_fuzz_targets_from_dir(build_dir), target_weights)

    # If this is partial build due to selected build files, then mark it as such
    # so that it is not re-used.
    if file_match_callback:
      partial_build_file_path = os.path.join(build_dir, PARTIAL_BUILD_FILE)
      utils.write_data_to_file('', partial_build_file_path)

    # No point in keeping the archive around.
    shell.remove_file(build_local_archive)

    end_time = time.time()
    elapsed_time = end_time - start_time
    log_func = logs.log_warn if elapsed_time > UNPACK_TIME_LIMIT else logs.log
    log_func('Build took %0.02f minutes to unpack.' % (elapsed_time / 60.))

    return True

  def _get_fuzz_targets_from_archive(self, archive_path):
    """Get iterator of fuzz targets from archive path."""
    # Import here as this path is not available in App Engine context.
    from bot.fuzzers import utils as fuzzer_utils

    for archive_file in archive.iterator(archive_path):
      if fuzzer_utils.is_fuzz_target_local(archive_file.name,
                                           archive_file.handle):
        fuzz_target = os.path.splitext(os.path.basename(archive_file.name))[0]
        yield fuzz_target

  def _get_fuzz_targets_from_dir(self, build_dir):
    """Get iterator of fuzz targets from build dir."""
    # Import here as this path is not available in App Engine context.
    from bot.fuzzers import utils as fuzzer_utils

    for path in fuzzer_utils.get_fuzz_targets(build_dir):
      yield os.path.splitext(os.path.basename(path))[0]

  def setup(self):
    """Set up the build on disk, and set all the necessary environment
    variables. Should return whether or not build setup succeeded."""
    raise NotImplementedError

  @property
  def build_dir(self):
    """The build directory. Usually a subdirectory of base_build_dir."""
    raise NotImplementedError

  def exists(self):
    """Check if build already exists."""
    revision_file = os.path.join(self.build_dir, REVISION_FILE_NAME)
    if os.path.exists(revision_file):
      file_handle = open(revision_file, 'r')
      try:
        current_revision = int(file_handle.read())
      except ValueError:
        current_revision = -1
      file_handle.close()

      # We have the revision required locally, no more work to do, other than
      # setting application path environment variables.
      if self.revision == current_revision:
        return True

    return False

  def delete(self):
    """Delete this build."""
    # This overrides BaseBuild.delete (which deletes the entire base build
    # directory) to delete this specific build.
    shell.remove_directory(self.build_dir)

  def _write_revision(self):
    revision_file = os.path.join(self.build_dir, REVISION_FILE_NAME)
    revisions.write_revision_to_revision_file(revision_file, self.revision)

  def _setup_application_path(self,
                              build_dir=None,
                              app_path='APP_PATH',
                              build_update=False):
    """Sets up APP_PATH environment variables for revision build."""
    logs.log('Setup application path.')

    if not build_dir:
      build_dir = self.build_dir

    # Make sure to initialize so that we don't carry stale values
    # in case of errors. app_path can be APP_PATH or APP_PATH_DEBUG.
    app_path = self.env_prefix + app_path
    environment.set_value(app_path, '')
    environment.set_value(self.env_prefix + 'APP_DIR', '')
    environment.set_value(self.env_prefix + 'BUILD_DIR', build_dir)
    environment.set_value(self.env_prefix + 'GN_ARGS_PATH', '')
    environment.set_value(self.env_prefix + 'LLVM_SYMBOLIZER_PATH',
                          environment.get_default_tool_path('llvm-symbolizer'))

    # Initialize variables.
    fuzzer_directory = environment.get_value('FUZZER_DIR')
    search_directories = [build_dir]
    if fuzzer_directory:
      search_directories.append(fuzzer_directory)

    set_environment_vars(
        search_directories, app_path=app_path, env_prefix=self.env_prefix)

    absolute_file_path = environment.get_value(app_path)
    app_directory = environment.get_value(self.env_prefix + 'APP_DIR')

    if not absolute_file_path:
      return

    # Set the symlink if needed.
    symbolic_link_target = environment.get_value(self.env_prefix +
                                                 'SYMBOLIC_LINK')
    if symbolic_link_target:
      os.system('mkdir --parents %s' % os.path.dirname(symbolic_link_target))
      os.system('rm %s' % symbolic_link_target)
      os.system('ln -s %s %s' % (app_directory, symbolic_link_target))

    if utils.is_chromium():
      # Use deterministic fonts when available. See crbug.com/822737.
      # For production builds (stable, beta), assume that they support it.
      if not isinstance(self.revision, int) or self.revision >= 635076:
        environment.set_value('FONTCONFIG_SYSROOT', app_directory)
      else:
        # Remove if set during previous iterations of regression testing.
        environment.remove_key('FONTCONFIG_SYSROOT')

    if not environment.is_android():
      return

    android.device.update_build(absolute_file_path, force_update=build_update)


class RegularBuild(Build):
  """Represents a regular build."""

  def __init__(self,
               base_build_dir,
               revision,
               build_url,
               target_weights=None,
               build_prefix=''):
    super(RegularBuild, self).__init__(base_build_dir, revision, build_prefix)
    self.build_url = build_url

    if build_prefix:
      self.build_dir_name = build_prefix.lower()
    else:
      self.build_dir_name = 'revisions'

    self._build_dir = os.path.join(self.base_build_dir, self.build_dir_name)
    self.target_weights = target_weights

  @property
  def build_dir(self):
    return self._build_dir

  def setup(self):
    """Sets up build with a particular revision."""
    self._pre_setup()
    environment.set_value(self.env_prefix + 'BUILD_URL', self.build_url)

    logs.log('Retrieving build r%d.' % self.revision)
    build_update = not self.exists()
    if build_update:
      if not self._unpack_build(self.base_build_dir, self.build_dir,
                                self.build_url, self.target_weights):
        return False

      logs.log('Retrieved build r%d.' % self.revision)
    else:
      _set_random_fuzz_target_for_fuzzing_if_needed(
          self._get_fuzz_targets_from_dir(self.build_dir), self.target_weights)

      # We have the revision required locally, no more work to do, other than
      # setting application path environment variables.
      logs.log('Build already exists.')

    self._setup_application_path(build_update=build_update)
    self._post_setup_success(update_revision=build_update)

    return True


class FuchsiaBuild(RegularBuild):
  """Represents a Fuchsia build."""

  SYMBOLIZE_REL_PATH = os.path.join('build', 'zircon', 'prebuilt', 'downloads',
                                    'symbolize')
  LLVM_SYMBOLIZER_REL_PATH = os.path.join('build', 'buildtools', 'linux-x64',
                                          'clang', 'bin', 'llvm-symbolizer')
  FUCHSIA_BUILD_REL_PATH = os.path.join('build', 'out', 'default')
  FUCHSIA_DIR_REL_PATH = 'build'

  def _get_fuzz_targets_from_dir(self, build_dir):
    """Overridden to get targets list from fuchsia."""
    # Prevent App Engine import issues.
    from platforms.fuchsia.util.fuzzer import Fuzzer
    from platforms.fuchsia.util.host import Host
    host = Host.from_dir(os.path.join(build_dir, self.FUCHSIA_BUILD_REL_PATH))

    sanitizer = environment.get_memory_tool_name(
        environment.get_value('JOB_NAME')).lower()
    return [
        str(target[0] + '/' + target[1]) for target in Fuzzer.filter(
            host.fuzzers, '', sanitizer, example_fuzzers=False)
    ]

  def setup(self):
    """Fuchsia build setup."""
    # Prevent App Engine import issues.
    from platforms import fuchsia
    new_setup = not self.exists()

    # Need to be set before fuchsia utils is called in setup().
    environment.set_value(
        'FUCHSIA_DIR', os.path.join(self.build_dir, self.FUCHSIA_DIR_REL_PATH))
    environment.set_value('FUCHSIA_RESOURCES_DIR', self.build_dir)

    assert environment.get_value('UNPACK_ALL_FUZZ_TARGETS_AND_FILES'), \
        'Fuchsia does not support partial unpacks'
    result = super(FuchsiaBuild, self).setup()
    if not result:
      return result

    # We set these values here, rather than in initial_qemu_setup, since
    # SYMBOLIZE_REL_PATH and LLVM_SYMBOLIZER_REL_PATH are properties of the
    # Build object.
    symbolize_path = os.path.join(self.build_dir, self.SYMBOLIZE_REL_PATH)
    os.chmod(symbolize_path, 0o777)
    llvm_symbolizer_path = os.path.join(self.build_dir,
                                        self.LLVM_SYMBOLIZER_REL_PATH)
    os.chmod(llvm_symbolizer_path, 0o777)

    logs.log('Initializing QEMU.')

    # Kill any stale processes that may be left over from previous build.
    fuchsia.device.stop_qemu()
    if new_setup:
      fuchsia.device.initial_qemu_setup()

    fuchsia.device.start_qemu()
    return result


class SymbolizedBuild(Build):
  """Symbolized build."""

  def __init__(self, base_build_dir, revision, release_build_url,
               debug_build_url):
    super(SymbolizedBuild, self).__init__(base_build_dir, revision)
    self._build_dir = os.path.join(self.base_build_dir, 'symbolized')
    self.release_build_dir = os.path.join(self.build_dir, 'release')
    self.debug_build_dir = os.path.join(self.build_dir, 'debug')

    self.release_build_url = release_build_url
    self.debug_build_url = debug_build_url

  @property
  def build_dir(self):
    return self._build_dir

  def _unpack_builds(self):
    """Download and unpack builds."""
    if not shell.remove_directory(self.build_dir, recreate=True):
      logs.log_error('Unable to clear symbolized build directory.')
      _handle_unrecoverable_error_on_windows()
      return False

    if not self.release_build_url and not self.debug_build_url:
      return False

    if self.release_build_url:
      if not self._unpack_build(self.base_build_dir, self.release_build_dir,
                                self.release_build_url):
        return False

    if self.debug_build_url:
      if not self._unpack_build(self.base_build_dir, self.debug_build_dir,
                                self.debug_build_url):
        return False

    return True

  def setup(self):
    self._pre_setup()
    logs.log('Retrieving symbolized build r%d.' % self.revision)

    build_update = not self.exists()
    if build_update:
      if not self._unpack_builds():
        return False

      logs.log('Retrieved symbolized build r%d.' % self.revision)
    else:
      logs.log('Build already exists.')

    if self.release_build_url:
      self._setup_application_path(
          self.release_build_dir, build_update=build_update)
      environment.set_value('BUILD_URL', self.release_build_url)

    if self.debug_build_url:
      # Note: this will override LLVM_SYMBOLIZER_PATH, APP_DIR etc from the
      # previous release setup, which may not be desirable behaviour.
      self._setup_application_path(
          self.debug_build_dir, 'APP_PATH_DEBUG', build_update=build_update)

    self._post_setup_success(update_revision=build_update)
    return True


class ProductionBuild(Build):
  """Production build."""

  def __init__(self, base_build_dir, version, build_url, build_type):
    super(ProductionBuild, self).__init__(base_build_dir, version)
    self.build_url = build_url
    self.build_type = build_type
    self._build_dir = os.path.join(self.base_build_dir, self.build_type)

  @property
  def build_dir(self):
    return self._build_dir

  def setup(self):
    """Sets up build with a particular revision."""
    self._pre_setup()
    logs.log('Retrieving %s branch (%s).' % (self.build_type, self.revision))
    environment.set_value('BUILD_URL', self.build_url)

    version_file = os.path.join(self.build_dir, 'VERSION')
    build_update = revisions.needs_update(version_file, self.revision)

    if build_update:
      if not self._unpack_build(self.base_build_dir, self.build_dir,
                                self.build_url):
        return False

      revisions.write_revision_to_revision_file(version_file, self.revision)
      logs.log('Retrieved %s branch (%s).' % (self.build_type, self.revision))
    else:
      logs.log('Build already exists.')

    self._setup_application_path(build_update=build_update)

    # 'VERSION' file already written.
    self._post_setup_success(update_revision=False)
    return True


class CustomBuild(Build):
  """Custom binary."""

  def __init__(self,
               base_build_dir,
               custom_binary_key,
               custom_binary_filename,
               custom_binary_revision,
               target_weights=None):
    super(CustomBuild, self).__init__(base_build_dir, custom_binary_revision)
    self.custom_binary_key = custom_binary_key
    self.custom_binary_filename = custom_binary_filename
    self._build_dir = os.path.join(self.base_build_dir, 'custom')
    self.target_weights = target_weights

  @property
  def build_dir(self):
    return self._build_dir

  def _unpack_custom_build(self):
    """Unpack the custom build."""
    if not shell.remove_directory(self.build_dir, recreate=True):
      logs.log_error('Unable to clear custom binary directory.')
      _handle_unrecoverable_error_on_windows()
      return False

    build_local_archive = os.path.join(self.build_dir,
                                       self.custom_binary_filename)
    if not blobs.read_blob_to_disk(self.custom_binary_key, build_local_archive):
      return False

    # If custom binary is an archive, then unpack it.
    if archive.is_archive(self.custom_binary_filename):
      if not _make_space_for_build(build_local_archive, self.base_build_dir):
        # Remove downloaded archive to free up space and otherwise, it won't get
        # deleted until next job run.
        shell.remove_file(build_local_archive)

        logs.log_fatal_and_exit('Could not make space for build.')

      try:
        archive.unpack(build_local_archive, self.build_dir, trusted=True)
      except:
        logs.log_error(
            'Unable to unpack build archive %s.' % build_local_archive)
        return False

      # Remove the archive.
      shell.remove_file(build_local_archive)

    _set_random_fuzz_target_for_fuzzing_if_needed(
        self._get_fuzz_targets_from_dir(self.build_dir), self.target_weights)
    return True

  def setup(self):
    """Set up the custom binary for a particular job."""
    self._pre_setup()

    # Track the key for the custom binary so we can create a download link
    # later.
    environment.set_value('BUILD_KEY', self.custom_binary_key)

    logs.log('Retrieving custom binary build r%d.' % self.revision)

    revision_file = os.path.join(self.build_dir, REVISION_FILE_NAME)
    build_update = revisions.needs_update(revision_file, self.revision)

    if build_update:
      if not self._unpack_custom_build():
        return False

      logs.log('Retrieved custom binary build r%d.' % self.revision)
    else:
      logs.log('Build already exists.')

      _set_random_fuzz_target_for_fuzzing_if_needed(
          self._get_fuzz_targets_from_dir(self.build_dir), self.target_weights)

    self._setup_application_path(build_update=build_update)
    self._post_setup_success(update_revision=build_update)
    return True


class SystemBuild(Build):
  """System binary."""

  def __init__(self, system_binary_directory):
    super(SystemBuild, self).__init__(None, 1)
    self._build_dir = system_binary_directory

  @property
  def build_dir(self):
    return self._build_dir

  def setup(self):
    """Set up a build that we assume is already installed on the system."""
    self._pre_setup()
    self._setup_application_path()
    return True

  def delete(self):
    raise BuildManagerException('Cannot delete system build.')


def _sort_build_urls_by_revision(build_urls, bucket_path, reverse):
  """Return a sorted list of build url by revision."""
  base_url = os.path.dirname(bucket_path)
  file_pattern = os.path.basename(bucket_path)
  filename_by_revision_dict = {}

  _, base_path = storage.get_bucket_name_and_path(base_url)
  base_path_with_seperator = base_path + '/' if base_path else ''

  for build_url in build_urls:
    match_pattern = '{base_path_with_seperator}({file_pattern})'.format(
        base_path_with_seperator=base_path_with_seperator,
        file_pattern=file_pattern)
    match = re.match(match_pattern, build_url)
    if match:
      filename = match.group(1)
      revision = match.group(2)

      # Ensure that there are no duplicate revisions.
      if revision in filename_by_revision_dict:
        job_name = environment.get_value('JOB_NAME')
        raise errors.BadStateError(
            'Found duplicate revision %s when processing bucket. '
            'Bucket path is probably malformed for job %s.' % (revision,
                                                               job_name))

      filename_by_revision_dict[revision] = filename

  try:
    sorted_revisions = sorted(
        filename_by_revision_dict,
        reverse=reverse,
        key=lambda x: list(map(int, x.split('.'))))
  except:
    logs.log_warn(
        'Revision pattern is not an integer, falling back to string sort.')
    sorted_revisions = sorted(filename_by_revision_dict, reverse=reverse)

  sorted_build_urls = []
  for revision in sorted_revisions:
    filename = filename_by_revision_dict[revision]
    sorted_build_urls.append('%s/%s' % (base_url, filename))

  return sorted_build_urls


def get_build_urls_list(bucket_path, reverse=True):
  """Returns a sorted list of build urls from a bucket path."""
  if not bucket_path:
    return []

  base_url = os.path.dirname(bucket_path)
  if environment.is_running_on_app_engine():
    build_urls = list(storage.list_blobs(base_url))
  else:
    keys_directory = environment.get_value('BUILD_URLS_DIR')
    keys_filename = '%s.list' % utils.string_hash(bucket_path)
    keys_file_path = os.path.join(keys_directory, keys_filename)

    # For one task, keys file that is cached locally should be re-used.
    # Otherwise, we do waste lot of network bandwidth calling and getting the
    # same set of urls (esp for regression and progression testing).
    if not os.path.exists(keys_file_path):
      # Get url list by reading the GCS bucket.
      with open(keys_file_path, 'w') as f:
        for path in storage.list_blobs(base_url):
          f.write(path + '\n')

    content = utils.read_data_from_file(
        keys_file_path, eval_data=False).decode('utf-8')
    if not content:
      return []

    build_urls = content.splitlines()

  return _sort_build_urls_by_revision(build_urls, bucket_path, reverse)


def get_primary_bucket_path():
  """Get the main bucket path for the current job."""
  release_build_bucket_path = environment.get_value('RELEASE_BUILD_BUCKET_PATH')
  if release_build_bucket_path:
    return release_build_bucket_path

  fuzz_target_build_bucket_path = environment.get_value(
      'FUZZ_TARGET_BUILD_BUCKET_PATH')
  if fuzz_target_build_bucket_path:
    fuzz_target = environment.get_value('FUZZ_TARGET')
    if not fuzz_target:
      raise BuildManagerException('FUZZ_TARGET is not defined.')

    return fuzz_target_build_bucket_path.replace('%TARGET%', fuzz_target)

  raise BuildManagerException(
      'RELEASE_BUILD_BUCKET_PATH or FUZZ_TARGET_BUILD_BUCKET_PATH '
      'needs to be defined.')


def get_revisions_list(bucket_path, testcase=None):
  """Returns a sorted ascending list of revisions from a bucket path, excluding
  bad build revisions and testcase crash revision (if any)."""
  revision_pattern = revisions.revision_pattern_from_build_bucket_path(
      bucket_path)

  revision_urls = get_build_urls_list(bucket_path, reverse=False)
  if not revision_urls:
    return None

  # Parse the revisions out of the build urls.
  revision_list = []
  for url in revision_urls:
    match = re.match(revision_pattern, url)
    if match:
      revision = revisions.convert_revision_to_integer(match.group(1))
      revision_list.append(revision)

  # Remove revisions for bad builds from the revision list.
  job_type = environment.get_value('JOB_NAME')
  bad_builds = ndb_utils.get_all_from_query(
      data_types.BuildMetadata.query(
          ndb_utils.is_true(data_types.BuildMetadata.bad_build),
          data_types.BuildMetadata.job_type == job_type))
  for bad_build in bad_builds:
    # Don't remove testcase revision even if it is in bad build list. This
    # usually happens when a bad bot sometimes marks a particular revision as
    # bad due to flakiness.
    if testcase and bad_build.revision == testcase.crash_revision:
      continue

    if bad_build.revision in revision_list:
      revision_list.remove(bad_build.revision)

  return revision_list


def _get_targets_list(bucket_path):
  """Get the target list for a given fuzz target bucket path. This is done by
  reading the targets.list file, which contains a list of the currently active
  fuzz targets."""
  bucket_dir_path = os.path.dirname(os.path.dirname(bucket_path))
  targets_list_path = os.path.join(bucket_dir_path, TARGETS_LIST_FILENAME)
  data = storage.read_data(targets_list_path)
  if not data:
    return None

  # Filter out targets which are not yet built.
  targets = data.decode('utf-8').splitlines()
  listed_targets = set(
      os.path.basename(path.rstrip('/'))
      for path in storage.list_blobs(bucket_dir_path, recursive=False))
  return [t for t in targets if t in listed_targets]


def _setup_split_targets_build(bucket_path, target_weights, revision=None):
  """Set up targets build."""
  targets_list = _get_targets_list(bucket_path)
  if not targets_list:
    raise BuildManagerException(
        'No targets found in targets.list (path=%s).' % bucket_path)

  fuzz_target = _set_random_fuzz_target_for_fuzzing_if_needed(
      targets_list, target_weights)
  if not fuzz_target:
    raise BuildManagerException(
        'Failed to choose a fuzz target (path=%s).' % bucket_path)

  fuzz_target_bucket_path = bucket_path.replace('%TARGET%', fuzz_target)
  if not revision:
    revision = _get_latest_revision([fuzz_target_bucket_path])

  return setup_regular_build(revision, bucket_path=fuzz_target_bucket_path)


def _get_latest_revision(bucket_paths):
  """Get the latest revision."""
  build_urls = []
  for bucket_path in bucket_paths:
    urls_list = get_build_urls_list(bucket_path)
    if not urls_list:
      logs.log_error('Error getting list of build urls from %s.' % bucket_path)
      return None

    build_urls.append(BuildUrls(bucket_path=bucket_path, urls_list=urls_list))

  main_build_urls = build_urls[0]
  other_build_urls = build_urls[1:]

  revision_pattern = revisions.revision_pattern_from_build_bucket_path(
      main_build_urls.bucket_path)
  for build_url in main_build_urls.urls_list:
    match = re.match(revision_pattern, build_url)
    if not match:
      continue

    revision = revisions.convert_revision_to_integer(match.group(1))
    if (not other_build_urls or all(
        revisions.find_build_url(url.bucket_path, url.urls_list, revision)
        for url in other_build_urls)):
      return revision

  return None


def setup_trunk_build(bucket_paths, build_prefix=None, target_weights=None):
  """Sets up latest trunk build."""
  latest_revision = _get_latest_revision(bucket_paths)
  if latest_revision is None:
    logs.log_error('Unable to find a matching revision.')
    return None

  build = setup_regular_build(
      latest_revision,
      bucket_path=bucket_paths[0],
      build_prefix=build_prefix,
      target_weights=target_weights)
  if not build:
    logs.log_error('Failed to set up a build.')
    return None

  return build


def setup_regular_build(revision,
                        bucket_path=None,
                        build_prefix='',
                        target_weights=None):
  """Sets up build with a particular revision."""
  if not bucket_path:
    # Bucket path can be customized, otherwise get it from the default env var.
    bucket_path = environment.get_value('RELEASE_BUILD_BUCKET_PATH')

  build_urls = get_build_urls_list(bucket_path)
  job_type = environment.get_value('JOB_NAME')
  if not build_urls:
    logs.log_error('Error getting build urls for job %s.' % job_type)
    return None
  build_url = revisions.find_build_url(bucket_path, build_urls, revision)
  if not build_url:
    logs.log_error(
        'Error getting build url for job %s (r%d).' % (job_type, revision))

    return None

  base_build_dir = _base_build_dir(bucket_path)

  build_class = RegularBuild
  if environment.is_trusted_host():
    from bot.untrusted_runner import build_setup_host
    build_class = build_setup_host.RemoteRegularBuild
  elif environment.platform() == 'FUCHSIA':
    build_class = FuchsiaBuild

  build = build_class(
      base_build_dir,
      revision,
      build_url,
      target_weights=target_weights,
      build_prefix=build_prefix)
  if build.setup():
    return build
  return None


def setup_symbolized_builds(revision):
  """Set up symbolized release and debug build."""
  sym_release_build_bucket_path = environment.get_value(
      'SYM_RELEASE_BUILD_BUCKET_PATH')
  sym_debug_build_bucket_path = environment.get_value(
      'SYM_DEBUG_BUILD_BUCKET_PATH')

  sym_release_build_urls = get_build_urls_list(sym_release_build_bucket_path)
  sym_debug_build_urls = get_build_urls_list(sym_debug_build_bucket_path)

  # We should at least have a symbolized debug or release build.
  if not sym_release_build_urls and not sym_debug_build_urls:
    logs.log_error(
        'Error getting list of symbolized build urls from (%s, %s).' %
        (sym_release_build_bucket_path, sym_debug_build_bucket_path))
    return None

  sym_release_build_url = revisions.find_build_url(
      sym_release_build_bucket_path, sym_release_build_urls, revision)
  sym_debug_build_url = revisions.find_build_url(sym_debug_build_bucket_path,
                                                 sym_debug_build_urls, revision)

  base_build_dir = _base_build_dir(sym_release_build_bucket_path)

  build_class = SymbolizedBuild
  if environment.is_trusted_host():
    from bot.untrusted_runner import build_setup_host
    build_class = build_setup_host.RemoteSymbolizedBuild

  build = build_class(base_build_dir, revision, sym_release_build_url,
                      sym_debug_build_url)
  if build.setup():
    return build

  return None


def setup_custom_binary(target_weights=None):
  """Set up the custom binary for a particular job."""
  # Check if this build is dependent on any other custom job. If yes,
  # then fake out our job name for setting up the build.
  old_job_name = ''
  share_build_job_type = environment.get_value('SHARE_BUILD_WITH_JOB_TYPE')
  if share_build_job_type:
    job_name = share_build_job_type
    old_job_name = environment.get_value('JOB_NAME', '')
    environment.set_value('JOB_NAME', job_name)
  else:
    job_name = environment.get_value('JOB_NAME', '')

  # Verify that this is really a custom binary job.
  job = data_types.Job.query(data_types.Job.name == job_name).get()
  if not job or not job.custom_binary_key or not job.custom_binary_filename:
    logs.log_error(
        'Job does not have a custom binary, even though CUSTOM_BINARY is set.')
    return False

  base_build_dir = _base_build_dir('')
  build = CustomBuild(
      base_build_dir,
      job.custom_binary_key,
      job.custom_binary_filename,
      job.custom_binary_revision,
      target_weights=target_weights)

  # Revert back the actual job name.
  if share_build_job_type:
    environment.set_value('JOB_NAME', old_job_name)

  if build.setup():
    return build

  return None


def setup_production_build(build_type):
  """Sets up build with a particular revision."""
  # Bail out if there are not stable and beta build urls.
  if build_type == 'stable':
    build_bucket_path = environment.get_value('STABLE_BUILD_BUCKET_PATH')
  elif build_type == 'beta':
    build_bucket_path = environment.get_value('BETA_BUILD_BUCKET_PATH')
  else:
    logs.log_error('Unknown build type %s.' % build_type)
    return None

  build_urls = get_build_urls_list(build_bucket_path)
  if not build_urls:
    logs.log_error(
        'Error getting list of build urls from %s.' % build_bucket_path)
    return None

  # First index is the latest build for that version.
  build_url = build_urls[0]
  version_pattern = environment.get_value('VERSION_PATTERN')
  v_match = re.match(version_pattern, build_url)
  if not v_match:
    logs.log_error(
        'Unable to find version information from the build url %s.' % build_url)
    return None

  version = v_match.group(1)
  base_build_dir = _base_build_dir(build_bucket_path)

  build_class = ProductionBuild
  if environment.is_trusted_host():
    from bot.untrusted_runner import build_setup_host
    build_class = build_setup_host.RemoteProductionBuild

  build = build_class(base_build_dir, version, build_url, build_type)

  if build.setup():
    return build

  return None


def setup_system_binary():
  """Set up a build that we assume is already installed on the system."""
  system_binary_directory = environment.get_value('SYSTEM_BINARY_DIR', '')
  build = SystemBuild(system_binary_directory)
  if build.setup():
    return build

  return None


def setup_build(revision=0, target_weights=None):
  """Set up a custom or regular build based on revision."""
  # For custom binaries we always use the latest version. Revision is ignored.
  custom_binary = environment.get_value('CUSTOM_BINARY')
  if custom_binary:
    return setup_custom_binary(target_weights=target_weights)

  # In this case, we assume the build is already installed on the system.
  system_binary = environment.get_value('SYSTEM_BINARY_DIR')
  if system_binary:
    return setup_system_binary()

  fuzz_target_build_bucket_path = environment.get_value(
      'FUZZ_TARGET_BUILD_BUCKET_PATH')
  if fuzz_target_build_bucket_path:
    # Split fuzz target build.
    return _setup_split_targets_build(
        fuzz_target_build_bucket_path, target_weights, revision=revision)

  if revision:
    # Setup regular build with revision.
    return setup_regular_build(revision, target_weights=target_weights)

  # If no revision is provided, we default to a trunk build.
  bucket_paths = []
  for env_var in DEFAULT_BUILD_BUCKET_PATH_ENV_VARS:
    bucket_path = environment.get_value(env_var)
    if bucket_path:
      bucket_paths.append(bucket_path)

  return setup_trunk_build(bucket_paths, target_weights=target_weights)


def is_custom_binary():
  """Determine if this is a custom or preinstalled system binary."""
  return (environment.get_value('CUSTOM_BINARY') or
          environment.get_value('SYSTEM_BINARY_DIR'))


def has_production_builds():
  """Return a bool on if job type has build urls for stable and beta builds."""
  return (environment.get_value('STABLE_BUILD_BUCKET_PATH') and
          environment.get_value('BETA_BUILD_BUCKET_PATH'))


def has_symbolized_builds():
  """Return a bool on if job type has either a release or debug build for stack
  symbolization."""
  return (environment.get_value('SYM_RELEASE_BUILD_BUCKET_PATH') or
          environment.get_value('SYM_DEBUG_BUILD_BUCKET_PATH'))


def _set_rpaths_chrpath(binary_path, rpaths):
  """Set rpaths using chrpath."""
  chrpath = environment.get_default_tool_path('chrpath')
  if not chrpath:
    raise BuildManagerException('Failed to find chrpath')

  subprocess.check_output(
      [chrpath, '-r', ':'.join(rpaths), binary_path], stderr=subprocess.PIPE)


def _set_rpaths_patchelf(binary_path, rpaths):
  """Set rpaths using patchelf."""
  patchelf = spawn.find_executable('patchelf')
  if not patchelf:
    raise BuildManagerException('Failed to find patchelf')

  subprocess.check_output(
      [patchelf, '--force-rpath', '--set-rpath', ':'.join(rpaths), binary_path],
      stderr=subprocess.PIPE)


def set_rpaths(binary_path, rpaths):
  """Set rpath of a binary."""
  # Patchelf handles rpath patching much better, and allows e.g. extending the
  # length of the rpath. However, it loads the entire binary into memory so
  # does not work for large binaries, so use chrpath for larger binaries.
  binary_size = os.path.getsize(binary_path)
  if binary_size >= PATCHELF_SIZE_LIMIT:
    _set_rpaths_chrpath(binary_path, rpaths)
  else:
    _set_rpaths_patchelf(binary_path, rpaths)


def get_rpaths(binary_path):
  """Get rpath of a binary."""
  chrpath = environment.get_default_tool_path('chrpath')
  if not chrpath:
    raise BuildManagerException('Failed to find chrpath')

  try:
    rpaths = subprocess.check_output(
        [chrpath, '-l', binary_path],
        stderr=subprocess.PIPE).strip().decode('utf-8')
  except subprocess.CalledProcessError as e:
    if b'no rpath or runpath tag found' in e.output:
      return []

    raise

  if rpaths:
    search_marker = 'RPATH='
    start_index = rpaths.index(search_marker) + len(search_marker)
    return rpaths[start_index:].split(':')

  return []


def check_app_path(app_path='APP_PATH'):
  """Check if APP_PATH is properly set."""
  # If APP_NAME is not set (e.g. for grey box jobs), then we don't need
  # APP_PATH.
  return (not environment.get_value('APP_NAME') or
          environment.get_value(app_path))
