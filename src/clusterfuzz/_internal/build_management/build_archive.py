# Copyright 2024 Google LLC
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
"""Build Archive manager."""

import abc
import os
from typing import BinaryIO
from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive

# Extensions to exclude when unarchiving a fuzz target. Note that fuzz target
# own files like seed corpus, options, etc are covered by its own regex.
FUZZ_TARGET_EXCLUDED_EXTENSIONS = [
    'exe', 'options', 'txt', 'zip', 'exe.pdb', 'par'
]

# File prefixes to explicitly include when unarchiving a fuzz target.
FUZZ_TARGET_ALLOWLISTED_PREFIXES = [
    'afl-cmin',
    'afl-fuzz',
    'afl-showmap',
    'afl-tmin',
    'centipede',
    'honggfuzz',
    'jazzer_agent_deploy.jar',
    'jazzer_driver',
    'jazzer_driver_with_sanitizer',
    'jazzerjs.node',
    'llvm-symbolizer',
    # crbug.com/1471427: chrome_crashpad_handler is needed for fuzzers that are
    # spawning the full chrome browser.
    'chrome_crashpad_handler',
    # This is part of the chrome archives. This directory contains all sort of
    # data needed by tests that initially exist in the source tree.
    'src_root',
]


class BuildArchive(archive.ArchiveReader):
  """Abstract class for representing a build archive. This is mostly an
  enhanced and more specific version of `archive.ArchiveReader`. This
  class inherits from `archive.ArchiveReader`, so this also provides
  class archive management features.
  """

  def __init__(self, reader: archive.ArchiveReader):
    self._reader = reader

  def list_members(self) -> List[archive.ArchiveMemberInfo]:
    return self._reader.list_members()

  def extract(self,
              member: str,
              path: Union[str, os.PathLike],
              trusted: bool = False) -> str:
    return self._reader.extract(member=member, path=path, trusted=trusted)

  def open(self, member: str) -> BinaryIO:
    return self._reader.open(member)

  def close(self) -> None:
    self._reader.close()

  @abc.abstractmethod
  def list_fuzz_targets(self) -> List[str]:
    """Lists fuzzing targets in the archive.

    Returns:
        The list of fuzz targets.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def get_target_dependencies(
      self, fuzz_target: str) -> List[archive.ArchiveMemberInfo]:
    """Gets the target dependencies. This returns all the necessary files in
    order for the fuzzer to run correctly.

    Args:
        fuzz_target: the fuzz target.

    Returns:
        The list of dependencies represented as `archive.ArchiveMemberInfo`.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def unpacked_size(self, fuzz_target: Optional[str] = None) -> int:
    """Gets the total extracted size for the files returned by
    `get_target_dependencies`. In other words this returns the necessary space
    needed in order for the fuzz_target to run correctly.

    Args:
        fuzz_target: the fuzz target. Defaults to None.

    Returns:
        the sum of the extract size in bytes for fuzz_target and all its
        dependencies. If fuzz_target is None, this call is equivalent to
        `extracted_size(None)`.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def unpack(self,
             build_dir: str,
             fuzz_target: Optional[str] = None,
             trusted: bool = False) -> bool:
    """Unpacks the build to build_dir. During this operation, all the
    fuzz_target dependencies will be computed in order to unpack all the
    necessary for the fuzzer to run correctly.

    Args:
        fuzz_target: the fuzz target. Defaults to None.

    Returns:
        whether the unpack was successful or not.
    """
    raise NotImplementedError


class DefaultBuildArchive(BuildArchive):
  """Default class for handling builds. This should work with everything.
  """

  def __init__(self, reader: archive.ArchiveReader):
    super().__init__(reader)
    self._fuzz_targets = {}

  def get_path_for_target(self, fuzz_target: str) -> str:
    """Returns the path in the archive of the fuzz_target if found.
    This is needed because target name normalization means we're losing
    information about the actual file reprensenting the fuzz_target.
    """
    if not self._fuzz_targets:
      self.list_fuzz_targets()

    if not fuzz_target in self._fuzz_targets:
      return None

    return self._fuzz_targets[fuzz_target]

  def get_target_dependencies(
      self, fuzz_target: str) -> List[archive.ArchiveMemberInfo]:
    allowlisted_names = tuple([fuzz_target] + FUZZ_TARGET_ALLOWLISTED_PREFIXES)
    blocklisted_extensions = tuple(
        '.' + extension for extension in FUZZ_TARGET_EXCLUDED_EXTENSIONS)

    to_extract = []
    for file in self.list_members():
      filepath = file.name
      path_components = os.path.normpath(filepath).split(os.sep)
      # Is it an allowlisted binary?
      if any(
          component.startswith(allowlisted_names)
          for component in path_components):
        to_extract.append(file)
        continue

      basename = os.path.basename(filepath)
      # Does it have a blocklisted extension?
      if basename.endswith(blocklisted_extensions):
        continue

      # Does it have an extension?
      if '.' in basename:
        to_extract.append(file)

    return to_extract

  def list_fuzz_targets(self) -> List[str]:
    if self._fuzz_targets:
      return list(self._fuzz_targets.keys())
    # Import here as this path is not available in App Engine context.
    from clusterfuzz._internal.bot.fuzzers import utils as fuzzer_utils

    for archive_file in self.list_members():
      if fuzzer_utils.is_fuzz_target(archive_file.name, self.open):
        fuzz_target = fuzzer_utils.normalize_target_name(archive_file.name)
        self._fuzz_targets[fuzz_target] = archive_file.name

    return list(self._fuzz_targets.keys())

  def unpacked_size(self, fuzz_target: Optional[str] = None) -> int:
    if not fuzz_target:
      return self.extracted_size()

    files = self.get_target_dependencies(fuzz_target=fuzz_target)
    return sum(f.size_bytes for f in files)

  def unpack(self,
             build_dir: str,
             fuzz_target: Optional[str] = None,
             trusted: bool = False) -> bool:
    if not fuzz_target:
      return self.extract_all(build_dir, trusted=trusted)
    files = self.get_target_dependencies(fuzz_target=fuzz_target)
    error_occured = False
    for file in files:
      error_occured |= self.extract(
          file.name, build_dir, trusted=trusted) is None
    return not error_occured


class ChromeBuildArchive(DefaultBuildArchive):
  """Handles chrome build archives. This special cases the default behaviour by
  looking at the content of the `.runtime_deps` file, in order to unpack all the
  fuzzer dependencies correctly.
  In case something goes wrong, this defaults to using the default unpacker.
  """

  def root_dir(self) -> str:
    if not hasattr(self, '_root_dir'):
      self._root_dir = super().root_dir()  # pylint: disable=attribute-defined-outside-init
    return self._root_dir

  def to_archive_path(self, path: str) -> str:
    """Deps are relative to the Chrome root directory. However, there might be
    a common root directory in the archive, which means we need to make sure
    the file path is correct.

    Args:
        path: the dependency path relative to Chrome's root directory.

    Returns:
        the path relative to the archive.
    """
    path = os.path.normpath(path)

    if path.startswith('../../'):
      path = path.replace('../../', 'src_root/')

    return os.path.join(self.root_dir(), path)

  def _get_prefix_matcher(self, prefix: str) -> Callable[[str], bool]:
    return lambda f: f.startswith(prefix)

  def _get_filename_matcher(self, file: str) -> Callable[[str], bool]:
    return lambda f: os.path.basename(f) == file

  def _match_files(self, matchers: List[Callable[[str], bool]]
                  ) -> List[archive.ArchiveMemberInfo]:
    res = []
    for member in self.list_members():
      if any(matcher(member.name) for matcher in matchers):
        res.append(member)
    return res

  def _get_common_files(self) -> List[str]:
    """Those files are always to be extracted.
    """
    return [
        'args.gn',
        'llvm-symbolizer',
    ]

  def get_target_dependencies(
      self, fuzz_target: str) -> List[archive.ArchiveMemberInfo]:
    target_path = self.to_archive_path(fuzz_target)
    deps_file = f'{target_path}.runtime_deps'
    if not self.file_exists(deps_file):
      logs.warning(f'runtime_deps file not found for {target_path}')
      return super().get_target_dependencies(fuzz_target)

    res = []
    matchers = []
    with self.open(deps_file) as f:
      deps = [self.to_archive_path(l.decode()) for l in f.read().splitlines()]
      for dep in deps:
        # We need to match the file prefixes here, because some of the deps are
        # globering the whole directory. Same for files, on mac platform, we
        # also need to extract `dSYM` in order to have debug info.
        matchers.append(self._get_prefix_matcher(dep))

    matchers += [
        self._get_filename_matcher(f) for f in self._get_common_files()
    ]

    res += self._match_files(matchers)
    return res


def open_with_reader(reader: archive.ArchiveReader) -> BuildArchive:
  """Open the archive and gets the appropriate build archive based on the
  provided archive information.

  Args:
      reader: the archive reader.

  Raises:
    If the archive reader cannot be handled.

  Returns:
      The build archive.
  """
  # Unfortunately, there is no good heuristic for determining which build
  # archive implementation to use.
  # Hopefully, we can search in the archive whether some files are present and
  # give us some hints.
  # For instance, chrome build archives are embedding `gn.args`. Let's use
  # this for now.
  # Being wrong is no big deal here, because BuildArchive is designed so that
  # we always fall back on default behaviour.
  args_gn_path = os.path.join(reader.root_dir(), 'args.gn')
  if reader.file_exists(args_gn_path):
    return ChromeBuildArchive(reader)
  return DefaultBuildArchive(reader)


def open(archive_path: str) -> BuildArchive:  # pylint: disable=redefined-builtin
  """Opens the archive and gets the appropriate build archive based on the
  `archive_path`. The resulting object is usable as a normal archive reader,
  but provides additional feature related to build handling.

  Args:
      archive_path: the path to the archive.

  Raises:
      If the file could not be opened or if the archive type cannot be handled.

  Returns:
      The build archive.
  """
  reader = archive.open(archive_path)
  return open_with_reader(reader)


def open_uri(uri: str) -> BuildArchive:
  """Opens a build archive over HTTP. This is only compatible with chromium as
  of now.

  Args:
      uri: the URI pointing to the zip file.

  Returns:
      The build archive.
  """
  reader = archive.ZipArchiveReader(archive.HttpZipFile(uri))
  return open_with_reader(reader)


def unzip_over_http_compatible(build_url: str) -> bool:
  """Whether the build URL is compatible with unzipping over HTTP.
  """
  return archive.HttpZipFile.is_uri_compatible(build_url)
