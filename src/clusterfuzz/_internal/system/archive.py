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
"""Functions for handling archives."""

import abc
import dataclasses
import os
import tarfile
from typing import BinaryIO
from typing import Callable
from typing import List
from typing import Optional
from typing import Union
import zipfile

from clusterfuzz._internal.metrics import logs

FILE_ATTRIBUTE = '0o10'
SYMLINK_ATTRIBUTE = '0o12'

# File extensions for archive files.
ZIP_FILE_EXTENSIONS = ['.zip']
TAR_FILE_EXTENSIONS = [
    '.tar', '.tar.bz2', '.tar.gz', '.tb2', '.tbz', '.tbz2', '.tgz'
]
LZMA_FILE_EXTENSIONS = ['.tar.lzma', '.tar.xz']

ARCHIVE_FILE_EXTENSIONS = (
    ZIP_FILE_EXTENSIONS + TAR_FILE_EXTENSIONS + LZMA_FILE_EXTENSIONS)

StrBytesPathLike = Union[str, bytes, os.PathLike]
MatchCallback = Callable[[str], bool]


def _is_attempting_path_traversal(archive_name: StrBytesPathLike,
                                  output_dir: StrBytesPathLike,
                                  filename: StrBytesPathLike) -> bool:
  """Detects whether there is a path traversal attempt.

  Args:
      archive_name: the name of the archive.
      output_dir: the output directory.
      filename: the name of the file being checked.

  Returns:
      Whether there is a path traversal attempt
  """
  output_dir = os.path.realpath(output_dir)
  absolute_file_path = os.path.join(output_dir, os.path.normpath(filename))
  real_file_path = os.path.realpath(absolute_file_path)

  if real_file_path == output_dir:
    # Workaround for https://bugs.python.org/issue28488.
    # Ignore directories named '.'.
    return False

  if real_file_path != absolute_file_path:
    logs.error('Directory traversal attempted while unpacking archive %s '
               '(file path=%s, actual file path=%s). Aborting.' %
               (archive_name, absolute_file_path, real_file_path))
    return True
  return False


@dataclasses.dataclass
class ArchiveMemberInfo:
  """Represents an archive member. A member can either be a file or a directory.
  Members:
    name: the name of the archive member. It can represent a file or a directory
    name.
    is_dir: whether this member is a directory.
    size_bytes: the extracted size of the member.
    mode: the mode of the member (file system attributes).
  """
  name: str
  is_dir: bool
  size_bytes: int
  mode: int


class ArchiveReader(abc.ABC):
  """Abstract class for representing an archive reader.
  """

  @abc.abstractmethod
  def list_members(self) -> List[ArchiveMemberInfo]:
    """Lists all members contained in the archives.

    Returns:
        List[ArchiveMemberInfo]: All the archive members
    """
    raise NotImplementedError

  @abc.abstractmethod
  def extract(self,
              member: str,
              path: Union[str, os.PathLike],
              trusted: bool = False) -> str:
    """Extracts `member` out of the archive to the provided path.
    If `member` is a directory in the archive, only the directory itself will
    be extracted, not its content.

    Args:
        member: the member name
        path: the path where the member should be extracted.
        trusted: whether the archive is trusted.

    Returns:
        The path to the extracted member
    """
    raise NotImplementedError

  @abc.abstractmethod
  def open(self, member: str) -> BinaryIO:
    """Opens `member`.

    Args:
        member: the member name

    Returns:
        a file-like object that can be `read`.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def close(self) -> None:
    """Closes the archive.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def extract_all(self,
                  path: Union[str, os.PathLike],
                  members: Optional[List[str]] = None,
                  trusted: bool = False) -> None:
    """Extract the whole archive content or the members listed in `members`.

    Args:
        path: the path where the members should be extracted.
        members: the member names.
        trusted: whether the archive is trusted or not.
    """
    raise NotImplementedError

  def try_open(self, member: str) -> Optional[BinaryIO]:
    """Tries to open the archive. Does not throw.

    Args:
        member: the member name

    Returns:
        a file-like object that can be `read` or None if an error occured.
    """
    try:
      return self.open(member)
    except:
      return None

  def get_first_file_matching(self, search_string: str) -> str:
    """Gets the name of the first matching member.

    Args:
        search_string: the string to be searched for.

    Returns:
        the member name that matched.
    """
    for file in self.list_members():
      if file.name.startswith('__MACOSX/'):
        # Exclude MAC resource forks.
        continue

      if search_string in file.name:
        return file.name
    return None

  def extracted_size(self, file_match_callback: MatchCallback = None) -> int:
    """Gets the total extracted size of the files matched by
    file_match_callback. If file_match_callback is None, gets the extracted
    size of the whole archive.

    Args:
        file_match_callback: the file matching callback.

    Returns:
        the sum of the extract size in bytes of members matched with the
        callback. If the callback isn't specified, returns the extracted size
        of the whole archive.
    """
    return sum(f.size_bytes
               for f in self.list_members()
               if not file_match_callback or file_match_callback(f.name))


class TarArchiveReader(ArchiveReader):
  """A tar archive reader. Currently supports TAR and TAR_LZMA archives.
  """

  def __init__(self,
               archive_path: Union[str, os.PathLike],
               file_obj: BinaryIO = None) -> None:
    if file_obj:
      self._archive = tarfile.open(fileobj=file_obj)
    else:
      archive_type = get_archive_type(archive_path)
      mode = 'r' if archive_type == ArchiveType.TAR else 'r:xz'
      self._archive = tarfile.open(archive_path, mode=mode)
    self._archive_path = archive_path

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self._archive.close()

  def list_members(self) -> List[ArchiveMemberInfo]:
    return [
        ArchiveMemberInfo(
            name=f.name, is_dir=f.isdir(), size_bytes=f.size, mode=f.mode)
        for f in self._archive.getmembers()
    ]

  def open(self, member: str):
    return self._archive.extractfile(member)

  def close(self) -> None:
    self._archive.close()

  def extract(self,
              member: str,
              path: Union[str, os.PathLike],
              trusted: bool = False):
    # If the output directory is a symlink, get its actual path since we will be
    # doing directory traversal checks later when unpacking the archive.
    output_directory = os.path.realpath(path)

    if not trusted:
      if (_is_attempting_path_traversal(self._archive_path, output_directory,
                                        member)):
        return None

    self._archive.extract(member=member, path=output_directory)
    return os.path.realpath(os.path.join(output_directory, member))

  def extract_all(self,
                  path: Union[str, os.PathLike],
                  members: Optional[List[str]] = None,
                  trusted: bool = False) -> None:
    to_extract = members if members is not None else self._archive.namelist()
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


class ZipArchiveReader(ArchiveReader):
  """A zip archive reader.
  """

  def __init__(self, file) -> None:
    self._zip_archive = zipfile.ZipFile(file, mode='r')

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self._zip_archive.close()

  def list_members(self) -> List[ArchiveMemberInfo]:
    return [
        ArchiveMemberInfo(
            name=f.filename,
            is_dir=f.is_dir(),
            size_bytes=f.file_size,
            mode=(f.external_attr >> 16) & 0o7777)
        for f in self._zip_archive.infolist()
    ]

  def open(self, member):
    return self._zip_archive.open(name=member)

  def close(self) -> None:
    self._zip_archive.close()

  def extract(self,
              member: str,
              path: Union[str, os.PathLike],
              trusted: bool = False):
    # If the output directory is a symlink, get its actual path since we will be
    # doing directory traversal checks later when unpacking the archive.
    output_directory = os.path.realpath(path)

    # If the archive is not trusted, do file path checks to make
    # sure this archive is safe and is not attempting to do path
    # traversals.
    if not trusted:
      if (_is_attempting_path_traversal(self._zip_archive.filename,
                                        output_directory, member)):
        return None

    try:
      extracted_path = self._zip_archive.extract(member, output_directory)

      # Preserve permissions for regular files. 640 is the default
      # permission for extract. If we need execute permission, we need
      # to chmod it explicitly. Also, get rid of suid bit for security
      # reasons.
      external_attr = self._zip_archive.getinfo(member).external_attr >> 16
      if oct(external_attr).startswith(FILE_ATTRIBUTE):
        old_mode = external_attr & 0o7777
        new_mode = external_attr & 0o777
        new_mode |= 0o440
        needs_execute_permission = external_attr & 100

        if new_mode != old_mode or needs_execute_permission:
          # Default extract condition is 640 which is safe.
          # |new_mode| might have read+write+execute bit for
          # others, so remove those.
          new_mode &= 0o770

          os.chmod(extracted_path, new_mode)

      # Create symlink if needed (only on unix platforms).
      if (trusted and hasattr(os, 'symlink') and
          oct(external_attr).startswith(SYMLINK_ATTRIBUTE)):
        symlink_source = self._zip_archive.read(member)
        if os.path.exists(extracted_path):
          os.remove(extracted_path)
        os.symlink(symlink_source, extracted_path)

      return extracted_path
    except Exception as e:
      # In case of errors, we try to extract whatever we can without errors.
      logs.warning('An error occured while extracting %s from the archive: %s.'
                   % (member, repr(e)))
      return None

  def extract_all(self,
                  path: Union[str, os.PathLike],
                  members: Optional[List[str]] = None,
                  trusted: bool = False) -> None:
    to_extract = members if members is not None else self._zip_archive.namelist(
    )
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


class ArchiveError(Exception):
  """ArchiveError"""


# pylint: disable=redefined-builtin
def open(archive_path: str,
         file_obj: Optional[BinaryIO] = None) -> ArchiveReader:
  """Opens the archive and gets the appropriate archive reader based on the
  `archive_path`. If `file_obj` is not none, the binary file-like object will be
  used to read the archive instead of opening `archive_path`.

  Args:
      archive_path: the path to the archive.
      file_obj: a file-like object containing the archive.

  Raises:
      If the file could not be opened or if the archive type cannot be handled.
      See `is_archive()` to check whether the archive type is handled.

  Returns:
      the archive reader.
  """
  archive_type = get_archive_type(archive_path)
  if archive_type == ArchiveType.ZIP:
    return ZipArchiveReader(archive_path or file_obj)
  if archive_type in (ArchiveType.TAR_LZMA, ArchiveType.TAR):
    return TarArchiveReader(archive_path, file_obj=file_obj)
  raise ArchiveError('Unhandled archive type.')


class ArchiveType:
  """Type of the archive."""
  UNKNOWN = 0
  ZIP = 1
  TAR = 2
  TAR_LZMA = 3


def get_archive_type(archive_path: str) -> ArchiveType:
  """Get the type of the archive.

  Args:
      archive_path: the path to the archive.

  Returns:
      the type of the archive, or ArchiveType.UNKNOWN if unknown.
  """

  def has_extension(extensions):
    """Returns True if |archive_path| endswith an extension in |extensions|."""
    for extension in extensions:
      if archive_path.endswith(extension):
        return True
    return False

  if has_extension(ZIP_FILE_EXTENSIONS):
    return ArchiveType.ZIP

  if has_extension(TAR_FILE_EXTENSIONS):
    return ArchiveType.TAR

  if has_extension(LZMA_FILE_EXTENSIONS):
    return ArchiveType.TAR_LZMA

  return ArchiveType.UNKNOWN


def is_archive(filename: str) -> bool:
  """Return true if the file is an archive.

  Args:
      filename: the path to a file.

  Returns:
      whether the provided file is an archive.
  """
  return get_archive_type(filename) != ArchiveType.UNKNOWN


def unpack(reader: ArchiveReader,
           output_dir: Union[str, os.PathLike],
           trusted: bool = False,
           file_match_callback: MatchCallback = None):
  """Unpacks the current archive opened with `reader`. If `file_match_callback`
  is None, unpacks all the archive. Otherwise, this only unpacks the files
  matched by the callback.

  Args:
      reader: the archive reader
      output_dir: the output directory to unpack the archive to.
      trusted: whether the archive is trusted.
      file_match_callback: the file matching callback.

  Returns:
      bool: whether an error occurred.
  """
  assert reader

  file_list = [
      f.name
      for f in reader.list_members()
      if not file_match_callback or file_match_callback(f.name)
  ]

  archive_file_unpack_count = 0
  archive_file_total_count = len(file_list)

  error_occurred = False
  for file in file_list:
    error_occurred |= reader.extract(
        member=file, path=output_dir, trusted=trusted) is None
    # Keep heartbeat happy by updating with our progress.
    archive_file_unpack_count += 1
    if archive_file_unpack_count % 1000 == 0:
      logs.info('Unpacked %d/%d.' % (archive_file_unpack_count,
                                     archive_file_total_count))

  return not error_occurred
