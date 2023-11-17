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
import typing
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


def _is_attempting_path_traversal(archive_name, output_dir, filename) -> bool:
  """Detects whether there is a path traversal attempt.

  Args:
      archive_name (str): the name of the archive.
      output_dir (str): the output directory.
      filename (str): the name of the file being checked.

  Returns:
      bool: Whether there is a path traversal attempt
  """
  absolute_file_path = os.path.join(output_dir, os.path.normpath(filename))
  real_file_path = os.path.realpath(absolute_file_path)

  if real_file_path == output_dir:
    # Workaround for https://bugs.python.org/issue28488.
    # Ignore directories named '.'.
    return False

  if real_file_path != absolute_file_path:
    logs.log_error('Directory traversal attempted while unpacking archive %s '
                   '(file path=%s, actual file path=%s). Aborting.' %
                   (archive_name, absolute_file_path, real_file_path))
    return True
  return False


@dataclasses.dataclass
class ArchiveMemberInfo:
  """Represents an archive member.
  """
  filename: str
  is_dir: bool
  file_size_bytes: int
  mode: int


class ArchiveReader(abc.ABC):
  """Abstract class for representing an archive reader. Abstract methods must
  be overriden.
  """

  @abc.abstractmethod
  def list_files(self) -> typing.List[ArchiveMemberInfo]:
    """Lists all members contained in the archives.

    Returns:
        typing.List[ArchiveMemberInfo]: All the archive members
    """
    raise NotImplementedError

  @abc.abstractmethod
  def extract(self, member, path, trusted=False) -> str:
    """Extracts `member` out of the archive to the provided path.

    Args:
        member (str): the member name
        path (str): the path where the member should be extracted.
        Defaults to None.
        trusted (bool, optional): whether the archive is trusted. Defaults to
        False.

    Returns:
        str: the path to the extracted member
    """
    raise NotImplementedError

  @abc.abstractmethod
  def open(self, member):
    """Opens `member`.

    Args:
        member (str): the member name

    Returns:
        [IO]: a file-like object that can be `read`.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def close(self) -> None:
    """Closes the archive.
    """
    raise NotImplementedError

  @abc.abstractmethod
  def extractall(self, path, members=None, trusted=False) -> None:
    """Extract the whole archive content or the members listed in `members`.

    Args:
        path (str): the path where the members should be extracted.
        Defaults to None.
        members ([str], optional): the member names. Defaults to None.
        trusted (bool, optional): whether the archive is trusted or not.
        Defaults to False.
    """
    raise NotImplementedError

  def try_open(self, member):
    """Tries to open the archive. Does not throw.

    Args:
        member (str): the member name

    Returns:
        [IO]: a file-like object that can be `read`.
    """
    try:
      return self.open(member)
    except:
      return None

  def get_first_file_matching(self, search_string):
    """Gets the name of the first matching member.

    Args:
        search_string (str): the string to be searched for.

    Returns:
        str: the member name that matched.
    """
    for file in self.list_files():
      if file.filename.startswith('__MACOSX/'):
        # Exclude MAC resource forks.
        continue

      if search_string in file.filename:
        return file.filename
    return None

  def extracted_size(self, file_match_callback=None):
    """Gets the total extracted size of the file matched by
    file_match_callback. If file_match_callback is None, gets the extracted
    size of the whole archive.

    Args:
        file_match_callback (optional): the file matching callback. Defaults
        to None.

    Returns:
        int: the extracted size.
    """
    return sum(f.file_size_bytes
               for f in self.list_files()
               if not file_match_callback or file_match_callback(f.filename))


class TarArchiveReader(ArchiveReader):
  """A tar archive reader. Currently supports TAR and TAR_LZMA archives.
  """

  def __init__(self, archive_path, file_obj=None) -> None:
    if file_obj:
      self.archive = tarfile.open(fileobj=file_obj)
    else:
      archive_type = get_archive_type(archive_path)
      mode = 'r' if archive_type == ArchiveType.TAR else 'r:xz'
      self.archive = tarfile.open(archive_path, mode=mode)
    self.archive_path = archive_path

  def list_files(self) -> typing.List[ArchiveMemberInfo]:
    return [
        ArchiveMemberInfo(
            filename=f.name,
            is_dir=f.isdir(),
            file_size_bytes=f.size,
            mode=f.mode) for f in self.archive.getmembers()
    ]

  def open(self, member):
    return self.archive.extractfile(member)

  def close(self) -> None:
    self.archive.close()

  def extract(self, member, path, trusted=False):
    # If the output directory is a symlink, get its actual path since we will be
    # doing directory traversal checks later when unpacking the archive.
    output_directory = os.path.realpath(path)

    if not trusted:
      if (_is_attempting_path_traversal(self.archive_path, output_directory,
                                        member)):
        return None

    self.archive.extract(member=member, path=output_directory)
    return os.path.realpath(os.path.join(output_directory, member))

  def extractall(self, path, members=None, trusted=False) -> None:
    to_extract = members if members is not None else self.archive.namelist()
    #FIXME(paulsemel): we could try extracting that all.
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


class ZipArchiveReader(ArchiveReader):
  """A zip archive reader.
  """

  def __init__(self, file) -> None:
    self.zip_archive = zipfile.ZipFile(file, mode='r')

  def list_files(self) -> typing.List[ArchiveMemberInfo]:
    return [
        ArchiveMemberInfo(
            filename=f.filename,
            is_dir=f.is_dir(),
            file_size_bytes=f.file_size,
            mode=f.external_attr & 0o7777) for f in self.zip_archive.infolist()
    ]

  def open(self, member):
    return self.zip_archive.open(name=member)

  def close(self) -> None:
    self.zip_archive.close()

  def extract(self, member, path, trusted=False):
    # If the output directory is a symlink, get its actual path since we will be
    # doing directory traversal checks later when unpacking the archive.
    output_directory = os.path.realpath(path)

    # If the archive is not trusted, do file path checks to make
    # sure this archive is safe and is not attempting to do path
    # traversals.
    if not trusted:
      if (_is_attempting_path_traversal(self.zip_archive.filename,
                                        output_directory, member)):
        return None

    try:
      extracted_path = self.zip_archive.extract(member, output_directory)

      # Preserve permissions for regular files. 640 is the default
      # permission for extract. If we need execute permission, we need
      # to chmod it explicitly. Also, get rid of suid bit for security
      # reasons.
      external_attr = self.zip_archive.getinfo(member).external_attr >> 16
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
        symlink_source = self.zip_archive.read(member)
        if os.path.exists(extracted_path):
          os.remove(extracted_path)
        os.symlink(symlink_source, extracted_path)

      return extracted_path
    except:
      # In case of errors, we try to extract whatever we can without errors.
      return None

  def extractall(self, path, members=None, trusted=False) -> None:
    to_extract = members if members is not None else self.zip_archive.namelist()
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


def get_archive_reader(archive_path, file_obj=None):
  """Gets the appropriate archive reader based on the provided path.

  Args:
      archive_path (str): the path to the archive.
      file_obj (obj, optional): a object-like containing the archive. Defaults
      to None.

  Returns:
      (ArchiveReader): the archive reader or None if an error occurred.
  """
  archive_type = get_archive_type(archive_path)
  try:
    if archive_type == ArchiveType.ZIP:
      return ZipArchiveReader(archive_path or file_obj)
    if archive_type in (ArchiveType.TAR_LZMA, ArchiveType.TAR):
      return TarArchiveReader(archive_path, file_obj=file_obj)
    return None
  except:
    logs.log_error(f"Could not open archive at {archive_path}.")
    return None


class ArchiveType:
  """Type of the archive."""
  UNKNOWN = 0
  ZIP = 1
  TAR = 2
  TAR_LZMA = 3


def get_archive_type(archive_path):
  """Get the type of the archive."""

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


def is_archive(filename):
  """Return true if the file is an archive."""
  return get_archive_type(filename) != ArchiveType.UNKNOWN


def unpack(reader, output_dir, trusted=False, file_match_callback=None):
  """Unpacks the current archives opened with `reader`. If file_match_callback
  is None, unpacks all the archive. Otherwise, this only unpacks the files
  matched by the callback.

  Args:
      reader (ArchiveReader): the archive reader
      output_dir (_type_): the output directory to unpack the archive to.
      trusted (bool, optional): whether the archive is trusted. Defaults to
      False.
      file_match_callback (optional): the file matching callback. Defaults to
      None.

  Returns:
      bool: whether an error occurred.
  """
  assert reader

  file_list = [
      f.filename
      for f in reader.list_files()
      if not file_match_callback or file_match_callback(f.filename)
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
      logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                    archive_file_total_count))

  return not error_occurred
