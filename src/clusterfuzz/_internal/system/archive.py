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

import os
import tarfile
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
  """_is_attempting_path_traversal"""
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


class ArchiveMemberInfo:
  """ArchiveMemberInfo"""

  def __init__(self, filename, is_dir, file_size, compress_size):
    self._filename = filename
    self._is_dir = is_dir
    self._file_size = file_size
    self._compress_size = compress_size

  @property
  def filename(self):
    return self._filename

  def is_dir(self):
    return self._is_dir

  @property
  def file_size(self):
    return self._file_size

  @property
  def compress_size(self):
    return self._compress_size


class ArchiveReader:
  """ArchiveReader"""

  # This should have a few of the handful functions a tool like unzip has
  def list_files(self) -> [ArchiveMemberInfo]:
    raise NotImplementedError

  def extract(self, member, path=None, trusted=False):
    raise NotImplementedError

  def open(self, member):
    raise NotImplementedError

  def try_open(self, member):
    try:
      return self.open(member)
    except:
      return None

  def extractall(self, path=None, members=None, trusted=False) -> None:
    raise NotImplementedError

  def extracted_size(self, file_match_callback=None):
    return sum(f.file_size
               for f in self.list_files()
               if not file_match_callback or file_match_callback(f.filename))


class TarArchiveReader(ArchiveReader):
  """TarArchiveReader"""

  def __init__(self, archive_path, file_obj=None) -> None:
    # we need to know whether it's a lzma file or not.
    archive_type = get_archive_type(archive_path)
    if file_obj:
      self.archive = tarfile.open(fileobj=file_obj)
    else:
      mode = 'r' if archive_type == ArchiveType.TAR else 'r:xz'
      self.archive = tarfile.open(archive_path, mode=mode)
    self.archive_path = archive_path

  def list_files(self) -> [ArchiveMemberInfo]:
    return [
        ArchiveMemberInfo(
            filename=f.name,
            is_dir=f.isdir(),
            file_size=f.size,
            compress_size=f.size) for f in self.archive.getmembers()
    ]

  def open(self, member):
    return self.archive.extractfile(member)

  def extract(self, member, path=None, trusted=False):
    # If the output directory is a symlink, get its actual path since we will be
    # doing directory traversal checks later when unpacking the archive.
    output_directory = os.path.realpath(path)

    if not trusted:
      if (_is_attempting_path_traversal(self.archive_path, output_directory,
                                        member)):
        return None

    self.archive.extract(member=member, path=output_directory)
    return os.path.realpath(os.path.join(output_directory, member))

  def extractall(self, path=None, members=None, trusted=False) -> None:
    to_extract = members if members is not None else self.archive.namelist()
    #FIXME(paulsemel): we could try extracting that all.
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


class ZipArchiveReader(ArchiveReader):
  """ZipArchiveReader"""

  def __init__(self, file) -> None:
    self.zip_archive = zipfile.ZipFile(file, mode='r')

  def list_files(self):
    return [
        ArchiveMemberInfo(
            filename=f.filename,
            is_dir=f.is_dir(),
            file_size=f.file_size,
            compress_size=f.compress_size) for f in self.zip_archive.infolist()
    ]

  def open(self, member):
    return self.zip_archive.open(name=member)

  def extract(self, member, path=None, trusted=False):
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

  def extractall(self, path=None, members=None, trusted=False) -> None:
    to_extract = members if members is not None else self.zip_archive.namelist()
    for member in to_extract:
      self.extract(member=member, path=path, trusted=trusted)


def get_archive_reader(archive_path, file_obj=None):
  archive_type = get_archive_type(archive_path)
  try:
    if archive_type == ArchiveType.ZIP:
      return ZipArchiveReader(archive_path or file_obj)
    if archive_type in (ArchiveType.TAR_LZMA, ArchiveType.TAR):
      return TarArchiveReader(archive_path, file_obj=file_obj)
    return None
  except:
    return None


class ArchiveType:
  """Type of the archive."""
  UNKNOWN = 0
  ZIP = 1
  TAR = 2
  TAR_LZMA = 3


class ArchiveFile:
  """File in an archive."""

  def __init__(self, name, size, handle):
    self.name = name
    self.size = size
    self.handle = handle


def extracted_size(archive_path, file_match_callback=None):
  """Return the total extracted size of the archive."""
  reader = get_archive_reader(archive_path)
  return sum(f.file_size
             for f in reader.list_files()
             if not file_match_callback or file_match_callback(f.filename))


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


def get_file_list(archive_path, file_match_callback=None):
  """List all files in an archive."""
  reader = get_archive_reader(archive_path)
  return [
      f.filename
      for f in reader.list_files()
      if not file_match_callback or file_match_callback(f.filename)
  ]


def get_first_file_matching(search_string, archive_obj, archive_path):
  """Returns the first file with a name matching search string in archive."""
  reader = get_archive_reader(archive_path, archive_obj)
  for file in reader.list_files():
    if file.filename.startswith('__MACOSX/'):
      # Exclude MAC resouce forks.
      continue

    if search_string in file.filename:
      return file.filename
  return None


def is_archive(filename):
  """Return true if the file is an archive."""
  return get_archive_type(filename) != ArchiveType.UNKNOWN


def unpack(archive_path,
           output_directory,
           trusted=False,
           file_match_callback=None):
  """Extracts an archive into the target directory."""
  if not os.path.exists(archive_path):
    logs.log_error('Archive %s not found.' % archive_path)
    return False
  reader = get_archive_reader(archive_path=archive_path)
  assert reader is not None

  # If the output directory is a symlink, get its actual path since we will be
  # doing directory traversal checks later when unpacking the archive.
  output_directory = os.path.realpath(output_directory)

  # Choose to unpack all files or ones matching a particular regex.
  file_list = get_file_list(
      archive_path, file_match_callback=file_match_callback)

  archive_file_unpack_count = 0
  archive_file_total_count = len(file_list)

  error_occurred = False
  for file in file_list:
    error_occurred = reader.extract(
        member=file, path=output_directory, trusted=trusted) is None
    # Keep heartbeat happy by updating with our progress.
    archive_file_unpack_count += 1
    if archive_file_unpack_count % 1000 == 0:
      logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                    archive_file_total_count))

  return not error_occurred
