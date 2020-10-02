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

import lzma
import os
import tarfile
import zipfile

from metrics import logs

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


class ArchiveType(object):
  """Type of the archive."""
  UNKNOWN = 0
  ZIP = 1
  TAR = 2
  TAR_LZMA = 3


class ArchiveFile(object):
  """File in an archive."""

  def __init__(self, name, size, handle):
    self.name = name
    self.size = size
    self.handle = handle


def iterator(archive_path,
             archive_obj=None,
             file_match_callback=None,
             should_extract=True):
  """Return an iterator for files in an archive. Extracts files if
  |should_extract| is True."""
  archive_type = get_archive_type(archive_path)

  if not file_match_callback:
    file_match_callback = lambda _: True

  def maybe_extract(extract_func, info):
    """Returns an extracted file or None if it is not supposed to be extracted.
    """
    if should_extract:
      return extract_func(info)
    return None

  if archive_type == ArchiveType.ZIP:
    try:
      with zipfile.ZipFile(archive_obj or archive_path) as zip_file:
        for info in zip_file.infolist():
          if not file_match_callback(info.filename):
            continue

          yield ArchiveFile(info.filename, info.file_size,
                            maybe_extract(zip_file.open, info))

    except (zipfile.BadZipfile, zipfile.LargeZipFile):
      logs.log_error('Bad zip file %s.' % archive_path)

  elif archive_type == ArchiveType.TAR:
    try:
      if archive_obj:
        tar_file = tarfile.open(fileobj=archive_obj)
      else:
        tar_file = tarfile.open(archive_path)

      for info in tar_file.getmembers():
        if not file_match_callback(info.name):
          continue

        yield ArchiveFile(info.name, info.size,
                          maybe_extract(tar_file.extractfile, info))
      tar_file.close()
    except tarfile.TarError:
      logs.log_error('Bad tar file %s.' % archive_path)

  elif archive_type == ArchiveType.TAR_LZMA:
    assert archive_obj is None, "LZMAFile doesn't support opening file handles."
    try:
      with lzma.LZMAFile(archive_path) as lzma_file, \
            tarfile.open(fileobj=lzma_file) as tar_file:

        error_filepaths = []
        for info in tar_file.getmembers():
          if not file_match_callback(info.name):
            continue

          try:
            yield ArchiveFile(info.name, info.size,
                              maybe_extract(tar_file.extractfile, info))

          except KeyError:  # Handle broken links gracefully.
            error_filepaths.append(info.name)
            yield ArchiveFile(info.name, info.size, None)

        if error_filepaths:
          logs.log_warn(
              'Check archive %s for broken links.' % archive_path,
              error_filepaths=error_filepaths)

    except (lzma.LZMAError, tarfile.TarError):
      logs.log_error('Bad lzma file %s.' % archive_path)

  else:
    logs.log_error('Unsupported compression type for file %s.' % archive_path)


def extracted_size(archive_path, archive_obj=None, file_match_callback=None):
  """Return the total extracted size of the archive."""
  return sum(
      f.size for f in iterator(
          archive_path, archive_obj, file_match_callback, should_extract=False))


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


def get_file_list(archive_path, archive_obj=None, file_match_callback=None):
  """List all files in an archive."""
  return [
      f.name for f in iterator(
          archive_path, archive_obj, file_match_callback, should_extract=False)
  ]


def get_first_file_matching(search_string, archive_obj, archive_path):
  """Returns the first file with a name matching search string in archive."""
  for current_file in get_file_list(archive_path, archive_obj):
    # Exclude MAC resouce forks.
    if current_file.startswith('__MACOSX/'):
      continue

    if search_string in current_file:
      return current_file

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

  # If the output directory is a symlink, get its actual path since we will be
  # doing directory traversal checks later when unpacking the archive.
  output_directory = os.path.realpath(output_directory)

  archive_filename = os.path.basename(archive_path)
  error_occurred = False

  # Choose to unpack all files or ones matching a particular regex.
  file_list = get_file_list(
      archive_path, file_match_callback=file_match_callback)

  archive_file_unpack_count = 0
  archive_file_total_count = len(file_list)

  # If the archive is not trusted, do file path checks to make
  # sure this archive is safe and is not attempting to do path
  # traversals.
  if not trusted:
    for filename in file_list:
      absolute_file_path = os.path.join(output_directory,
                                        os.path.normpath(filename))
      real_file_path = os.path.realpath(absolute_file_path)

      if real_file_path == output_directory:
        # Workaround for https://bugs.python.org/issue28488.
        # Ignore directories named '.'.
        continue

      if real_file_path != absolute_file_path:
        logs.log_error(
            'Directory traversal attempted while unpacking archive %s '
            '(file path=%s, actual file path=%s). Aborting.' %
            (archive_path, absolute_file_path, real_file_path))
        return False

  archive_type = get_archive_type(archive_filename)

  # Extract based on file's extension.
  if archive_type == ArchiveType.ZIP:
    zip_file_handle = open(archive_path, 'rb')
    zip_archive = zipfile.ZipFile(zip_file_handle)

    for filename in file_list:
      try:
        extracted_path = zip_archive.extract(filename, output_directory)

        # Preserve permissions for regular files. 640 is the default
        # permission for extract. If we need execute permission, we need
        # to chmod it explicitly. Also, get rid of suid bit for security
        # reasons.
        external_attr = zip_archive.getinfo(filename).external_attr >> 16
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
          symlink_source = zip_archive.read(filename)
          if os.path.exists(extracted_path):
            os.remove(extracted_path)
          os.symlink(symlink_source, extracted_path)

        # Keep heartbeat happy by updating with our progress.
        archive_file_unpack_count += 1
        if archive_file_unpack_count % 1000 == 0:
          logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                        archive_file_total_count))

      except:
        # In case of errors, we try to extract whatever we can without errors.
        error_occurred = True
        continue

    logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                  archive_file_total_count))
    zip_archive.close()
    zip_file_handle.close()

    if error_occurred:
      logs.log_error(
          'Failed to extract everything from archive %s.' % archive_filename)

  elif archive_type in (ArchiveType.TAR, ArchiveType.TAR_LZMA):
    if archive_type == ArchiveType.TAR_LZMA:
      lzma_file = lzma.LZMAFile(archive_path)
      tar_archive = tarfile.open(fileobj=lzma_file)
    else:
      tar_archive = tarfile.open(archive_path)

    try:
      tar_archive.extractall(path=output_directory)
    except:
      # In case of errors, we try to extract whatever we can without errors.
      error_occurred = True
      logs.log_error(
          'Failed to extract everything from archive %s, trying one at a time.'
          % archive_filename)
      for filename in file_list:
        try:
          tar_archive.extract(filename, output_directory)
        except:
          continue

        # Keep heartbeat happy by updating with our progress.
        archive_file_unpack_count += 1
        if archive_file_unpack_count % 1000 == 0:
          logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                        archive_file_total_count))

      logs.log('Unpacked %d/%d.' % (archive_file_unpack_count,
                                    archive_file_total_count))

    tar_archive.close()
    if archive_type == ArchiveType.TAR_LZMA:
      lzma_file.close()

  else:
    logs.log_error(
        'Unsupported compression type for file %s.' % archive_filename)
    return False

  return not error_occurred
