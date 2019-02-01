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
"""Patch the path-related methods to make them compatible with windows. Please
  see crbug.com/656653"""

import __builtin__
import functools
import os
import sys

WINDOWS_PREFIX_PATH = '\\\\?\\'
_ORIGINAL_MAP = {}

VALID_PATCHEE_TYPES = ['builtin_function_or_method', 'function', 'MagicMock']


def _patch_single(obj, attr, fn):
  """Patch the attr of the obj and save the original implementation."""
  if (obj, attr) in _ORIGINAL_MAP:
    raise Exception('You cannot patch %s.%s more than once.' % (obj, attr))

  _ORIGINAL_MAP[(obj, attr)] = getattr(obj, attr)
  setattr(obj, attr, fn)
  setattr(getattr(obj, attr), '__path_patcher__', True)


def _unpatch_single(obj, attr):
  """Unpatch the attr of the obj."""
  setattr(obj, attr, _ORIGINAL_MAP[(obj, attr)])
  del _ORIGINAL_MAP[(obj, attr)]


def _is_windows():
  """Return true if it's on windows."""
  return sys.platform.startswith('win')


def _short_name_modifier(original_path):
  """Get the short path of `path` on windows."""
  if not _is_windows():
    return original_path

  # These paths don't work with prefix, skip.
  if original_path in ['.', '..']:
    return original_path

  path = original_path
  if not path.startswith(WINDOWS_PREFIX_PATH):
    path = WINDOWS_PREFIX_PATH + path

  path = path.replace('/', '\\')

  import ctypes
  from ctypes import wintypes

  get_short_path = ctypes.windll.kernel32.GetShortPathNameW
  get_short_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
  get_short_path.restype = wintypes.DWORD

  # When passing (path, None, 0), the return value is the size of the buffer
  # that contains the short path and the terminating null character.
  # See: https://msdn.microsoft.com/en-us/library/aa364989.aspx and
  # http://stackoverflow.com/a/23598461/200291
  buffer_length = get_short_path(path, None, 0)

  # The path doesn't exist. There's no corresponding short path.
  # I'm not sure if we should handle this. It might cause a problem when we
  # use os.makedirs(..).
  if buffer_length == 0:
    return path

  output_buffer = ctypes.create_unicode_buffer(buffer_length)
  expected_length = buffer_length - 1

  # When passing (path, output_buffer, buffer_length), the short path is
  # written to output_buffer, and the return value is the length of the short
  # path (excluding the terminating null character).
  actual_length = get_short_path(path, output_buffer, buffer_length)
  if expected_length != actual_length:
    raise Exception(
        "The short-path length %d of %s doesn't equal the expected length %d." %
        (actual_length, path, expected_length))

  return output_buffer.value


def _wrap(fn, *modifiers):
  """Wrap a path-related function with modifiers. fn must take path as its
    first argument."""
  type_class = type(fn)
  if type_class.__name__ not in VALID_PATCHEE_TYPES:
    raise ValueError('%s (%s) cannot be patched.' % (fn.__name__, type_class))

  @functools.wraps(fn)
  def _wrapped(path, *args, **kwargs):
    for modifier in modifiers:
      path = modifier(path)

    return fn(path, *args, **kwargs)

  return _wrapped


def _wrap_file():
  """Wrap the `file` class' constructor with _short_name_modifier."""

  class WrappedFile(file):

    def __init__(self, name, *args, **kwargs):
      self.original_name = name
      short_name = _short_name_modifier(name)
      super(WrappedFile, self).__init__(short_name, *args, **kwargs)

  WrappedFile.__name__ = file.__name__
  WrappedFile.__module__ = file.__module__
  return WrappedFile


def patch():
  """Apply patches to path-related methods."""
  if not _is_windows():
    return

  if _ORIGINAL_MAP:
    return

  _patch_single(os, 'listdir', _wrap(os.listdir, _short_name_modifier))
  _patch_single(os, 'makedirs', _wrap(os.makedirs, _short_name_modifier))
  _patch_single(os, 'mkdir', _wrap(os.mkdir, _short_name_modifier))
  _patch_single(os, 'stat', _wrap(os.stat, _short_name_modifier))
  _patch_single(os.path, 'exists', _wrap(os.path.exists, _short_name_modifier))
  _patch_single(os.path, 'isfile', _wrap(os.path.isfile, _short_name_modifier))
  _patch_single(os.path, 'isdir', _wrap(os.path.isdir, _short_name_modifier))
  _patch_single(__builtin__, 'open', _wrap(open, _short_name_modifier))

  _patch_single(__builtin__, 'file', _wrap_file())


def unpatch():
  """Restore the methods to their original implementations."""
  if not _is_windows():
    return

  for obj, attr in list(_ORIGINAL_MAP):
    _unpatch_single(obj, attr)
