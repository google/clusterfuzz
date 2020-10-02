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
"""File operations implemenations."""

import os

from . import file_utils

from bot.fuzzers import utils as fuzzers_utils
from protos import untrusted_runner_pb2
from system import shell


def create_directory(request, _):
  """Create a directory."""
  result = shell.create_directory(request.path, request.create_intermediates)
  return untrusted_runner_pb2.CreateDirectoryResponse(result=result)


def remove_directory(request, _):
  """Remove a directory."""
  result = shell.remove_directory(request.path, request.recreate)
  return untrusted_runner_pb2.RemoveDirectoryResponse(result=result)


def list_files(request, _):
  """List files."""
  file_paths = []
  if request.recursive:
    for root, _, files in shell.walk(request.path):
      for filename in files:
        file_paths.append(os.path.join(root, filename))
  else:
    file_paths.extend(
        os.path.join(request.path, path) for path in os.listdir(request.path))

  return untrusted_runner_pb2.ListFilesResponse(file_paths=file_paths)


def copy_file_to_worker(request_iterator, context):
  """Copy file from host to worker."""
  metadata = dict(context.invocation_metadata())
  path = metadata['path-bin'].decode('utf-8')

  # Create intermediate directories if needed.
  directory = os.path.dirname(path)
  if not os.path.exists(directory):
    try:
      os.makedirs(directory)
    except Exception:
      pass

  if not os.path.isdir(directory):
    # Failed to create intermediate directories.
    return untrusted_runner_pb2.CopyFileToResponse(result=False)

  file_utils.write_chunks(path, request_iterator)
  return untrusted_runner_pb2.CopyFileToResponse(result=True)


def copy_file_from_worker(request, context):
  """Copy file from worker to host."""
  path = request.path
  if not os.path.isfile(path):
    context.set_trailing_metadata([('result', 'invalid-path')])
    return

  with open(path, 'rb') as f:
    for chunk in file_utils.file_chunk_generator(f):
      yield chunk
  context.set_trailing_metadata([('result', 'ok')])


def stat(request, _):
  """Stat a path."""
  if not os.path.exists(request.path):
    return untrusted_runner_pb2.StatResponse(result=False)

  stat_result = os.stat(request.path)
  return untrusted_runner_pb2.StatResponse(
      result=True,
      st_mode=stat_result.st_mode,
      st_size=stat_result.st_size,
      st_atime=stat_result.st_atime,
      st_mtime=stat_result.st_mtime,
      st_ctime=stat_result.st_ctime)


def get_fuzz_targets(request, _):
  """Get list of fuzz targets."""
  fuzz_target_paths = fuzzers_utils.get_fuzz_targets_local(request.path)
  return untrusted_runner_pb2.GetFuzzTargetsResponse(
      fuzz_target_paths=fuzz_target_paths)
