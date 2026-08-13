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
"""File operations implementations."""

from collections.abc import Iterable
from collections.abc import Iterator
import os
from typing import cast

import grpc

from clusterfuzz._internal.bot.fuzzers import utils as fuzzers_utils
from clusterfuzz._internal.protos import untrusted_runner_pb2
from clusterfuzz._internal.system import shell

from . import file_utils

# pylint: disable=no-member,unused-argument


def create_directory(
    request: untrusted_runner_pb2.CreateDirectoryRequest,
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.CreateDirectoryResponse:
  """Create a directory."""
  result = shell.create_directory(request.path, request.create_intermediates)
  return untrusted_runner_pb2.CreateDirectoryResponse(result=result)


def remove_directory(
    request: untrusted_runner_pb2.RemoveDirectoryRequest,
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.RemoveDirectoryResponse:
  """Remove a directory."""
  result = shell.remove_directory(request.path, request.recreate)
  return untrusted_runner_pb2.RemoveDirectoryResponse(result=result)


def list_files(
    request: untrusted_runner_pb2.ListFilesRequest,
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.ListFilesResponse:
  """List files."""
  file_paths: list[str] = []
  if request.recursive:
    for root, _, files in shell.walk(request.path):
      for filename in files:
        file_paths.append(os.path.join(root, filename))
  else:
    file_paths.extend(
        os.path.join(request.path, path) for path in os.listdir(request.path))

  return untrusted_runner_pb2.ListFilesResponse(file_paths=file_paths)


def copy_file_to_worker(
    request_iterator: Iterable[untrusted_runner_pb2.FileChunk],
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.CopyFileToResponse:
  """Copy file from host to worker."""
  metadata = dict(context.invocation_metadata())
  path = cast(bytes, metadata['path-bin']).decode('utf-8')

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


def copy_file_from_worker(
    request: untrusted_runner_pb2.CopyFileFromRequest,
    context: grpc.ServicerContext,
) -> Iterator[untrusted_runner_pb2.FileChunk]:
  """Copy file from worker to host."""
  path = request.path
  if not os.path.isfile(path):
    context.set_trailing_metadata([('result', 'invalid-path')])
    return

  with open(path, 'rb') as f:
    yield from file_utils.file_chunk_generator(f)
  context.set_trailing_metadata([('result', 'ok')])


def stat(
    request: untrusted_runner_pb2.StatRequest,
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.StatResponse:
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


def get_fuzz_targets(
    request: untrusted_runner_pb2.GetFuzzTargetsRequest,
    context: grpc.ServicerContext,
) -> untrusted_runner_pb2.GetFuzzTargetsResponse:
  """Get list of fuzz targets."""
  fuzz_target_paths = fuzzers_utils.get_fuzz_targets_local(request.path)
  return untrusted_runner_pb2.GetFuzzTargetsResponse(
      fuzz_target_paths=fuzz_target_paths)
