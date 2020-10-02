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
"""File operations host (client)."""

import os
import shutil

from . import file_utils
from . import host

from metrics import logs
from protos import untrusted_runner_pb2
from system import environment
from system import shell


def is_directory_parent(path, directory):
  """Check whether if |directory| is a parent of |path|."""
  path = os.path.abspath(path)
  directory = os.path.abspath(directory)

  path_components = path.split(os.sep)
  directory_components = directory.split(os.sep)

  if len(path_components) <= len(directory_components):
    return False

  return all(path_components[i] == directory_components[i]
             for i in range(len(directory_components)))


def _rebase(path, target_base, cur_base):
  """Rebase a path."""
  if not path:
    # Don't rebase if the path is None or empty string (in case of default
    # variable value).
    return path

  if os.path.abspath(path).startswith(target_base):
    # Already rebased.
    return path

  rel_path = os.path.relpath(os.path.abspath(path), cur_base)

  if rel_path == os.curdir:
    return target_base

  # Only paths relative to ROOT_DIR are supported.
  assert not rel_path.startswith(os.pardir), 'Bad relative path %s' % rel_path
  return os.path.join(target_base, rel_path)


def rebase_to_host_root(worker_path):
  """Return corresponding host root given a worker CF path."""
  return _rebase(worker_path, environment.get_value('ROOT_DIR'),
                 environment.get_value('WORKER_ROOT_DIR'))


def rebase_to_worker_root(host_path):
  """Return corresponding worker path given a host CF path."""
  return _rebase(host_path, environment.get_value('WORKER_ROOT_DIR'),
                 environment.get_value('ROOT_DIR'))


def create_directory(path, create_intermediates=False):
  """Create a directory."""
  request = untrusted_runner_pb2.CreateDirectoryRequest(
      path=path, create_intermediates=create_intermediates)

  response = host.stub().CreateDirectory(request)
  return response.result


def remove_directory(path, recreate=False):
  """Remove a directory. If |recreate| is set, always creates the directory even
  if it did not exist."""
  request = untrusted_runner_pb2.RemoveDirectoryRequest(
      path=path, recreate=recreate)

  response = host.stub().RemoveDirectory(request)
  return response.result


def list_files(path, recursive=False):
  """List files in the directory. Returns full file paths."""
  request = untrusted_runner_pb2.ListFilesRequest(
      path=path, recursive=recursive)

  response = host.stub().ListFiles(request)
  return response.file_paths


def copy_file_to_worker(host_path, worker_path):
  """Copy file from host to worker. |worker_path| must be a full path (including
  the filename). Any directories will be created if needed."""
  with open(host_path, 'rb') as f:
    request_iterator = file_utils.file_chunk_generator(f)
    metadata = [('path-bin', worker_path.encode('utf-8'))]

    response = host.stub().CopyFileTo(request_iterator, metadata=metadata)
    return response.result


def write_data_to_worker(data, worker_path):
  """Write data to a file on the worker."""
  request_iterator = file_utils.data_chunk_generator(data)
  metadata = [('path-bin', worker_path.encode('utf-8'))]

  response = host.stub().CopyFileTo(request_iterator, metadata=metadata)
  return response.result


def copy_file_from_worker(worker_path, host_path):
  """Copy file from worker to host."""
  request = untrusted_runner_pb2.CopyFileFromRequest(path=worker_path)
  response = host.stub().CopyFileFrom(request)
  file_utils.write_chunks(host_path, response)
  metadata = dict(response.trailing_metadata())
  if metadata.get('result') != 'ok':
    # file_utils.write_chunks always opens the file for writing, so remove it
    # here.
    os.remove(host_path)
    return False

  return True


def copy_directory_to_worker(host_directory, worker_directory, replace=False):
  """Recursively copy a directory to the worker. Directories are created as
  needed. Unless |replace| is True, files already in |worker_path| will remain
  after this call."""
  if replace:
    remove_directory(worker_directory, recreate=True)

  for root, _, files in shell.walk(host_directory):
    for filename in files:
      file_path = os.path.join(root, filename)
      worker_file_path = os.path.join(
          worker_directory, os.path.relpath(file_path, host_directory))
      if not copy_file_to_worker(file_path, worker_file_path):
        logs.log_warn('Failed to copy %s to worker.' % file_path)
        return False

  return True


def copy_directory_from_worker(worker_directory, host_directory, replace=False):
  """Recursively copy a directory from the worker. Directories are created as
  needed. Unless |replace| is True, files already in |host_directory| will
  remain after this call."""
  if replace and os.path.exists(host_directory):
    shutil.rmtree(host_directory, ignore_errors=True)
    os.mkdir(host_directory)

  for worker_file_path in list_files(worker_directory, recursive=True):
    relative_worker_file_path = os.path.relpath(worker_file_path,
                                                worker_directory)
    host_file_path = os.path.join(host_directory, relative_worker_file_path)

    # Be careful with the path provided by the worker here. We want to make sure
    # we're only writing files to |host_directory| and not outside it.
    if not is_directory_parent(host_file_path, host_directory):
      logs.log_warn('copy_directory_from_worker: Attempt to escape |host_dir|.')
      return False

    host_file_directory = os.path.dirname(host_file_path)
    if not os.path.exists(host_file_directory):
      os.makedirs(host_file_directory)

    if not copy_file_from_worker(worker_file_path, host_file_path):
      logs.log_warn('Failed to copy %s from worker.' % worker_file_path)
      return False

  return True


def stat(path):
  """stat() a path."""
  request = untrusted_runner_pb2.StatRequest(path=path)
  response = host.stub().Stat(request)
  if not response.result:
    return None

  return response


def clear_testcase_directories():
  """Clear the testcases directories on the worker."""
  remove_directory(
      rebase_to_worker_root(environment.get_value('FUZZ_INPUTS')),
      recreate=True)
  remove_directory(
      rebase_to_worker_root(environment.get_value('FUZZ_INPUTS_DISK')),
      recreate=True)


def clear_build_urls_directory():
  """Clear the build urls directory on the worker."""
  remove_directory(
      rebase_to_worker_root(environment.get_value('BUILD_URLS_DIR')),
      recreate=True)


def clear_temp_directory():
  """Clear the temp directory on the worker."""
  remove_directory(environment.get_value('WORKER_BOT_TMPDIR'), recreate=True)


def push_testcases_to_worker():
  """Push all testcases to the worker."""
  local_testcases_directory = environment.get_value('FUZZ_INPUTS')
  worker_testcases_directory = rebase_to_worker_root(local_testcases_directory)
  return copy_directory_to_worker(
      local_testcases_directory, worker_testcases_directory, replace=True)


def pull_testcases_from_worker():
  """Pull all testcases to the worker."""
  local_testcases_directory = environment.get_value('FUZZ_INPUTS')
  worker_testcases_directory = rebase_to_worker_root(local_testcases_directory)
  return copy_directory_from_worker(
      worker_testcases_directory, local_testcases_directory, replace=True)


def get_fuzz_targets(path):
  """Get list of fuzz target paths."""
  request = untrusted_runner_pb2.GetFuzzTargetsRequest(path=path)
  response = host.stub().GetFuzzTargets(request)
  return response.fuzz_target_paths
