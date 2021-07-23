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
"""Helpers for file operations."""

from clusterfuzz._internal.protos import untrusted_runner_pb2

from . import config


def file_chunk_generator(handle):
  """Yields chunks from handle."""
  data = handle.read(config.FILE_TRANSFER_CHUNK_SIZE)
  while data:
    yield untrusted_runner_pb2.FileChunk(data=data)
    data = handle.read(config.FILE_TRANSFER_CHUNK_SIZE)


def data_chunk_generator(data):
  """Yields chunks for data."""
  index = 0
  while index < len(data):
    cur_chunk = data[index:index + config.FILE_TRANSFER_CHUNK_SIZE]
    yield untrusted_runner_pb2.FileChunk(data=cur_chunk)

    index += config.FILE_TRANSFER_CHUNK_SIZE


def write_chunks(file_path, chunk_iterator):
  """Writes chunks to file."""
  with open(file_path, 'wb') as f:
    for chunk in chunk_iterator:
      f.write(chunk.data)
