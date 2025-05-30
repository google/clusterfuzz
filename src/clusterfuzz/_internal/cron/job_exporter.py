# Copyright 2025 Google LLC
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
"""Exports Jobs, Fuzzer, DataBundles and their JobTemplates to GCS, 
    in order to mirror the workloads on testing environments."""

import os
import tempfile

from google.cloud import ndb
from google.protobuf import any_pb2

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage

target_entities = [
    (data_types.Fuzzer, ['blobstore_key'], 'fuzzer'),
    (data_types.Job, ['custom_binary_key'], 'job'),
    (data_types.DataBundle, [], 'databundle'),
    (data_types.JobTemplate, [], 'jobtemplate'),
]
export_bucket = os.getenv('EXPORT_BUCKET', None)
operation_mode = os.getenv('OPERATION_MODE', None)


class EntityMigrator:
  """Serializes entities to GCS, and imports them back."""

  def __init__(self, target_cls: ndb.Model, blobstore_keys: list[str],
               entity_type: str):
    self._target_cls = target_cls
    self.blobstore_keys = blobstore_keys
    self._entity_type = entity_type

  def _serialize(self, entity) -> str:
    return uworker_io.entity_to_protobuf(entity).SerializeToString()

  def _deserialize(self, proto_as_str: str) -> ndb.Model:
    deserialized_any = any_pb2.Any()  # pylint: disable=no-member
    # Parse the bytes into the Any message
    deserialized_any.ParseFromString(proto_as_str)
    return uworker_io.entity_from_protobuf(deserialized_any, self._target_cls)

  def _export_entity(self, entity):
    """Exports entity as protobuf and its respective blobs to GCS."""
    # Entitites get their name from the 'name' field in datastore
    entity_name = getattr(entity, 'name', None)
    assert entity_name
    bucket_prefix = f'gs://{export_bucket}/{self._entity_type}/{entity_name}'
    target_location = f'{bucket_prefix}/entity.proto'
    with tempfile.NamedTemporaryFile(mode='wb+', delete=True) as tmp_file:
      entity_pb_as_str = self._serialize(entity)
      back_to_entity = self._deserialize(entity_pb_as_str)
      assert entity == back_to_entity
      tmp_file.write(entity_pb_as_str)
      tmp_file.flush()
      storage.copy_file_to(tmp_file.name, target_location)
    for blobstore_key in self.blobstore_keys:
      blob_id = getattr(entity, blobstore_key, None)
      if blob_id:
        blob_gcs_path = blobs.get_gcs_path(blob_id)
        blob_destination_path = f'{bucket_prefix}/{blobstore_key}'
        storage.copy_blob(blob_gcs_path, blob_destination_path)

  def export_entities(self):
    for entity in self._target_cls.query():
      self._export_entity(entity)

  def import_entities(self):
    pass


def main():
  "Exports datastore entities and respective blobs"

  assert export_bucket
  assert export_bucket == 'vguidi_exporting_exps'
  assert operation_mode in ['import', 'export']
  assert operation_mode == 'export'
  for (entity, blobstore_keys, entity_name) in target_entities:
    migrator = EntityMigrator(entity, blobstore_keys, entity_name)
    if operation_mode == 'export':
      migrator.export_entities()
    else:
      migrator.import_entities()
  return True
