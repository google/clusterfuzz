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

from google.cloud import ndb
from google.protobuf import any_pb2

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import gsutil
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs

target_entities = [
    (data_types.Fuzzer, ['blobstore_key', 'sample_testcase'], 'fuzzer'),
    (data_types.Job, ['custom_binary_key'], 'job'),
    (data_types.DataBundle, [], 'databundle'),
    (data_types.JobTemplate, [], 'jobtemplate'),
]


class RSyncClient:
  """Interface that defines the rsync contract."""

  def __init__(self):
    pass

  def rsync(self, source: str, target: str):
    pass


class GCloudCLIRSync(RSyncClient):
  """RSyncClient implementation that delegates to the gcloud cli.
    Unsuitable for unit testing."""

  def __init__(self):
    self._runner = gsutil.GSUtilRunner()

  def rsync(self, source: str, target: str):
    self._runner.rsync(f'gs://{source}', target)


class StorageRSync(RSyncClient):
  """RSyncClient implementation for unit testing,
    meant for use with GCS emulator."""

  def __init__(self):
    pass

  def rsync(self, source: str, target: str):
    for blob in storage.list_blobs(f'gs://{source}'):
      blob_target_path = f'{target}/{blob}'
      storage.copy_blob(f'gs://{source}/{blob}', blob_target_path)


class EntityMigrator:
  """Serializes entities to GCS, and imports them back."""

  def __init__(self, target_cls: ndb.Model, blobstore_keys: list[str],
               entity_type: str, rsync_client: RSyncClient, export_bucket: str):
    self._target_cls = target_cls
    self.blobstore_keys = blobstore_keys
    self._entity_type = entity_type
    self._rsync_client = rsync_client
    self._export_bucket = export_bucket

  def _serialize(self, entity) -> bytes:
    return uworker_io.entity_to_protobuf(entity).SerializeToString()

  def _deserialize(self, proto_as_str: bytes) -> ndb.Model:
    deserialized_any = any_pb2.Any()  # pylint: disable=no-member
    # Parse the bytes into the Any message
    deserialized_any.ParseFromString(proto_as_str)
    return uworker_io.entity_from_protobuf(deserialized_any, self._target_cls)

  def _serialize_entity_to_gcs(self, entity: ndb.Model, upload_path: str):
    entity_as_bytes = self._serialize(entity)
    storage.write_data(entity_as_bytes, upload_path)

  def _deserialize_entity_from_gcs(self, download_path: str):
    entity_as_bytes = storage.read_data(download_path)
    return self._deserialize(entity_as_bytes)

  def _export_blobs(self, entity: ndb.Model, bucket_prefix: str):
    """Exports blobs for an entity, if applicable (fuzzer/job only)."""
    for blobstore_key in self.blobstore_keys:
      blob_id = getattr(entity, blobstore_key, None)
      if blob_id:
        blob_gcs_path = blobs.get_gcs_path(blob_id)
        blob_destination_path = f'{bucket_prefix}/{blobstore_key}'
        storage.copy_blob(blob_gcs_path, blob_destination_path)

  def _export_data_bundle_contents_if_applicable(self, entity: ndb.Model,
                                                 bucket_prefix: str):
    """Uploads data bundle proto and rsyncs the respective bucket contents."""
    if not isinstance(entity, data_types.DataBundle):
      logs.info(
          f'Entity is not a DataBundle, skipping bucket export: {type(entity)}')
      return
    if not entity.bucket_name:
      logs.info(
          f'DataBundle {entity.name} has no related gcs bucket, skipping.')
      return
    target_location = f'{bucket_prefix}/contents'
    self._rsync_client.rsync(entity.bucket_name, target_location)

  def _export_entity(self, entity: ndb.Model):
    """Exports entity as protobuf and its respective blobs to GCS."""
    # Entitites get their name from the 'name' field in datastore
    entity_name = getattr(entity, 'name', None)
    assert entity_name
    bucket_prefix = (f'gs://{self._export_bucket}/'
                     f'{self._entity_type}/'
                     f'{entity_name}')
    entity_target_location = f'{bucket_prefix}/entity.proto'
    self._serialize_entity_to_gcs(entity, entity_target_location)
    self._export_blobs(entity, bucket_prefix)
    self._export_data_bundle_contents_if_applicable(entity, bucket_prefix)

  def export_entities(self):
    for entity in self._target_cls.query():
      self._export_entity(entity)

  def import_entities(self):
    pass


def main():
  "Exports datastore entities and respective blobs"
  export_bucket = os.getenv('EXPORT_BUCKET', None)
  operation_mode = os.getenv('OPERATION_MODE', None)
  assert export_bucket
  assert operation_mode in ['import', 'export']

  rsync_client = GCloudCLIRSync()

  for (entity, blobstore_keys, entity_name) in target_entities:
    migrator = EntityMigrator(entity, blobstore_keys, entity_name, rsync_client,
                              export_bucket)
    if operation_mode == 'export':
      migrator.export_entities()
    else:
      migrator.import_entities()

  return True
