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
import re

from google.cloud import ndb
from google.protobuf import any_pb2

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
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
    """Rsyncs a source to a target destination. Returns True if
    successful, False if there was any failure. Considers successful
     any gsutil execution with a 0 return code."""
    rsync_process_output = self._runner.rsync(source, target)
    return_code = rsync_process_output.return_code
    return return_code == 0


class StorageRSync(RSyncClient):
  """RSyncClient implementation for unit testing,
    meant for use with GCS emulator."""

  def __init__(self):
    pass

  def rsync(self, source: str, target: str):
    """Lists all files under the source path, and uploads
      them to the target path. Since list_blobs returns
      fully qualified names, the source prefix is trimmed
      to recover file names. Returns True on success, False
      on failure."""
    pattern = r"^gs://([^/]+)(?:/.*)?$"
    for blob in storage.list_blobs(source):
      bucket_name_match = re.match(pattern, source)
      assert bucket_name_match
      # group(0) matches the full string
      bucket_name = bucket_name_match.group(1)
      assert bucket_name

      prefix = source.replace(f'gs://{bucket_name}', '')
      if prefix:
        # Case when source is gs://some-bucket/path
        # Prefix will be /path, and a blob will be
        # path/blob. Invert the position of / in prefix,
        # then remove
        prefix = prefix[1:] + '/'
        blob_file_name = blob.replace(prefix, '')
      else:
        # Case for when source is gs://some-bucket
        # No op, the blob name will be the file name
        blob_file_name = blob

      blob_target_path = f'{target}/{blob_file_name}'
      if not storage.copy_blob(f'{source}/{blob_file_name}', blob_target_path):
        return False
    return True


class EntityMigrator:
  """Serializes entities to GCS, and imports them back."""

  def __init__(self,
               target_cls: ndb.Model,
               blobstore_keys: list[str],
               entity_type: str,
               rsync_client: RSyncClient,
               export_bucket: str,
               env_string_substitutions: dict[str, str] | None = None):
    self._target_cls = target_cls
    self.blobstore_keys = blobstore_keys
    self._entity_type = entity_type
    self._rsync_client = rsync_client
    self._export_bucket = export_bucket
    self._env_string_substitutions = env_string_substitutions or {}

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
        if not storage.get(blob_gcs_path):
          logs.warning(f'{blobstore_key} with id {blob_id} not present '
                       f'for {entity.name}, skipping.')
          continue
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
    if not storage.get_bucket(entity.bucket_name):
      logs.warning(f'Bucket {entity.bucket_name} missing for '
                   f'data bundle {entity.name}, skipping.')
      return
    source_location = f'gs://{entity.bucket_name}'
    target_location = f'{bucket_prefix}/contents'
    rsync_succeeded = self._rsync_client.rsync(source_location, target_location)
    if not rsync_succeeded:
      raise ValueError(
          f'Failed to rsync {source_location} to {target_location}.')

  def _export_entity(self, entity: ndb.Model, entity_bucket_prefix: str,
                     entity_name: str):
    """Exports entity as protobuf and its respective blobs to GCS."""
    # Entitites get their name from the 'name' field in datastore
    bucket_prefix = f'{entity_bucket_prefix}/{entity_name}'
    entity_target_location = f'{bucket_prefix}/entity.proto'
    self._serialize_entity_to_gcs(entity, entity_target_location)
    self._export_blobs(entity, bucket_prefix)
    self._export_data_bundle_contents_if_applicable(entity, bucket_prefix)

  def _export_entity_names(self, entities: set[str], entity_bucket_prefix: str):
    """Writes entity name list to GCS."""
    entity_list = '\n'.join(entities)
    storage.write_data(
        entity_list.encode('utf-8'), f'{entity_bucket_prefix}/entities')

  def export_entities(self):
    """Exports individual entities of a certain type, and populates a list
       the individual names of entities for future importing."""
    entity_names = set()
    entity_bucket_prefix = f'gs://{self._export_bucket}/{self._entity_type}'
    for entity in self._target_cls.query():
      entity_name = getattr(entity, 'name', None)
      if not entity_name:
        raise ValueError('Expected entity name to be present, it is not.')
      self._export_entity(entity, entity_bucket_prefix, entity_name)
      entity_names.add(entity_name)
    self._export_entity_names(entity_names, entity_bucket_prefix)

  def _import_blobs(self, entity: ndb.Model, entity_name: str,
                    entity_location: str):
    """Copies exported blobs to a new blob id, and returns a map with
        the new blob ids."""
    new_blob_ids = {}
    for blobstore_key in self.blobstore_keys:
      source_blob_location = f'{entity_location}/{blobstore_key}'
      if not getattr(entity, blobstore_key, None):
        logs.info(
            f'{blobstore_key} missing for {entity_name}, skipping blob import.')
        continue
      if not storage.get(source_blob_location):
        logs.warning(f'Absent blob for {blobstore_key} in {entity_name}, it '
                     'was expected be present. Marked as None and skipping.')
        new_blob_ids[blobstore_key] = None
        continue
      new_blob_id = blobs.generate_new_blob_name()
      target_blob_location = f'gs://{storage.blobs_bucket()}/{new_blob_id}'
      if not storage.copy_blob(source_blob_location, target_blob_location):
        raise ValueError(f'Failed to import blob from {source_blob_location} '
                         f'to {target_blob_location}.')
      new_blob_ids[blobstore_key] = new_blob_id
    return new_blob_ids

  def _substitute_environment_string(self, env_string: str | None):
    """Performs raw text substitution in an environment
      string, given a substitution dictionary."""
    if not env_string:
      return env_string
    substitutions = self._env_string_substitutions
    for source_text in substitutions:
      replacement = substitutions[source_text]
      env_string = env_string.replace(source_text, replacement)
    return env_string

  def _import_data_bundle_contents(self, source_location: str,
                                   bundle_name: str):
    """Imports data bundle contents from the export bucket to the new 
      data bundle bucket in the target project. Skips if the contents
      are absent during export, and throws an exception if the rsync 
      call failed."""
    new_bundle_bucket = data_handler.get_data_bundle_bucket_name(bundle_name)
    storage.create_bucket_if_needed(new_bundle_bucket)
    # There is no helper method to figure out if a folder exists, resort to
    # checking if there are blobs under the path.
    if not list(storage.get_blobs(source_location)):
      logs.warning(f'No source content for data bundle {bundle_name},'
                   ' skipping content import.')
      return new_bundle_bucket
    target_location = f'gs://{new_bundle_bucket}'
    rsync_result = self._rsync_client.rsync(source_location, target_location)
    if not rsync_result:
      raise ValueError(
          f'Failed to rsync data bundle contents from {source_location} '
          f'to {target_location}.')
    return new_bundle_bucket

  def _persist_entity(self, entity: ndb.Model):
    """A raw deserialization and put() call will cause an exception, since the
      project from which the entity was serialized will mistmatch the project to
      which we are writing it to datastore. This forces creation of a new 
      database key, circumventing the issue."""
    entity_to_persist = self._target_cls()
    for key, value in entity.to_dict().items():
      setattr(entity_to_persist, key, value)
    entity_to_persist.put()

  def _import_entity(self, entity_name: str, entity_location: str):
    """Imports entity into datastore, blobs, databundle contents
        and substitutes environment strings, if applicable."""
    entity_to_import = self._deserialize_entity_from_gcs(
        f'{entity_location}/entity.proto')

    # Blobs are deployment specific, must be migrated
    new_blob_ids = self._import_blobs(entity_to_import, entity_name,
                                      entity_location)
    for blob_key, blob_value in new_blob_ids.items():
      setattr(entity_to_import, blob_key, blob_value)

    # This avoids testing environments from using production
    # corpus, logs, backup or quarantine buckets, since these are hardcoded
    # into job env strings. See b/422759773
    if isinstance(entity_to_import, (data_types.Job, data_types.JobTemplate)):
      env_string = getattr(entity_to_import, 'environment_string', None)
      new_env_string = self._substitute_environment_string(env_string)
      setattr(entity_to_import, 'environment_string', new_env_string)

    # The contents from the data bundle buckete must be moved to the target
    # project
    if isinstance(entity_to_import, data_types.DataBundle):
      new_bundle_bucket = self._import_data_bundle_contents(
          f'{entity_location}/contents', entity_name)
      setattr(entity_to_import, 'bucket_name', new_bundle_bucket)

    # Do not assume that name is a primary key, avoid having two
    # different keys with the same name.
    preexisting_entities = list(
        self._target_cls.query(self._target_cls.name == entity_name))
    logs.info(f'Found {len(preexisting_entities)} of type {self._entity_type}'
              f' and name {entity_name}, deleting.')
    for preexisting_entity in preexisting_entities:
      preexisting_entity.key.delete()

    self._persist_entity(entity_to_import)

  def import_entities(self):
    """Iterates over all entitiy names declared in the last export, and imports
      its contents."""
    entity_bucket_prefix = f'gs://{self._export_bucket}/{self._entity_type}'
    entity_list_location = f'{entity_bucket_prefix}/entities'
    if not storage.get(entity_list_location):
      raise ValueError(f'Missing entity list in {entity_list_location}')
    entities_to_sync = storage.read_data(entity_list_location)
    if not entities_to_sync:
      entities_to_sync = []
    else:
      entities_to_sync = entities_to_sync.decode('utf-8').split('\n')
    for entity in self._target_cls.query():
      if entity.name not in entities_to_sync:
        entity.key.delete()
    for entity_name in entities_to_sync:
      entity_location = f'{entity_bucket_prefix}/{entity_name}'
      self._import_entity(entity_name, entity_location)


def main():
  """Exports datastore entities and respective blobs."""
  export_bucket = os.getenv('EXPORT_BUCKET', None)
  operation_mode = os.getenv('OPERATION_MODE', None)
  assert export_bucket
  assert operation_mode in ['import', 'export']

  rsync_client = GCloudCLIRSync()

  project_config = local_config.ProjectConfig()
  env_string_substitutions = project_config.get(
      'job_exporter.env_string_substitutions', {})

  for (entity, blobstore_keys, entity_name) in target_entities:
    migrator = EntityMigrator(entity, blobstore_keys, entity_name, rsync_client,
                              export_bucket, env_string_substitutions)
    if operation_mode == 'export':
      migrator.export_entities()
    else:
      migrator.import_entities()

  return True
