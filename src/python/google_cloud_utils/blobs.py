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
"""Blobs handling."""

import os
import re
import uuid

from google.cloud import ndb

from base import memoize
from base import retry
from datastore import data_types
from system import environment

from . import storage

FAIL_NUM_RETRIES = 2
FAIL_WAIT = 1.5


# pylint: disable=invalid-name
class BlobInfo(data_types.Model):
  """Legacy BlobInfo."""

  content_type = ndb.StringProperty()
  creation = ndb.DateTimeProperty()
  filename = ndb.StringProperty()
  gs_object_name = ndb.StringProperty()
  md5_hash = ndb.StringProperty()
  size = ndb.IntegerProperty()
  upload_id = ndb.StringProperty()

  @classmethod
  def _get_kind(cls):
    if environment.get_value('DATASTORE_EMULATOR_HOST'):
      # Datastore emulator does not allow writing entities with names of the
      # format "__*__".
      cls._kind_map['_BlobInfo_'] = cls
      return '_BlobInfo_'

    return '__BlobInfo__'


class _blobmigrator_BlobKeyMapping(data_types.Model):
  """Migrated blob."""

  old_blob_key = ndb.ComputedProperty(lambda self: self.key.id())
  gcs_filename = ndb.StringProperty(required=True)
  new_blob_key = ndb.StringProperty(required=True)


# pylint: enable=invalid-name
class BlobsException(Exception):
  """Base exception for blobs module."""


def _is_gcs_key(blob_key):
  """Return whether if the key is a GCS key."""
  gcs_key_pattern = re.compile(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

  return bool(gcs_key_pattern.match(blob_key))


def _get_gcs_blob_path(blob_key):
  """Return the full path to the blob on GCS."""
  return '/%s/%s' % (storage.blobs_bucket(), blob_key)


def get_gcs_path(blob_key):
  """Return GCS path for the blob."""
  if _is_gcs_key(blob_key):
    return _get_gcs_blob_path(blob_key)

  # Legacy blobstore key.
  blob_info = get_legacy_blob_info(blob_key)
  if not blob_info:
    return None

  return blob_info.gs_object_name


@memoize.wrap(memoize.Memcache(60 * 60 * 24 * 30))  # 30 day TTL
@retry.wrap(
    retries=FAIL_NUM_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.blobs.get_blob_size')
def get_blob_size(blob_key):
  """Returns blob size for a given blob key."""
  if not blob_key or blob_key == 'NA':
    return None

  blob_info = get_blob_info(blob_key)
  if not blob_info:
    return None

  return blob_info.size


def get_blob_info(blob_key):
  """Get the GcsBlobInfo for the given key. Always returns a
  storage.GcsBlobInfo, even for legacy blobs."""
  if _is_gcs_key(blob_key):
    return storage.GcsBlobInfo.from_key(blob_key)

  legacy_blob_info = get_legacy_blob_info(blob_key)
  if not legacy_blob_info:
    return None

  return storage.GcsBlobInfo.from_legacy_blob_info(legacy_blob_info)


@retry.wrap(
    retries=FAIL_NUM_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.blobs.delete_blob',
    retry_on_false=True)
def delete_blob(blob_key):
  """Delete a blob key."""
  blob_info = get_blob_info(blob_key)
  if not blob_info:
    return False

  return storage.delete(blob_info.gcs_path)


@retry.wrap(
    retries=FAIL_NUM_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.blobs.write_blob',
    retry_on_false=True)
def write_blob(file_handle_or_path):
  """Write a single file testcase to GCS."""
  blobs_bucket = storage.blobs_bucket()
  blob_name = generate_new_blob_name()

  if storage.get(storage.get_cloud_storage_file_path(blobs_bucket, blob_name)):
    raise BlobsException('UUID collision found: %s' % blob_name)

  if isinstance(file_handle_or_path, str):
    filename = os.path.basename(file_handle_or_path)
  else:
    filename = file_handle_or_path.name

  metadata = {
      storage.BLOB_FILENAME_METADATA_KEY: filename,
  }

  gcs_path = '/%s/%s' % (blobs_bucket, blob_name)
  if storage.copy_file_to(file_handle_or_path, gcs_path, metadata=metadata):
    return blob_name

  raise BlobsException('Failed to write blob %s.' % blob_name)


@retry.wrap(
    retries=FAIL_NUM_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.blobs.read_blob_to_disk',
    retry_on_false=True)
def read_blob_to_disk(blob_key, local_file):
  """Copy data stored in the blobstore to a local file."""
  assert not environment.is_running_on_app_engine()

  directory = os.path.dirname(local_file)
  if not os.path.exists(directory):
    os.makedirs(directory)

  gcs_path = get_gcs_path(blob_key)
  return storage.copy_file_from(gcs_path, local_file)


def read_key(blob_key):
  """Returns data associated with a blobstore key."""
  gcs_path = get_gcs_path(blob_key)
  return storage.read_data(gcs_path)


def get_legacy_blob_info(blob_key):
  """Return legacy blob info information."""
  legacy_blob_info = ndb.Key(BlobInfo, blob_key).get()
  if not legacy_blob_info:
    return None

  if legacy_blob_info.gs_object_name:
    return legacy_blob_info

  # Blobs which were stored before the move to GCS have an additional mapping
  # entry created by our migration jobs.
  blob_mapping = get_blob_mapping(blob_key)
  if not blob_mapping:
    raise BlobsException('Blob mapping not found.')

  legacy_blob_info.gs_object_name = blob_mapping.gcs_filename
  return legacy_blob_info


def get_blob_mapping(blob_key):
  """Return blob mapping information."""
  return ndb.Key(_blobmigrator_BlobKeyMapping, blob_key).get()


def generate_new_blob_name():
  """Generate a new blob name."""
  return str(uuid.uuid4()).lower()
