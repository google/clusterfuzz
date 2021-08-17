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
"""Functions for managing Google Cloud Storage."""

import copy
import datetime
import json
import os
import shutil
import threading
import time

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import locks
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

from . import credentials

try:
  import google.cloud
  from google.cloud import storage as gcs
except ImportError:
  # This is expected to fail on AppEngine.
  pass

# Usually, authentication time have expiry of ~30 minutes, but keeping this
# values lower to avoid failures and any future changes.
AUTH_TOKEN_EXPIRY_TIME = 10 * 60

# Wait time to let NFS copy to sync across bricks.
CACHE_COPY_WAIT_TIME = 10

# Cache directory name.
CACHE_DIRNAME = 'cache'

# Time to hold the cache lock for.
CACHE_LOCK_TIMEOUT = 30 * 60

# File extension for tmp cache files.
CACHE_METADATA_FILE_EXTENSION = '.metadata'

# Maximum size of file to allow in cache.
CACHE_SIZE_LIMIT = 5 * 1024 * 1024 * 1024  # 5 GB

# Cache get/set timeout.
CACHE_TIMEOUT = 3 * 60 * 60  # 3 hours.

# The number of retries to perform some GCS operation.
DEFAULT_FAIL_RETRIES = 8

# The time to wait between retries while performing GCS operation.
DEFAULT_FAIL_WAIT = 2

# Prefix for GCS urls.
GS_PREFIX = 'gs:/'

# Maximum number of cached files per directory.
MAX_CACHED_FILES_PER_DIRECTORY = 15

# https://cloud.google.com/storage/docs/best-practices states that we can
# create/delete 1 bucket about every 2 seconds.
CREATE_BUCKET_DELAY = 4

# GCS blob metadata key for filename.
BLOB_FILENAME_METADATA_KEY = 'filename'

# Thread local globals.
_local = threading.local()

# Urls for web viewer.
OBJECT_URL = 'https://storage.cloud.google.com'
DIRECTORY_URL = 'https://console.cloud.google.com/storage'


class StorageProvider(object):
  """Core storage provider interface."""

  def create_bucket(self, name, object_lifecycle, cors):
    """Create a new bucket."""
    raise NotImplementedError

  def get_bucket(self, name):
    """Get a bucket."""
    raise NotImplementedError

  def list_blobs(self, remote_path, recursive=True):
    """List the blobs under the remote path."""
    raise NotImplementedError

  def copy_file_from(self, remote_path, local_path):
    """Copy file from a remote path to a local path."""
    raise NotImplementedError

  def copy_file_to(self, local_path_or_handle, remote_path, metadata=None):
    """Copy file from a local path to a remote path."""
    raise NotImplementedError

  def copy_blob(self, remote_source, remote_target):
    """Copy a remote file to another remote location."""
    raise NotImplementedError

  def read_data(self, remote_path):
    """Read the data of a remote file."""
    raise NotImplementedError

  def write_data(self, data, remote_path, metadata=None):
    """Write the data of a remote file."""
    raise NotImplementedError

  def get(self, remote_path):
    """Get information about a remote file."""
    raise NotImplementedError

  def delete(self, remote_path):
    """Delete a remote file."""
    raise NotImplementedError


class GcsProvider(StorageProvider):
  """GCS storage provider."""

  def _chunk_size(self):
    if environment.is_running_on_app_engine():
      # To match App Engine URLFetch's request size limit.
      return 10 * 1024 * 1024  # 10 MiB.

    return None

  def create_bucket(self, name, object_lifecycle, cors):
    """Create a new bucket."""
    project_id = utils.get_application_id()
    request_body = {'name': name}
    if object_lifecycle:
      request_body['lifecycle'] = object_lifecycle

    if cors:
      request_body['cors'] = cors

    client = create_discovery_storage_client()
    try:
      client.buckets().insert(project=project_id, body=request_body).execute()
    except HttpError as e:
      logs.log_warn('Failed to create bucket %s: %s' % (name, e))
      raise

    return True

  def get_bucket(self, name):
    """Get a bucket."""
    client = create_discovery_storage_client()
    try:
      return client.buckets().get(bucket=name).execute()
    except HttpError as e:
      if e.resp.status == 404:
        return None

      raise

  def list_blobs(self, remote_path, recursive=True):
    """List the blobs under the remote path."""
    bucket_name, path = get_bucket_name_and_path(remote_path)

    if path and not path.endswith('/'):
      path += '/'

    client = _storage_client()
    bucket = client.bucket(bucket_name)
    properties = {}

    if recursive:
      delimiter = None
    else:
      delimiter = '/'

    iterator = bucket.list_blobs(prefix=path, delimiter=delimiter)
    for blob in iterator:
      properties['bucket'] = bucket_name
      properties['name'] = blob.name
      properties['updated'] = blob.updated
      properties['size'] = blob.size

      yield properties

    if not recursive:
      # When doing delimiter listings, the "directories" will be in `prefixes`.
      for prefix in iterator.prefixes:
        properties['bucket'] = bucket_name
        properties['name'] = prefix
        yield properties

  def copy_file_from(self, remote_path, local_path):
    """Copy file from a remote path to a local path."""
    client = _storage_client()
    bucket_name, path = get_bucket_name_and_path(remote_path)

    try:
      bucket = client.bucket(bucket_name)
      blob = bucket.blob(path, chunk_size=self._chunk_size())
      blob.download_to_filename(local_path)
    except google.cloud.exceptions.GoogleCloudError:
      logs.log_warn('Failed to copy cloud storage file %s to local file %s.' %
                    (remote_path, local_path))
      raise

    return True

  def copy_file_to(self, local_path_or_handle, remote_path, metadata=None):
    """Copy file from a local path to a remote path."""
    client = _storage_client()
    bucket_name, path = get_bucket_name_and_path(remote_path)

    try:
      bucket = client.bucket(bucket_name)
      blob = bucket.blob(path, chunk_size=self._chunk_size())
      if metadata:
        blob.metadata = metadata

      if isinstance(local_path_or_handle, str):
        blob.upload_from_filename(local_path_or_handle)
      else:
        blob.upload_from_file(local_path_or_handle, rewind=True)

    except google.cloud.exceptions.GoogleCloudError:
      logs.log_warn('Failed to copy local file %s to cloud storage file %s.' %
                    (local_path_or_handle, remote_path))
      raise

    return True

  def copy_blob(self, remote_source, remote_target):
    """Copy a remote file to another remote location."""
    source_bucket_name, source_path = get_bucket_name_and_path(remote_source)
    target_bucket_name, target_path = get_bucket_name_and_path(remote_target)

    client = _storage_client()
    try:
      source_bucket = client.bucket(source_bucket_name)
      source_blob = source_bucket.blob(source_path)
      target_bucket = client.bucket(target_bucket_name)
      source_bucket.copy_blob(source_blob, target_bucket, target_path)
    except google.cloud.exceptions.GoogleCloudError:
      logs.log_warn('Failed to copy cloud storage file %s to cloud storage '
                    'file %s.' % (remote_source, remote_target))
      raise

    return True

  def read_data(self, remote_path):
    """Read the data of a remote file."""
    bucket_name, path = get_bucket_name_and_path(remote_path)

    client = _storage_client()
    try:
      bucket = client.bucket(bucket_name)
      blob = bucket.blob(path, chunk_size=self._chunk_size())
      return blob.download_as_string()
    except google.cloud.exceptions.GoogleCloudError as e:
      if e.code == 404:
        return None

      logs.log_warn('Failed to read cloud storage file %s.' % remote_path)
      raise

  def write_data(self, data, remote_path, metadata=None):
    """Write the data of a remote file."""
    client = _storage_client()
    bucket_name, path = get_bucket_name_and_path(remote_path)

    try:
      bucket = client.bucket(bucket_name)
      blob = bucket.blob(path, chunk_size=self._chunk_size())
      if metadata:
        blob.metadata = metadata
      blob.upload_from_string(data)
    except google.cloud.exceptions.GoogleCloudError:
      logs.log_warn('Failed to write cloud storage file %s.' % remote_path)
      raise

    return True

  def get(self, remote_path):
    """Get information about a remote file."""
    client = create_discovery_storage_client()
    bucket, path = get_bucket_name_and_path(remote_path)

    try:
      return client.objects().get(bucket=bucket, object=path).execute()
    except HttpError as e:
      if e.resp.status == 404:
        return None

      raise

  def delete(self, remote_path):
    """Delete a remote file."""
    client = _storage_client()
    bucket_name, path = get_bucket_name_and_path(remote_path)

    try:
      bucket = client.bucket(bucket_name)
      bucket.delete_blob(path)
    except google.cloud.exceptions.GoogleCloudError:
      logs.log_warn('Failed to delete cloud storage file %s.' % remote_path)
      raise

    return True


class FileSystemProvider(StorageProvider):
  """File system backed storage provider."""

  OBJECTS_DIR = 'objects'
  METADATA_DIR = 'metadata'

  def __init__(self, filesystem_dir):
    self.filesystem_dir = os.path.abspath(filesystem_dir)

  def _get_object_properties(self, remote_path):
    """Set local object properties."""
    bucket, path = get_bucket_name_and_path(remote_path)
    fs_path = self.convert_path(remote_path)

    data = {
        'bucket': bucket,
        'name': path,
    }

    if not os.path.isdir(fs_path):
      # These attributes only apply to objects, not directories.
      data.update({
          'updated':
              datetime.datetime.utcfromtimestamp(os.stat(fs_path).st_mtime),
          'size':
              os.path.getsize(fs_path),
          'metadata':
              self._get_metadata(bucket, path),
      })

    return data

  def _get_metadata(self, bucket, path):
    """Get the metadata for a given object."""
    fs_metadata_path = self._fs_path(bucket, path, self.METADATA_DIR)
    if os.path.exists(fs_metadata_path):
      with open(fs_metadata_path) as f:
        return json.load(f)

    return {}

  def _fs_bucket_path(self, bucket):
    """Get the local FS path for the bucket."""
    return os.path.join(self.filesystem_dir, bucket)

  def _fs_objects_dir(self, bucket):
    """Get the local FS path for objects in the bucket."""
    return os.path.join(self._fs_bucket_path(bucket), self.OBJECTS_DIR)

  def _fs_path(self, bucket, path, directory):
    """Get the local object/metadata FS path."""
    return os.path.join(self._fs_bucket_path(bucket), directory, path)

  def _write_metadata(self, remote_path, metadata):
    """Write metadata."""
    if not metadata:
      return

    fs_metadata_path = self.convert_path_for_write(remote_path,
                                                   self.METADATA_DIR)
    with open(fs_metadata_path, 'w') as f:
      json.dump(metadata, f)

  def convert_path(self, remote_path, directory=OBJECTS_DIR):
    """Get the local FS path for the remote path."""
    bucket, path = get_bucket_name_and_path(remote_path)
    return self._fs_path(bucket, path, directory)

  def convert_path_for_write(self, remote_path, directory=OBJECTS_DIR):
    """Get the local FS path for writing to the remote path. Creates any
    intermediate directories if necessary (except for the parent bucket
    directory)."""
    bucket, path = get_bucket_name_and_path(remote_path)
    if not os.path.exists(self._fs_bucket_path(bucket)):
      raise RuntimeError(
          'Bucket {bucket} does not exist.'.format(bucket=bucket))

    fs_path = self._fs_path(bucket, path, directory)
    shell.create_directory(os.path.dirname(fs_path), create_intermediates=True)

    return fs_path

  def create_bucket(self, name, object_lifecycle, cors):
    """Create a new bucket."""
    bucket_path = self._fs_bucket_path(name)
    if os.path.exists(bucket_path):
      return False

    os.makedirs(bucket_path)
    return True

  def get_bucket(self, name):
    """Get a bucket."""
    bucket_path = self._fs_bucket_path(name)
    if not os.path.exists(bucket_path):
      return None

    return {
        'name': name,
    }

  def _list_files_recursive(self, fs_path):
    """List files recursively."""
    for root, _, filenames in shell.walk(fs_path):
      for filename in filenames:
        yield os.path.join(root, filename)

  def _list_files_nonrecursive(self, fs_path):
    """List files non-recursively."""
    for filename in os.listdir(fs_path):
      yield os.path.join(fs_path, filename)

  def list_blobs(self, remote_path, recursive=True):
    """List the blobs under the remote path."""
    bucket, _ = get_bucket_name_and_path(remote_path)
    fs_path = self.convert_path(remote_path)

    if recursive:
      file_paths = self._list_files_recursive(fs_path)
    else:
      file_paths = self._list_files_nonrecursive(fs_path)

    for fs_path in file_paths:
      path = os.path.relpath(fs_path, self._fs_objects_dir(bucket))

      yield self._get_object_properties(
          get_cloud_storage_file_path(bucket, path))

  def copy_file_from(self, remote_path, local_path):
    """Copy file from a remote path to a local path."""
    fs_path = self.convert_path(remote_path)
    return shell.copy_file(fs_path, local_path)

  def copy_file_to(self, local_path_or_handle, remote_path, metadata=None):
    """Copy file from a local path to a remote path."""
    fs_path = self.convert_path_for_write(remote_path)

    if isinstance(local_path_or_handle, str):
      if not shell.copy_file(local_path_or_handle, fs_path):
        return False
    else:
      with open(fs_path, 'wb') as f:
        shutil.copyfileobj(local_path_or_handle, f)

    self._write_metadata(remote_path, metadata)
    return True

  def copy_blob(self, remote_source, remote_target):
    """Copy a remote file to another remote location."""
    fs_source_path = self.convert_path(remote_source)
    fs_target_path = self.convert_path_for_write(remote_target)
    return shell.copy_file(fs_source_path, fs_target_path)

  def read_data(self, remote_path):
    """Read the data of a remote file."""
    fs_path = self.convert_path(remote_path)
    if not os.path.exists(fs_path):
      return None

    with open(fs_path, 'rb') as f:
      return f.read()

  def write_data(self, data, remote_path, metadata=None):
    """Write the data of a remote file."""
    fs_path = self.convert_path_for_write(remote_path)
    if isinstance(data, str):
      data = data.encode()

    with open(fs_path, 'wb') as f:
      f.write(data)

    self._write_metadata(remote_path, metadata)
    return True

  def get(self, remote_path):
    """Get information about a remote file."""
    fs_path = self.convert_path(remote_path)
    if not os.path.exists(fs_path):
      return None

    return self._get_object_properties(remote_path)

  def delete(self, remote_path):
    """Delete a remote file."""
    fs_path = self.convert_path(remote_path)
    shell.remove_file(fs_path)

    fs_metadata_path = self.convert_path(remote_path, self.METADATA_DIR)
    shell.remove_file(fs_metadata_path)
    return True


class GcsBlobInfo(object):
  """GCS blob info."""

  def __init__(self,
               bucket,
               object_path,
               filename=None,
               size=None,
               legacy_key=None):
    self.bucket = bucket
    self.object_path = object_path

    if filename is not None and size is not None:
      self.filename = filename
      self.size = size
    else:
      gcs_object = get(get_cloud_storage_file_path(bucket, object_path))

      self.filename = gcs_object['metadata'].get(BLOB_FILENAME_METADATA_KEY)
      self.size = int(gcs_object['size'])

    self.legacy_key = legacy_key

  def key(self):
    if self.legacy_key:
      return self.legacy_key

    return self.object_path

  @property
  def gcs_path(self):
    return '/%s/%s' % (self.bucket, self.object_path)

  @staticmethod
  def from_key(key):
    try:
      return GcsBlobInfo(blobs_bucket(), key)
    except Exception:
      logs.log_error('Failed to get blob from key %s.' % key)
      return None

  @staticmethod
  def from_legacy_blob_info(blob_info):
    bucket, path = get_bucket_name_and_path(blob_info.gs_object_name)
    return GcsBlobInfo(bucket, path, blob_info.filename, blob_info.size,
                       blob_info.key.id())


def _provider():
  """Get the current storage provider."""
  local_buckets_path = environment.get_value('LOCAL_GCS_BUCKETS_PATH')
  if local_buckets_path:
    return FileSystemProvider(local_buckets_path)

  return GcsProvider()


def _create_storage_client_new():
  """Create a storage client."""
  creds, project = credentials.get_default()
  if not project:
    project = utils.get_application_id()

  return gcs.Client(project=project, credentials=creds)


def _storage_client():
  """Get the storage client, creating it if it does not exist."""
  if hasattr(_local, 'client'):
    return _local.client

  _local.client = _create_storage_client_new()
  return _local.client


def get_bucket_name_and_path(cloud_storage_file_path):
  """Return bucket name and path given a full cloud storage path."""
  filtered_path = utils.strip_from_left(cloud_storage_file_path, GS_PREFIX)
  _, bucket_name_and_path = filtered_path.split('/', 1)

  if '/' in bucket_name_and_path:
    bucket_name, path = bucket_name_and_path.split('/', 1)
  else:
    bucket_name = bucket_name_and_path
    path = ''

  return bucket_name, path


def get_cloud_storage_file_path(bucket, path):
  """Get the full GCS file path."""
  return GS_PREFIX + '/' + bucket + '/' + path


def _get_error_reason(http_error):
  """Get error reason from googleapiclient.errors.HttpError."""
  try:
    data = json.loads(http_error.content.decode('utf-8'))
    return data['error']['message']
  except (ValueError, KeyError):
    logs.log_error('Failed to decode error content: %s' % http_error.content)

  return None


@environment.local_noop
def add_single_bucket_iam(storage, iam_policy, role, bucket_name, member):
  """Attempt to add a single bucket IAM. Returns the modified iam policy, or
  None on failure."""
  binding = get_bucket_iam_binding(iam_policy, role)
  binding['members'].append(member)

  result = set_bucket_iam_policy(storage, bucket_name, iam_policy)

  binding['members'].pop()
  return result


@environment.local_noop
def get_bucket_iam_binding(iam_policy, role):
  """Get the binding matching a role, or None."""
  return next((
      binding for binding in iam_policy['bindings'] if binding['role'] == role),
              None)


@environment.local_noop
def get_or_create_bucket_iam_binding(iam_policy, role):
  """Get or create the binding matching a role."""
  binding = get_bucket_iam_binding(iam_policy, role)
  if not binding:
    binding = {'role': role, 'members': []}
    iam_policy['bindings'].append(binding)

  return binding


@environment.local_noop
def remove_bucket_iam_binding(iam_policy, role):
  """Remove existing binding matching the role."""
  iam_policy['bindings'] = [
      binding for binding in iam_policy['bindings'] if binding['role'] != role
  ]


@environment.local_noop
def get_bucket_iam_policy(storage, bucket_name):
  """Get bucket IAM policy."""
  try:
    iam_policy = storage.buckets().getIamPolicy(bucket=bucket_name).execute()
  except HttpError as e:
    logs.log_error('Failed to get IAM policies for %s: %s' % (bucket_name, e))
    return None

  return iam_policy


@environment.local_noop
def set_bucket_iam_policy(client, bucket_name, iam_policy):
  """Set bucket IAM policy."""
  filtered_iam_policy = copy.deepcopy(iam_policy)

  # Bindings returned by getIamPolicy can have duplicates. Remove them or
  # otherwise, setIamPolicy operation fails.
  for binding in filtered_iam_policy['bindings']:
    binding['members'] = sorted(list(set(binding['members'])))

  # Filtering members can cause a binding to have no members. Remove binding
  # or otherwise, setIamPolicy operation fails.
  filtered_iam_policy['bindings'] = [
      b for b in filtered_iam_policy['bindings'] if b['members']
  ]

  try:
    return client.buckets().setIamPolicy(
        bucket=bucket_name, body=filtered_iam_policy).execute()
  except HttpError as e:
    error_reason = _get_error_reason(e)
    if error_reason == 'Invalid argument':
      # Expected error for non-Google emails or groups. Warn about these.
      logs.log_warn('Invalid Google email or group being added to bucket %s.' %
                    bucket_name)
    elif error_reason and 'is of type "group"' in error_reason:
      logs.log_warn('Failed to set IAM policy for %s bucket for a group: %s.' %
                    (bucket_name, error_reason))
    else:
      logs.log_error('Failed to set IAM policies for bucket %s.' % bucket_name)

  return None


def create_bucket_if_needed(bucket_name, object_lifecycle=None, cors=None):
  """Creates a GCS bucket."""
  provider = _provider()
  if provider.get_bucket(bucket_name):
    return True

  if not provider.create_bucket(bucket_name, object_lifecycle, cors):
    return False

  time.sleep(CREATE_BUCKET_DELAY)
  return True


@environment.local_noop
def create_discovery_storage_client():
  """Create a storage client using discovery APIs."""
  return build('storage', 'v1', cache_discovery=False)


def generate_life_cycle_config(action, age=None, num_newer_versions=None):
  """Generate GCS lifecycle management config.

  For the reference, see https://cloud.google.com/storage/docs/lifecycle and
  https://cloud.google.com/storage/docs/managing-lifecycles.
  """
  rule = {}
  rule['action'] = {'type': action}
  rule['condition'] = {}
  if age is not None:
    rule['condition']['age'] = age
  if num_newer_versions is not None:
    rule['condition']['numNewerVersions'] = num_newer_versions

  config = {'rule': [rule]}
  return config


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.copy_file_from',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def copy_file_from(cloud_storage_file_path, local_file_path, use_cache=False):
  """Saves a cloud storage file locally."""
  if use_cache and get_file_from_cache_if_exists(local_file_path):
    logs.log('Copied file %s from local cache.' % cloud_storage_file_path)
    return True

  if not _provider().copy_file_from(cloud_storage_file_path, local_file_path):
    return False

  if use_cache:
    store_file_in_cache(local_file_path)

  return True


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.copy_file_to',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def copy_file_to(local_file_path_or_handle,
                 cloud_storage_file_path,
                 metadata=None):
  """Copy local file to a cloud storage path."""
  if (isinstance(local_file_path_or_handle, str) and
      not os.path.exists(local_file_path_or_handle)):
    logs.log_error('Local file %s not found.' % local_file_path_or_handle)
    return False

  return _provider().copy_file_to(
      local_file_path_or_handle, cloud_storage_file_path, metadata=metadata)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.copy_blob',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def copy_blob(cloud_storage_source_path, cloud_storage_target_path):
  """Copy two blobs on GCS 'in the cloud' without touching local disk."""
  return _provider().copy_blob(cloud_storage_source_path,
                               cloud_storage_target_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.delete',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def delete(cloud_storage_file_path):
  """Delete a cloud storage file given its path."""
  return _provider().delete(cloud_storage_file_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.exists')
def exists(cloud_storage_file_path, ignore_errors=False):
  """Return whether if a cloud storage file exists."""
  try:
    return bool(_provider().get(cloud_storage_file_path))
  except HttpError:
    if not ignore_errors:
      logs.log_error('Failed when trying to find cloud storage file %s.' %
                     cloud_storage_file_path)

    return False


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.last_updated',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def last_updated(cloud_storage_file_path):
  """Return last updated value by parsing stats for all blobs under a cloud
  storage path."""
  last_update = None
  for blob in _provider().list_blobs(cloud_storage_file_path):
    if not last_update or blob['updated'] > last_update:
      last_update = blob['updated']
  if last_update:
    # Remove UTC tzinfo to make these comparable.
    last_update = last_update.replace(tzinfo=None)
  return last_update


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.read_data',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def read_data(cloud_storage_file_path):
  """Return content of a cloud storage file."""
  return _provider().read_data(cloud_storage_file_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.write_data',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def write_data(data, cloud_storage_file_path, metadata=None):
  """Return content of a cloud storage file."""
  return _provider().write_data(
      data, cloud_storage_file_path, metadata=metadata)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.get_blobs',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def get_blobs(cloud_storage_path, recursive=True):
  """Return blobs under the given cloud storage path."""
  for blob in _provider().list_blobs(cloud_storage_path, recursive=recursive):
    yield blob


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.list_blobs',
    exception_type=google.cloud.exceptions.GoogleCloudError)
def list_blobs(cloud_storage_path, recursive=True):
  """Return blob names under the given cloud storage path."""
  for blob in _provider().list_blobs(cloud_storage_path, recursive=recursive):
    yield blob['name']


def get_download_file_size(cloud_storage_file_path,
                           file_path=None,
                           use_cache=False):
  """Get the download file size of the bucket path."""
  if use_cache and file_path:
    size_from_cache = get_file_size_from_cache_if_exists(file_path)
    if size_from_cache is not None:
      return size_from_cache

  return get_object_size(cloud_storage_file_path)


@utils.timeout(CACHE_TIMEOUT)
def get_file_from_cache_if_exists(file_path,
                                  update_modification_time_on_access=True):
  """Get file from nfs cache if available."""
  cache_file_path = get_cache_file_path(file_path)
  if not cache_file_path or not file_exists_in_cache(cache_file_path):
    # If the file does not exist in cache, bail out.
    return False

  # Fetch cache file size before starting the actual copy.
  cache_file_size = get_cache_file_size_from_metadata(cache_file_path)

  # Copy file from cache to local.
  if not shell.copy_file(cache_file_path, file_path):
    return False

  # Update timestamp to later help with eviction of old files.
  if update_modification_time_on_access:
    update_access_and_modification_timestamp(cache_file_path)

  # Return success or failure based on existence of local file and size
  # comparison.
  return (os.path.exists(file_path) and
          os.path.getsize(file_path) == cache_file_size)


@utils.timeout(CACHE_TIMEOUT)
def get_file_size_from_cache_if_exists(file_path):
  """Get file size from nfs cache if available."""
  cache_file_path = get_cache_file_path(file_path)
  if not cache_file_path or not file_exists_in_cache(cache_file_path):
    # If the file does not exist in cache, bail out.
    return None

  return get_cache_file_size_from_metadata(cache_file_path)


def get_cache_file_path(file_path):
  """Return cache file path given a local file path."""
  if not environment.get_value('NFS_ROOT'):
    return None

  return os.path.join(
      environment.get_value('NFS_ROOT'), CACHE_DIRNAME,
      utils.get_directory_hash_for_path(file_path), os.path.basename(file_path))


def get_cache_file_metadata_path(cache_file_path):
  """Return metadata file path for a cache file."""
  return '%s%s' % (cache_file_path, CACHE_METADATA_FILE_EXTENSION)


def get_cache_file_size_from_metadata(cache_file_path):
  """Return cache file size from metadata file."""
  cache_file_metadata_path = get_cache_file_metadata_path(cache_file_path)
  metadata_content = utils.read_data_from_file(
      cache_file_metadata_path, eval_data=True)

  if not metadata_content or 'size' not in metadata_content:
    return None

  return metadata_content['size']


def write_cache_file_metadata(cache_file_path, file_path):
  """Write cache file metadata."""
  cache_file_metadata_path = get_cache_file_metadata_path(cache_file_path)
  utils.write_data_to_file({
      'size': os.path.getsize(file_path)
  }, cache_file_metadata_path)


def remove_cache_file_and_metadata(cache_file_path):
  """Removes cache file and its metadata."""
  logs.log('Removing cache file %s and its metadata.' % cache_file_path)
  shell.remove_file(get_cache_file_metadata_path(cache_file_path))
  shell.remove_file(cache_file_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.'
    'update_access_and_modification_timestamp')
def update_access_and_modification_timestamp(file_path):
  os.utime(file_path, None)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.file_exists_in_cache')
def file_exists_in_cache(cache_file_path):
  """Returns if the file exists in cache."""
  cache_file_metadata_path = get_cache_file_metadata_path(cache_file_path)
  if not os.path.exists(cache_file_metadata_path):
    return False

  if not os.path.exists(cache_file_path):
    return False

  actual_cache_file_size = os.path.getsize(cache_file_path)
  expected_cache_file_size = get_cache_file_size_from_metadata(cache_file_path)
  return actual_cache_file_size == expected_cache_file_size


@utils.timeout(CACHE_TIMEOUT)
def store_file_in_cache(file_path,
                        cached_files_per_directory_limit=True,
                        force_update=False):
  """Get file from nfs cache if available."""
  if not os.path.exists(file_path):
    logs.log_error(
        'Local file %s does not exist, nothing to store in cache.' % file_path)
    return

  if os.path.getsize(file_path) > CACHE_SIZE_LIMIT:
    logs.log('File %s is too large to store in cache, skipping.' % file_path)
    return

  nfs_root = environment.get_value('NFS_ROOT')
  if not nfs_root:
    # No NFS, nothing to store in cache.
    return

  # If NFS server is not available due to heavy load, skip storage operation
  # altogether as we would fail to store file.
  if not os.path.exists(os.path.join(nfs_root, '.')):  # Use . to iterate mount.
    logs.log_warn('Cache %s not available.' % nfs_root)
    return

  cache_file_path = get_cache_file_path(file_path)
  cache_directory = os.path.dirname(cache_file_path)
  filename = os.path.basename(file_path)

  if not os.path.exists(cache_directory):
    if not shell.create_directory(cache_directory, create_intermediates=True):
      logs.log_error('Failed to create cache directory %s.' % cache_directory)
      return

  # Check if the file already exists in cache.
  if file_exists_in_cache(cache_file_path):
    if not force_update:
      return

    # If we are forcing update, we need to remove current cached file and its
    # metadata.
    remove_cache_file_and_metadata(cache_file_path)

  # Delete old cached files beyond our maximum storage limit.
  if cached_files_per_directory_limit:
    # Get a list of cached files.
    cached_files_list = []
    for cached_filename in os.listdir(cache_directory):
      if cached_filename.endswith(CACHE_METADATA_FILE_EXTENSION):
        continue
      cached_file_path = os.path.join(cache_directory, cached_filename)
      cached_files_list.append(cached_file_path)

    mtime = lambda f: os.stat(f).st_mtime
    last_used_cached_files_list = list(
        sorted(cached_files_list, key=mtime, reverse=True))
    for cached_file_path in (
        last_used_cached_files_list[MAX_CACHED_FILES_PER_DIRECTORY - 1:]):
      remove_cache_file_and_metadata(cached_file_path)

  # Start storing the actual file in cache now.
  logs.log('Started storing file %s into cache.' % filename)

  # Fetch lock to store this file. Try only once since if any other bot has
  # started to store it, we don't need to do it ourselves. Just bail out.
  lock_name = 'store:cache_file:%s' % utils.string_hash(cache_file_path)
  if not locks.acquire_lock(
      lock_name, max_hold_seconds=CACHE_LOCK_TIMEOUT, retries=1, by_zone=True):
    logs.log_warn(
        'Unable to fetch lock to update cache file %s, skipping.' % filename)
    return

  # Check if another bot already updated it.
  if file_exists_in_cache(cache_file_path):
    locks.release_lock(lock_name, by_zone=True)
    return

  shell.copy_file(file_path, cache_file_path)
  write_cache_file_metadata(cache_file_path, file_path)
  time.sleep(CACHE_COPY_WAIT_TIME)
  error_occurred = not file_exists_in_cache(cache_file_path)
  locks.release_lock(lock_name, by_zone=True)

  if error_occurred:
    logs.log_error('Failed to store file %s into cache.' % filename)
  else:
    logs.log('Completed storing file %s into cache.' % filename)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.get')
def get(cloud_storage_file_path):
  """Get GCS object data."""
  return _provider().get(cloud_storage_file_path)


@environment.local_noop
@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.get_acl')
def get_acl(cloud_storage_file_path, entity):
  """Get the access control for a file."""
  client = create_discovery_storage_client()
  bucket, path = get_bucket_name_and_path(cloud_storage_file_path)

  try:
    return client.objectAccessControls().get(
        bucket=bucket, object=path, entity=entity).execute()
  except HttpError as e:
    if e.resp.status == 404:
      return None

    raise


@environment.local_noop
@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.set_acl')
def set_acl(cloud_storage_file_path, entity, role='READER'):
  """Set the access control for a file."""
  client = create_discovery_storage_client()
  bucket, path = get_bucket_name_and_path(cloud_storage_file_path)

  try:
    return client.objectAccessControls().insert(
        bucket=bucket, object=path, body={
            'entity': entity,
            'role': role
        }).execute()
  except HttpError as e:
    if e.resp.status == 404:
      return None

    raise


def get_object_size(cloud_storage_file_path):
  """Get the metadata for a file."""
  gcs_object = get(cloud_storage_file_path)
  if not gcs_object:
    return gcs_object

  return int(gcs_object['size'])


def blobs_bucket():
  """Get the blobs bucket name."""
  # Allow tests to override blobs bucket name safely.
  test_blobs_bucket = environment.get_value('TEST_BLOBS_BUCKET')
  if test_blobs_bucket:
    return test_blobs_bucket

  assert not environment.get_value('PY_UNITTESTS')
  return local_config.ProjectConfig().get('blobs.bucket')
