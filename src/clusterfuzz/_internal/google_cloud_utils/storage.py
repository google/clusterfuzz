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
import requests
import requests.exceptions

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell

from . import credentials

# pylint: disable=no-member

try:
  import google.cloud
  from google.cloud import storage as gcs
  import google.cloud.storage.fileio
except ImportError:
  # This is expected to fail on AppEngine.
  pass

# Usually, authentication time have expiry of ~30 minutes, but keeping this
# values lower to avoid failures and any future changes.
AUTH_TOKEN_EXPIRY_TIME = 10 * 60

# The number of retries to perform some GCS operation.
DEFAULT_FAIL_RETRIES = 8

# The time to wait between retries while performing GCS operation.
DEFAULT_FAIL_WAIT = 2

# Prefix for GCS urls.
GS_PREFIX = 'gs:/'

# https://cloud.google.com/storage/docs/best-practices states that we can
# create/delete 1 bucket about every 2 seconds.
CREATE_BUCKET_DELAY = 4

# GCS blob metadata key for filename.
BLOB_FILENAME_METADATA_KEY = 'filename'

# Thread local globals.
_local = threading.local()

# Urls for web viewer.
OBJECT_URL = 'https://storage.cloud.google.com'
DIRECTORY_URL = 'https://console.cloud.google.com/storage/browser'

# Expiration in minutes for signed URL.
SIGNED_URL_EXPIRATION_MINUTES = 24 * 60

# Timeout for HTTP operations.
HTTP_TIMEOUT_SECONDS = 15

_TRANSIENT_ERRORS = [
    google.cloud.exceptions.GoogleCloudError,
    ConnectionError,
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
    ConnectionResetError,
]


class StorageProvider:
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

  def write_stream(self, stream, remote_path, metadata=None):
    """Write the data of a generator."""
    raise NotImplementedError

  def get(self, remote_path):
    """Get information about a remote file."""
    raise NotImplementedError

  def delete(self, remote_path):
    """Delete a remote file."""
    raise NotImplementedError

  def sign_download_url(self,
                        remote_path,
                        minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Signs a download URL for a remote file."""
    raise NotImplementedError

  def sign_upload_url(self, remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Signs an upload URL for a remote file."""
    raise NotImplementedError

  def download_signed_url(self, signed_url):
    """Downloads |signed_url|."""
    raise NotImplementedError

  def upload_signed_url(self, data, signed_url):
    """Uploads |data| to |signed_url|."""
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

  def write_stream(self, stream, remote_path, metadata=None):
    """Writes the data from an iterator in chunks to a remote file."""
    client = _storage_client()
    bucket_name, path = get_bucket_name_and_path(remote_path)

    try:
      bucket = client.bucket(bucket_name)
      blob = bucket.blob(path, chunk_size=self._chunk_size())
      if metadata:
        blob.metadata = metadata
      with gcs.fileio.BlobWriter(blob) as blob_writer:
        for data in stream:
          if isinstance(data, str):
            data = data.encode()
          blob_writer.write(data)
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

  def sign_download_url(self,
                        remote_path,
                        minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Signs a download URL for a remote file."""
    return _sign_url(remote_path, method='GET', minutes=minutes)

  def sign_upload_url(self, remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Signs an upload URL for a remote file."""
    return _sign_url(remote_path, method='PUT', minutes=minutes)

  def download_signed_url(self, signed_url):
    """Downloads |signed_url|."""
    return _download_url(signed_url)

  def upload_signed_url(self, data, signed_url):
    """Uploads |data| to |signed_url|."""
    requests.put(signed_url, data=data, timeout=HTTP_TIMEOUT_SECONDS)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage._sign_url')
def _sign_url(remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES, method='GET'):
  """Returns a signed URL for |remote_path| with |method|."""
  if environment.get_value('UTASK_TESTS') or environment.get_value(
      'UNTRUSTED_RUNNER_TESTS'):
    return remote_path
  minutes = datetime.timedelta(minutes=minutes)
  bucket_name, object_path = get_bucket_name_and_path(remote_path)
  signing_creds = _signing_creds()
  client = _storage_client()
  bucket = client.bucket(bucket_name)
  blob = bucket.blob(object_path)
  url = blob.generate_signed_url(
      version='v4',
      expiration=minutes,
      method=method,
      credentials=signing_creds)
  return url


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

  def write_stream(self, stream, remote_path, metadata=None):
    """Write the data of a remote file."""
    fs_path = self.convert_path_for_write(remote_path)

    with open(fs_path, 'wb') as f:
      for data in stream:
        if isinstance(data, str):
          data = data.encode()
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

  def sign_download_url(self,
                        remote_path,
                        minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Returns remote_path since we are pretending to sign a URL for
    download."""
    del minutes
    return remote_path

  def sign_upload_url(self, remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES):
    """Returns remote_path since we are pretending to sign a URL for
    upload."""
    del minutes
    return remote_path

  def download_signed_url(self, signed_url):
    """Downloads |signed_url|."""
    return self.read_data(signed_url)

  def upload_signed_url(self, data, signed_url):
    """Uploads |data| to |signed_url|."""
    return self.write_data(data, signed_url)


class GcsBlobInfo:
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


def _signing_creds():
  if hasattr(_local, 'signing_creds'):
    return _local.signing_creds
  _local.signing_creds = credentials.get_signing_credentials()
  return _local.signing_creds


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
    exception_types=_TRANSIENT_ERRORS)
def copy_file_from(cloud_storage_file_path, local_file_path):
  """Saves a cloud storage file locally."""
  if not _provider().copy_file_from(cloud_storage_file_path, local_file_path):
    return False

  return True


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.copy_file_to',
    exception_types=_TRANSIENT_ERRORS)
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
    exception_types=_TRANSIENT_ERRORS)
def copy_blob(cloud_storage_source_path, cloud_storage_target_path):
  """Copy two blobs on GCS 'in the cloud' without touching local disk."""
  return _provider().copy_blob(cloud_storage_source_path,
                               cloud_storage_target_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.delete',
    exception_types=_TRANSIENT_ERRORS)
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
    exception_types=_TRANSIENT_ERRORS)
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
    exception_types=_TRANSIENT_ERRORS)
def read_data(cloud_storage_file_path):
  """Return content of a cloud storage file."""
  return _provider().read_data(cloud_storage_file_path)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.write_data',
    exception_types=_TRANSIENT_ERRORS)
def write_data(data, cloud_storage_file_path, metadata=None):
  """Return content of a cloud storage file."""
  return _provider().write_data(
      data, cloud_storage_file_path, metadata=metadata)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.write_data',
    exception_types=_TRANSIENT_ERRORS)
def write_stream(stream, cloud_storage_file_path, metadata=None):
  """Return content of a cloud storage file."""
  return _provider().write_stream(
      stream, cloud_storage_file_path, metadata=metadata)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.get_blobs',
    exception_types=_TRANSIENT_ERRORS)
def get_blobs(cloud_storage_path, recursive=True):
  """Return blobs under the given cloud storage path."""
  yield from _provider().list_blobs(cloud_storage_path, recursive=recursive)


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.list_blobs',
    exception_types=_TRANSIENT_ERRORS)
def list_blobs(cloud_storage_path, recursive=True):
  """Return blob names under the given cloud storage path."""
  for blob in _provider().list_blobs(cloud_storage_path, recursive=recursive):
    yield blob['name']


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


def uworker_input_bucket():
  """Returns the bucket where uworker input is done."""
  test_uworker_input_bucket = environment.get_value('TEST_UWORKER_INPUT_BUCKET')
  if test_uworker_input_bucket:
    return test_uworker_input_bucket

  assert not environment.get_value('PY_UNITTESTS')
  # TODO(metzman): Use local config.
  bucket = environment.get_value('UWORKER_INPUT_BUCKET')
  if not bucket:
    logs.log_error('UWORKER_INPUT_BUCKET is not defined.')
  return bucket


def uworker_output_bucket():
  """Returns the bucket where uworker I/O is done."""
  test_uworker_output_bucket = environment.get_value(
      'TEST_UWORKER_OUTPUT_BUCKET')
  if test_uworker_output_bucket:
    return test_uworker_output_bucket

  assert not environment.get_value('PY_UNITTESTS')
  # TODO(metzman): Use local config.
  bucket = environment.get_value('UWORKER_OUTPUT_BUCKET')
  if not bucket:
    logs.log_error('UWORKER_OUTPUT_BUCKET is not defined.')
  return bucket


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage._download_url',
    exception_types=_TRANSIENT_ERRORS)
def _download_url(url):
  """Downloads |url| and returns the contents."""
  if environment.get_value('UTASK_TESTS'):
    return read_data(url)
  request = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
  if not request.ok:
    raise RuntimeError('Request to %s failed. Code: %d. Reason: %s' %
                       (url, request.status_code, request.reason))
  return request.content


@retry.wrap(
    retries=DEFAULT_FAIL_RETRIES,
    delay=DEFAULT_FAIL_WAIT,
    function='google_cloud_utils.storage.upload_signed_url')
def upload_signed_url(data, url):
  """Uploads data to the |signed_url|."""
  return _provider().upload_signed_url(data, url)


def download_signed_url(url):
  """Returns contents of |url|. Writes to |local_path| if provided."""
  return _provider().download_signed_url(url)


def download_signed_url_to_file(url, filepath):
  contents = download_signed_url(url)
  os.makedirs(os.path.dirname(filepath), exist_ok=True)
  with open(filepath, 'wb') as fp:
    fp.write(contents)
  return True


def get_signed_upload_url(remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES):
  """Returns a signed upload URL for |remote_path|. Does not download the
  contents."""
  provider = _provider()
  return provider.sign_upload_url(remote_path, minutes=minutes)


def get_signed_download_url(remote_path, minutes=SIGNED_URL_EXPIRATION_MINUTES):
  """Returns a signed download URL for |remote_path|. Does not download the
  contents."""
  provider = _provider()
  return provider.sign_download_url(remote_path, minutes=minutes)
