# Copyright 2024 Google LLC
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
"""Migrates blobs and databundles to a test project"""

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.system import environment
from local.butler import common

BACKOFF_BASE_INTERVAL = 2
MAX_RETRIES = 3

#TODO(vitorguidi): generalize this so we can point to other projects
_PROD_BLOB_BUCKET = 'clusterfuzz-blobs'
_STAGING_BLOB_BUCKET = 'blobs.clusterfuzz-development.appspot.com'
_PROD_BUCKET_DOMAINS = [
    'cluster-fuzz.appspot.com',
    'clusterfuzz.com',
]
_STAGING_BUCKET_DOMAIN = 'clusterfuzz-development.appspot.com'


def _copy_blob(origin_blob_path, target_blob_path):
  assert not _PROD_BLOB_BUCKET in target_blob_path
  assert _STAGING_BLOB_BUCKET in target_blob_path

  storage.copy_blob(origin_blob_path, target_blob_path)
  print(f'Copied blob {origin_blob_path} to {target_blob_path}')


def _migrate_gcs_blob(source_blob_key):
  """grates blobs in the new GCS scheme."""
  print(f'Copying blob {source_blob_key} to the same name in the staging.')
  origin_blob_path = f'gs://{_PROD_BLOB_BUCKET}/{source_blob_key}'
  target_blob_path = f'gs://{_STAGING_BLOB_BUCKET}/{source_blob_key}'
  try:
    _copy_blob(origin_blob_path, target_blob_path)
  except Exception:
    # This might have be a legacy blobkey in prod which
    # was migrated to a gcs ke in staging. This should be
    # idempotent
    origin_blob_path = target_blob_path
    _copy_blob(origin_blob_path, target_blob_path)
  finally:
    # The blob key remains the same before and after migration
    return source_blob_key  # # pylint: disable=lost-exception


def _migrate_legacy_blob(source_blob_key):
  """Migrate blobs in the legacy blobstore scheme."""
  legacy_blob_info = ndb.Key(
      blobs._blobmigrator_BlobKeyMapping,  # pylint: disable=protected-access
      source_blob_key).get()
  source_blob_path = legacy_blob_info.gcs_filename
  new_blob_key = blobs.generate_new_blob_name()

  _copy_blob(f'gs:/{source_blob_path}',
             f'gs://{_STAGING_BLOB_BUCKET}/{new_blob_key}')
  return new_blob_key


def migrate_blob(source_blob_key):
  """
      Takes the source blob from the production bucket and copies it to
      a target blob in the staging bucket. This is safe to run multiple times,
      since either:
         - The source blob is a gcs url, and will be copied with the same
            blob key over and over, so this is idempotent;
         - Or the source blob is a legacy key, mapped to a gcs object in prod,
            with the mapping in the _blogmigrator_BlobKeyMapping entity. We keep 
            the blob key, and only the gcs_filename changes. We copy the same
            file everytime, so idempotency ensues.
   """

  if blobs._is_gcs_key(source_blob_key):  # pylint: disable=protected-access
    return _migrate_gcs_blob(source_blob_key)

  return _migrate_legacy_blob(source_blob_key)


def migrate_bucket(source_bucket, target_bucket):
  """
      Creates the target bucket, if it does not exist, and
      moves all content from the source bucket into it.
   """

  bucket_exists = storage.create_bucket_if_needed(target_bucket)

  assert bucket_exists
  sync_from = f'gs://{source_bucket}'
  sync_to = f'gs://{target_bucket}'
  command = f'gcloud storage rsync --recursive {sync_from} {sync_to}'
  error_code, output = common.execute(command, exit_on_error=False)
  output_as_str = str(output)
  print(output_as_str)
  if error_code == 0:
    print(f'Migrated bucket contents from {source_bucket} to {target_bucket}')
  else:
    print(f'Failed to migrate bucket: {output_as_str}')


def migrate_data_bundle(data_bundle):
  """
   Migrates a data bundle from prod to staging by replicating the
    respective blob from blobstore_key, keeping the same key, and
    moving the bucket contents from the production
    bucket to the corresponding one in staging.
   """
  print(f'Migrating data bundle {data_bundle.name}')
  bundle_corpus_gcs_bucket = data_bundle.bucket_name
  if '__common' in data_bundle.name:
    print(f'Data bundle {data_bundle.name} is deprecated, skipping')
    return
  target_corpus_bucket = ''
  for domain in _PROD_BUCKET_DOMAINS:
    if domain in bundle_corpus_gcs_bucket:
      target_corpus_bucket = bundle_corpus_gcs_bucket.replace(
          domain, _STAGING_BUCKET_DOMAIN)

  if bundle_corpus_gcs_bucket == target_corpus_bucket:
    # rsync already succeeded before and the entity was persisted
    return

  assert _STAGING_BUCKET_DOMAIN in target_corpus_bucket

  migrate_bucket(bundle_corpus_gcs_bucket, target_corpus_bucket)
  data_bundle.bucket_name = target_corpus_bucket
  data_bundle.put()


def migrate_fuzzer(fuzzer):
  """
   Migrates a fuzzer from production to staging. It suffices to replicate the
   blobstore key to the staging blobs bucket, keeping the same key.
   """
  print(f'Migrating fuzzer {fuzzer.name}')
  source_blob = fuzzer.blobstore_key
  if not source_blob:
    print('No blobstore_key, skipping')
    return
  new_blob_key = migrate_blob(source_blob)
  fuzzer.blobstore_key = new_blob_key
  fuzzer.put()
  print(f'Migrated {fuzzer.name} to gs://{_STAGING_BLOB_BUCKET}/{new_blob_key}')


def migrate_job(job):
  """
   Migrates a job from production to staging. It suffices to replicate the
   custom binary blob to the staging blobs bucket, keeping the same key.
   """
  source_blob = job.custom_binary_key
  if not source_blob:
    print('No custom binary key, skipping')
    return
  new_blob_key = migrate_blob(source_blob)
  job.custom_binary_key = new_blob_key
  job.put()
  print(
      f'Migrated job {job.name} to gcs://{_STAGING_BLOB_BUCKET}/{new_blob_key}')


def execute(args):  #pylint: disable=unused-argument
  """Build keywords."""
  environment.set_bot_environment()
  print('checking jobs')
  for job in data_types.Job.query():
    migrate_job(job)
  print('\n\n')

  print('checking fuzzers')
  for fuzzer in data_types.Fuzzer.query():
    migrate_fuzzer(fuzzer)
  print('\n\n')

  print('checking databundle')
  for data_bundle in data_types.DataBundle.query():
    migrate_data_bundle(data_bundle)
  print('\n\n')

  print('done')
