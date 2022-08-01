# Copyright 2020 Google LLC
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
"""Utility functions for ML training tasks."""

import os

from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from clusterfuzz._internal.system import archive
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell


def get_corpus(corpus_directory, fuzzer_name):
  """Get corpus directory.

  This function will download latest corpus backup file from GCS, unzip
  the file and put them in corpus directory.

  Args:
    directory: The directory to place corpus.
    fuzzer_name: Fuzzer name, e.g. libpng_read_fuzzer, xml_parser_fuzzer, etc.

  Returns:
    True if the corpus can be acquired and False otherwise.
  """
  backup_bucket_name = environment.get_value('BACKUP_BUCKET')
  corpus_fuzzer_name = environment.get_value('CORPUS_FUZZER_NAME_OVERRIDE')

  # Get GCS backup path.
  gcs_backup_path = corpus_manager.gcs_url_for_backup_file(
      backup_bucket_name, corpus_fuzzer_name, fuzzer_name,
      corpus_manager.LATEST_BACKUP_TIMESTAMP)

  # Get local backup path.
  local_backup_name = os.path.basename(gcs_backup_path)
  local_backup_path = os.path.join(corpus_directory, local_backup_name)

  # Download latest backup.
  if not storage.copy_file_from(gcs_backup_path, local_backup_path):
    logs.log_error(
        'Failed to download corpus from GCS bucket {}.'.format(gcs_backup_path))
    return False

  # Extract corpus from zip file.
  archive.unpack(local_backup_path, corpus_directory)
  shell.remove_file(local_backup_path)
  return True


def get_gcs_model_directory(folder, fuzzer_name):
  """
  Get gcs bucket path to store latest model.

  Args:
    folder (str): Subdirectory denoting the category of ML model being trained.
    fuzzer_name (str): Exactly what gets passed in to `execute_task()`.

  Returns:
    A string with the GCS absolute path to upload the model to.
  """
  model_bucket_name = environment.get_value('CORPUS_BUCKET')
  if not model_bucket_name:
    return None

  gcs_model_directory = 'gs://{}/{}/{}'.format(model_bucket_name, folder,
                                               fuzzer_name)

  return gcs_model_directory
