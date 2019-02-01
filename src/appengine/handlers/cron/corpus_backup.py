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
"""corpus backup handler."""

import datetime

from base import utils
from datastore import data_types
from datastore import fuzz_target_utils
from datastore import ndb_utils
from fuzzing import corpus_manager
from google_cloud_utils import storage
from handlers import base_handler
from libs import handler
from metrics import logs


def _make_corpus_backup_public(target, corpus_fuzzer_name_override,
                               corpus_backup_bucket_name):
  """Identifies old corpus backups and makes them public."""
  corpus_backup_date = utils.utcnow().date() - datetime.timedelta(
      days=data_types.CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS)

  corpus_backup_url = corpus_manager.gcs_url_for_backup_file(
      corpus_backup_bucket_name, corpus_fuzzer_name_override or target.engine,
      target.project_qualified_name(), corpus_backup_date)

  try:
    result = storage.get(corpus_backup_url)
  except:
    result = None

  if not result:
    logs.log_warn('Failed to find corpus backup %s.' % corpus_backup_url)
    return

  try:
    result = storage.get_acl(corpus_backup_url, 'allUsers')
  except:
    result = None

  if result:
    # Backup is already marked public. Skip.
    logs.log('Corpus backup %s is already marked public, skipping.' %
             corpus_backup_url)
    return

  try:
    result = storage.set_acl(corpus_backup_url, 'allUsers')
  except:
    result = None

  if not result:
    logs.log_error(
        'Failed to mark corpus backup %s public.' % corpus_backup_url)
    return

  logs.log('Corpus backup %s is now marked public.' % corpus_backup_url)


class MakePublicHandler(base_handler.Handler):
  """Makes corpuses older than 90 days public."""

  @handler.check_cron()
  def get(self):
    """Handle a GET request."""
    jobs = ndb_utils.get_all_from_model(data_types.Job)
    for job in jobs:
      job_environment = job.get_environment()
      if utils.string_is_true(job_environment.get('EXPERIMENTAL')):
        # Don't use corpus backups from experimental jobs. Skip.
        continue

      if not utils.string_is_true(job_environment.get('CORPUS_PRUNE')):
        # There won't be any corpus backups for these jobs. Skip.
        continue

      corpus_backup_bucket_name = job_environment.get('BACKUP_BUCKET')
      if not corpus_backup_bucket_name:
        # No backup bucket found. Skip.
        continue

      corpus_fuzzer_name_override = job_environment.get(
          'CORPUS_FUZZER_NAME_OVERRIDE')

      target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(job=job.name))
      fuzz_targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(
          target_jobs)

      for target in fuzz_targets:
        _make_corpus_backup_public(target, corpus_fuzzer_name_override,
                                   corpus_backup_bucket_name)
