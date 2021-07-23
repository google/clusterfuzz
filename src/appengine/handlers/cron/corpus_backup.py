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
import os

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import fuzz_target_utils
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.fuzzing import corpus_manager
from clusterfuzz._internal.google_cloud_utils import storage
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler


def _set_public_acl_if_needed(url):
  """Sets public ACL on the object with given URL, if it's not public yet."""
  if storage.get_acl(url, 'allUsers'):
    logs.log('%s is already marked public, skipping.' % url)
    return True

  if not storage.set_acl(url, 'allUsers'):
    logs.log_error('Failed to mark %s public.' % url)
    return False

  return True


def _make_corpus_backup_public(target, corpus_fuzzer_name_override,
                               corpus_backup_bucket_name):
  """Identifies old corpus backups and makes them public."""
  corpus_backup_date = utils.utcnow().date() - datetime.timedelta(
      days=data_types.CORPUS_BACKUP_PUBLIC_LOOKBACK_DAYS)

  corpus_backup_url = corpus_manager.gcs_url_for_backup_file(
      corpus_backup_bucket_name, corpus_fuzzer_name_override or target.engine,
      target.project_qualified_name(), corpus_backup_date)

  if not storage.get(corpus_backup_url):
    logs.log_warn('Failed to find corpus backup %s.' % corpus_backup_url)
    return

  if not _set_public_acl_if_needed(corpus_backup_url):
    return

  filename = (
      corpus_manager.PUBLIC_BACKUP_TIMESTAMP + os.extsep +
      corpus_manager.BACKUP_ARCHIVE_FORMAT)
  public_url = os.path.join(os.path.dirname(corpus_backup_url), filename)

  if not storage.copy_blob(corpus_backup_url, public_url):
    logs.log_error(
        'Failed to overwrite %s with the latest public corpus backup.' %
        public_url)
    return

  if not _set_public_acl_if_needed(public_url):
    return

  logs.log('Corpus backup %s is now marked public.' % corpus_backup_url)


class MakePublicHandler(base_handler.Handler):
  """Makes corpuses older than 90 days public."""

  @handler.cron()
  def get(self):
    """Handle a GET request."""
    jobs = ndb_utils.get_all_from_model(data_types.Job)
    default_backup_bucket = utils.default_backup_bucket()
    for job in jobs:
      job_environment = job.get_environment()
      if utils.string_is_true(job_environment.get('EXPERIMENTAL')):
        # Don't use corpus backups from experimental jobs. Skip.
        continue

      if not utils.string_is_true(job_environment.get('CORPUS_PRUNE')):
        # There won't be any corpus backups for these jobs. Skip.
        continue

      corpus_backup_bucket_name = job_environment.get('BACKUP_BUCKET',
                                                      default_backup_bucket)
      if not corpus_backup_bucket_name:
        # No backup bucket found. Skip.
        continue

      corpus_fuzzer_name_override = job_environment.get(
          'CORPUS_FUZZER_NAME_OVERRIDE')

      target_jobs = list(fuzz_target_utils.get_fuzz_target_jobs(job=job.name))
      fuzz_targets = fuzz_target_utils.get_fuzz_targets_for_target_jobs(
          target_jobs)

      for target in fuzz_targets:
        if not target:
          # This is expected if any fuzzer/job combinations become outdated.
          continue

        try:
          _make_corpus_backup_public(target, corpus_fuzzer_name_override,
                                     corpus_backup_bucket_name)
        except:
          logs.log_error('Failed to make %s corpus backup public.' % target)
