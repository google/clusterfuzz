# Copyright 2023 Google LLC
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
"""Task that triggers the backup URL. We need this task because
  https://cloud.google.com/appengine/articles/scheduled_backups doesn't support
  backing up all entities. Therefore, we have to get all entities here and
  send them to the backup URL."""

import datetime

from google.cloud import ndb
from googleapiclient import discovery
from googleapiclient import errors

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
# pylint: disable=unused-import
# This is required to populate the ndb _kind_map.
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.metrics import logs

# CrashStatistic is excluded because the number of records is too high and
# can be rebuilt from BigQuery dataset.
EXCLUDED_MODELS = {'CrashStatistic', 'CrashStatisticJobHistory'}


def _datastore_client():
  """Returns an api client for datastore."""
  return discovery.build('datastore', 'v1')


def main():
  """Backups all entities in a datastore bucket."""
  backup_bucket = local_config.Config(
      local_config.PROJECT_PATH).get('backup.bucket')
  if not backup_bucket:
    logs.log_error('No backup bucket is set, skipping.')
    return False

  kinds = [
      kind for kind in ndb.Model._kind_map  # pylint: disable=protected-access
      if (not kind.startswith('_') and kind not in EXCLUDED_MODELS)
  ]

  app_id = utils.get_application_id()
  timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
  output_url_prefix = (
      f'gs://testing-{backup_bucket}/datastore-backups/{timestamp}')

  body = {
      'output_url_prefix': output_url_prefix,
      'entity_filter': {
          'kinds': kinds
      }
  }

  try:
    request = _datastore_client().projects().export(projectId=app_id, body=body)
    response = request.execute()
    message = 'Datastore export succeeded.'
    logs.log(message, response=response)
    return True
  except errors.HttpError as e:
    status_code = e.resp.status
    message = f'Datastore export failed. Status code: {status_code}'
    logs.log_error(message)
    return False
