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
"""Run the backup cron task."""

import datetime

from google.cloud import ndb
from googleapiclient import discovery
from googleapiclient import errors

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.metrics import logs

# CrashStatistic is excluded because the number of records is too high and
# can be rebuilt from BigQuery dataset.
EXCLUDED_MODELS = {'CrashStatistic', 'CrashStatisticJobHistory'}


def _datastore_client():
  """Return an api client for datastore."""
  return discovery.build('datastore', 'v1')


def main():
  """Handle a cron job."""
  backup_bucket = local_config.Config(
      local_config.PROJECT_PATH).get('backup.bucket')
  if not backup_bucket:
    logs.log('No backup bucket is set, skipping.')
    return 'OK'

  kinds = [
      kind for kind in ndb.Model._kind_map  # pylint: disable=protected-access
      if (not kind.startswith('_') and kind not in EXCLUDED_MODELS)
  ]

  app_id = utils.get_application_id()
  timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
  output_url_prefix = (
      'gs://testing-{backup_bucket}/datastore-backups/{timestamp}'.format(
          backup_bucket=backup_bucket, timestamp=timestamp))

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
    status_code = 200
    logs.log(message, response=response)
  except errors.HttpError as e:
    message = 'Datastore export failed.'
    status_code = e.resp.status
    logs.log_error(message, error=str(e))

  return (message, status_code, {'Content-Type': 'text/plain'})


if __name__ == '__main__':
  main()
