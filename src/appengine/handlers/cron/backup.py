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
"""Handler that triggers the backup URL. We need this handler because
  https://cloud.google.com/appengine/articles/scheduled_backups doesn't support
  backing up all entities. Therefore, we have to get all entities here and
  send them to the backup URL."""

import datetime

from google.cloud import ndb
import googleapiclient

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.metrics import logs
from handlers import base_handler
from libs import handler

# CrashStatistic is excluded because the number of records is too high and
# can be rebuilt from BigQuery dataset.
EXCLUDED_MODELS = {'CrashStatistic', 'CrashStatisticJobHistory'}


def _datastore_client():
  """Return an api client for datastore."""
  return googleapiclient.discovery.build('datastore', 'v1')


class Handler(base_handler.Handler):
  """Handler for triggering the backup URL."""

  @handler.cron()
  def get(self):
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
        'gs://{backup_bucket}/datastore-backups/{timestamp}'.format(
            backup_bucket=backup_bucket, timestamp=timestamp))
    body = {
        'output_url_prefix': output_url_prefix,
        'entity_filter': {
            'kinds': kinds
        }
    }

    try:
      request = _datastore_client().projects().export(
          projectId=app_id, body=body)
      response = request.execute()

      message = 'Datastore export succeeded.'
      status_code = 200
      logs.log(message, response=response)
    except googleapiclient.errors.HttpError as e:
      message = 'Datastore export failed.'
      status_code = e.resp.status
      logs.log_error(message, error=str(e))

    return (message, status_code, {'Content-Type': 'text/plain'})
