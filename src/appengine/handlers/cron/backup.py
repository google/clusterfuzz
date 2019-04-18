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
import json

from google.appengine.api import app_identity
from google.appengine.api import urlfetch
from google.appengine.ext.db import metadata

from base import utils
from config import local_config
from handlers import base_handler
from libs import handler
from metrics import logs

# CrashStatistic is excluded because the number of records is too high and
# can be rebuilt from BigQuery dataset.
EXCLUDED_MODELS = {'CrashStatistic', 'CrashStatisticJobHistory'}


class Handler(base_handler.Handler):
  """Handler for triggering the backup URL."""

  @handler.check_cron()
  def get(self):
    """Handle a cron job."""
    gs_bucket_name = local_config.Config(
        local_config.PROJECT_PATH).get('backup.bucket')
    if not gs_bucket_name:
      logs.log('No backup bucket is set, skipping.')
      return

    kinds = [
        kind.kind_name
        for kind in metadata.Kind.all()
        if (not kind.kind_name.startswith('_') and
            kind.kind_name not in EXCLUDED_MODELS)
    ]

    app_id = utils.get_application_id()
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H:%M:%S')
    output_url_prefix = 'gs://%s/%s' % (gs_bucket_name, timestamp)
    token, _ = app_identity.get_access_token(
        'https://www.googleapis.com/auth/datastore')
    request = {
        'project_id': app_id,
        'output_url_prefix': output_url_prefix,
        'entity_filter': {
            'kinds': kinds
        }
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    }

    try:
      result = urlfetch.fetch(
          url='https://datastore.googleapis.com/v1/projects/%s:export' % app_id,
          payload=json.dumps(request),
          method=urlfetch.POST,
          deadline=60,
          headers=headers)
      message = result.content
      status_code = result.status_code
    except urlfetch.Error:
      message = 'Failed to initiate datastore export.'
      status_code = 500

    log_func = logs.log if status_code == 200 else logs.log_error
    log_func(message)

    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write(message)
    self.response.set_status(status_code)
