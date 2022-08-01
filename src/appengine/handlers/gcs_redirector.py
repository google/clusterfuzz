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
"""GCS redirector."""

from flask import request

from clusterfuzz._internal.google_cloud_utils import storage
from handlers import base_handler
from libs import handler
from libs import helpers


class Handler(base_handler.Handler):
  """Gcs redirector."""

  @handler.get(handler.HTML)
  def get(self):
    """Handle a get request."""
    gcs_path = request.args.get('path', '')
    if not gcs_path:
      raise helpers.EarlyExitException('No path provided.', 400)

    if storage.get(gcs_path):
      host_url = storage.OBJECT_URL
    else:
      host_url = storage.DIRECTORY_URL

    bucket_name, object_path = storage.get_bucket_name_and_path(gcs_path)
    return self.redirect(host_url + '/' + bucket_name + '/' + object_path)
