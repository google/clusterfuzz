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
"""Credentials management."""

from oauth2client.client import Credentials
from oauth2client.client import Storage

from clusterfuzz._internal.config import db_config


class CredentialStorage(Storage):
  """Instead of reading a file, just parse a config entry."""

  def locked_get(self):
    """Return Credentials."""
    content = db_config.get_value('client_credentials')
    if not content:
      return None

    try:
      credentials = Credentials.new_from_json(content)
      credentials.set_store(self)
    except ValueError:
      return None

    return credentials

  def locked_put(self, credentials):  # pylint: disable=unused-argument
    pass

  def locked_delete(self):
    pass
