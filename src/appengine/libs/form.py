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
"""form.py contains static methods around form generation."""
import base64
import datetime
import os

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from libs import helpers


def generate_csrf_token(length=64, valid_seconds=3600, html=False):
  """Generate a CSRF token."""
  now = utils.utcnow()
  valid_token = None

  # Clean up expired tokens to prevent junk from building up in the datastore.
  tokens = data_types.CSRFToken.query(
      data_types.CSRFToken.user_email == helpers.get_user_email())
  tokens_to_delete = []
  for token in tokens:
    if token.expiration_time > now:
      valid_token = token
      continue
    tokens_to_delete.append(token.key)
  ndb_utils.delete_multi(tokens_to_delete)

  # Generate a new token.
  if not valid_token:
    valid_token = data_types.CSRFToken()
    valid_token.value = base64.b64encode(os.urandom(length))
    valid_token.expiration_time = (
        now + datetime.timedelta(seconds=valid_seconds))
    valid_token.user_email = helpers.get_user_email()
    valid_token.put()

  value = valid_token.value
  if html:
    return '<input type="hidden" name="csrf_token" value="%s" />' % value
  return value
