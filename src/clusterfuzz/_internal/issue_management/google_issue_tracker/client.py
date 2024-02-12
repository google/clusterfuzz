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
"""Gets a Google Issue Tracker HTTP client."""

import google.auth
import google_auth_httplib2
from googleapiclient import discovery
from googleapiclient import errors
import httplib2

from clusterfuzz._internal.metrics import logs

_ROLE_ACCOUNT = "cluster-fuzz@appspot.gserviceaccount.com"

_DISCOVERY_URL = ('https://issuetracker.googleapis.com/$discovery/rest?'
                  'version=v1&labels=GOOGLE_PUBLIC')
_SCOPE = 'https://www.googleapis.com/auth/buganizer'
_REQUEST_TIMEOUT = 60

UnknownApiNameOrVersion = errors.UnknownApiNameOrVersion


def user():
  return _ROLE_ACCOUNT


def build_http():
  """Builds a httplib2.Http."""
  creds, _ = google.auth.default()
  if creds.requires_scopes:
    creds = creds.with_scopes([_SCOPE])
  return google_auth_httplib2.AuthorizedHttp(
      creds, http=httplib2.Http(timeout=_REQUEST_TIMEOUT))


def _call_discovery(api, http):
  return discovery.build(
      api,
      'v1',
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http,
      cache_discovery=False)


def build(api='issuetracker', http=None):
  """Builds a google api client for buganizer.

  Retries once if there are any UnknownApiNameOrVersion errors.
  """
  if not http:
    http = build_http()
  try:
    return _call_discovery(api, http)
  except UnknownApiNameOrVersion as err:
    logs.log_warn(f'google_issue_tracker: Error when calling discovery: {err}.'
                  ' Going to retry...')
    return _call_discovery(api, http)
