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

from clusterfuzz._internal.base import retry

_ROLE_ACCOUNT = "cluster-fuzz@appspot.gserviceaccount.com"

_DISCOVERY_URL = ('https://issuetracker.googleapis.com/$discovery/rest?'
                  'version=v1&labels=GOOGLE_PUBLIC')
_SCOPE = 'https://www.googleapis.com/auth/buganizer'
_REQUEST_TIMEOUT = 60

HttpError = errors.HttpError
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


@retry.wrap(
    retries=2,
    delay=2,
    exception_types=[UnknownApiNameOrVersion],
    function='issue_issue_management.google_issue_tracker,client.'
    '_call_discovery')
def _call_discovery(api, http):
  """Calls the discovery service.

  Retries upto twice if there are any UnknownApiNameOrVersion errors.
  """
  return discovery.build(
      api,
      'v1',
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http,
      static_discovery=False)


def build(api='issuetracker', http=None):
  """Builds a google api client for buganizer."""
  if not http:
    http = build_http()
  return _call_discovery(api, http)
