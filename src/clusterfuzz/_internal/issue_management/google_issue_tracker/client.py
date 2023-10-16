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
import google_auth_httplib2
import googleapiclient
import httplib2

_ROLE_ACCOUNT = "cluster-fuzz-google-issue-tracker"
_DISCOVERY_URL = 'https://issuetracker.googleapis.com/',\
  '$discovery/rest?version=v1'
_O_AUTH_SCOPE = 'https://www.googleapis.com/auth/buganizer'
_REQUEST_TIMEOUT = 60
HttpError = googleapiclient.errors.HttpError


def user():
  return _ROLE_ACCOUNT + '@google.com'


def build_http():
  """Builds a httplib2.Http."""
  # TODO(rmistry): Add real implementation
  creds = None
  return google_auth_httplib2.AuthorizedHttp(
      creds, http=httplib2.Http(timeout=_REQUEST_TIMEOUT))


def build(api='issuetracker', http=None):
  """Builds a google api client for buganizer."""
  if not http:
    http = build_http()
  return googleapiclient.discovery.build(
      api,
      'v1',
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http,
      cache_discovery=False)
