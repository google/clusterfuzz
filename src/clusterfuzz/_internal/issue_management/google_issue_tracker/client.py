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

import google.oauth2.credentials
import google_auth_httplib2
import googleapiclient
import httplib2

_DISCOVERY_URL = "https://issuetracker.googleapis.com/$discovery/rest?version=v1"
_O_AUTH_SCOPE = "https://www.googleapis.com/auth/buganizer"
_REQUEST_TIMEOUT = 60
HttpError = googleapiclient.errors.HttpError
from clusterfuzz._internal.google_cloud_utils import credentials


def build_http(api='issuetracker', oauth_token=None, uberproxy_cookie=None):
    """Builds a httplib2.Http."""
    credentials = google.oauth2.credentials.get_default(scopes=[_O_AUTH_SCOPE])[0]
    return google_auth_httplib2.AuthorizedHttp(
        credentials, http=httplib2.Http(timeout=_REQUEST_TIMEOUT)
    )


def build(api="issuetracker", http=None):
    """Builds a google api client for buganizer."""
    if not http:
        http = build_http(api)
    return googleapiclient.discovery.build(
        api, 'v1', discoveryServiceUrl=_DISCOVERY_URL, http=http, cache_discovery=False
    )
