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
"""Get a Google Issue Tracker HTTP client."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import urllib

import google.oauth2.credentials
import google_auth_httplib2
import googleapiclient
import httplib2

_ROLE_ACCOUNT = "cluster-fuzz-google-issue-tracker"
_DISCOVERY_URL = "https://issuetracker.googleapis.com/$discovery/rest?version=v1"
_ISSUE_TRACKER_URL = "https://issuetracker.corp.googleapis.com"
_UBERPROXY_SERVICE = "up.corp.googleapis.com/"
_O_AUTH_SCOPE = "https://www.googleapis.com/auth/buganizer"
_REQUEST_TIMEOUT = 60
HttpError = googleapiclient.errors.HttpError
from clusterfuzz._internal.google_cloud_utils import credentials


def user():
  return _ROLE_ACCOUNT + "@google.com"


def _request_urllib_for_testing(url, body, method, headers):
  """Make the request with urllib2 for testing purposes."""
  # For testing locally with ssolib.
  from urllib import request

  # Don't accept gzip.
  if "accept-encoding" in headers:
    del headers["accept-encoding"]
  # Pass request to urllib (best effort), which had an opener installed by
  # ssolib.
  req = request.Request(url, data=body, headers=headers)
  req.get_method = lambda: method
  try:
    response = request.urlopen(req)
    content = response.read()
    info = {
        "status": response.getcode(),
        "reason": "OK",
    }
    info.update(response.info().items())
    return httplib2.Response(info), content
  except Exception as e:
    return (
        httplib2.Response({
            "status": e.code,
            "reason": e.reason,
        }),
        e.read(),
    )


class _UberProxyHttp(httplib2.Http):
  """httplib2.Http which attaches UberProxy cookies."""

  def __init__(self, cookie, *args, **kwargs):
    self.cookie = cookie
    super(_UberProxyHttp, self).__init__(*args, **kwargs)

  def request(
      self,
      url,
      method="GET",
      body=None,
      headers=None,
      redirections=httplib2.DEFAULT_MAX_REDIRECTS,
      connection_type=None,
  ):
    """Make a request."""
    if headers is None:
      headers = {}
    if self.cookie:
      headers["Cookie"] = self.cookie
    if os.getenv("USE_URLLIB"):
      return _request_urllib_for_testing(url, body, method, headers)
    return super(_UberProxyHttp, self).request(
        url,
        method=method,
        body=body,
        headers=headers,
        redirections=redirections,
        connection_type=connection_type,
    )


def build_http(api="issuetracker", oauth_token=None, uberproxy_cookie=None):
  """Build a httplib2.Http."""
  # if uberproxy_cookie is None:
  #     uberproxy_client = corplogin_client_jwt.AppEngineCorpLoginClient(
  #         _ROLE_ACCOUNT, _UBERPROXY_SERVICE
  #     )
  #     uberproxy_cookie = uberproxy_client.GetUberProxyCookie(
  #         _ISSUE_TRACKER_URL.format(api=api)
  #     )
  # if oauth_token is None:
  #     oauth_client = corplogin_client_jwt.OAuthClientForGoogle(user(), _O_AUTH_SCOPE)
  #     oauth_token = oauth_client.GetToken()
  # credentials = google.oauth2.credentials.Credentials(oauth_token)
  # return google_auth_httplib2.AuthorizedHttp(
  #     credentials,
  #     http=_UberProxyHttp(cookie=uberproxy_cookie, timeout=_REQUEST_TIMEOUT),
  # )

  credentials = google.oauth2.credentials.get_default(scopes=[_O_AUTH_SCOPE])[0]
  return google_auth_httplib2.AuthorizedHttp(
      credentials, http=httplib2.Http(timeout=_REQUEST_TIMEOUT))


def build(api="issuetracker", http=None):
  """Build a google api client for buganizer."""
  if not http:
    http = build_http(api)
  return googleapiclient.discovery.build(
      api,
      "v1",
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http,
      cache_discovery=False)
