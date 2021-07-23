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
"""Fake objects used in reproduce tool tests."""

from local.butler import reproduce
from local.butler.reproduce_tool import http_utils


class FakeResponse(object):
  """Fake response object."""

  def __init__(self, status, include_auth_header=False, filename=None):
    self.status = status
    self.include_auth_header = include_auth_header
    self.filename = filename

  def __contains__(self, item):
    if item == http_utils.AUTHORIZATION_HEADER and self.include_auth_header:
      return True
    if item == reproduce.FILENAME_RESPONSE_HEADER and self.filename:
      return True

    return False

  def __getitem__(self, item):
    if item == http_utils.AUTHORIZATION_HEADER and self.include_auth_header:
      return 'fake auth token'
    if item == reproduce.FILENAME_RESPONSE_HEADER and self.filename:
      return self.filename

    return None


class FakeHttp(object):
  """Fake HTTP object. Stores information on the last request."""

  def __init__(self, replies):
    self.replies = replies
    self.last_url = None
    self.last_method = None
    self.last_headers = None
    self.last_body = None

  def request(self, url, method, headers, body):
    """Return a predetermined response and content."""
    self.last_url = url
    self.last_method = method
    self.last_headers = headers
    self.last_body = body

    return self.replies.pop(0)


class FakeConfig(object):
  """Fake configuration object."""

  def get(self, key):
    """Fake get."""
    if key == 'oauth_url':
      return 'https://oauth-url/'
    if key == 'testcase_download_url':
      return 'https://clusterfuzz/testcase-detail/download-testcase'

    raise Exception('Unexpected config key access: ' + key)
