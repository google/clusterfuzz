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
"""Cloud credential helpers."""

from google.auth import credentials

from base import retry
from system import environment

try:
  import google.auth
except ImportError:
  # Can't be imported on App Engine.
  pass

# Retry params.
FAIL_RETRIES = 5
FAIL_WAIT = 10


def _use_anonymous_credentials():
  """Returns whether or not to use anonymous credentials."""
  if (environment.get_value('INTEGRATION') or
      environment.get_value('UNTRUSTED_RUNNER_TESTS')):
    # Integration tests need real credentials.
    return False

  return (environment.get_value('LOCAL_DEVELOPMENT') or
          environment.get_value('PY_UNITTESTS'))


@retry.wrap(
    retries=FAIL_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.credentials.get_default')
def get_default(scopes=None):
  """Get default Google Cloud credentials."""
  if _use_anonymous_credentials():
    return credentials.AnonymousCredentials(), ''

  return google.auth.default(scopes=scopes)
