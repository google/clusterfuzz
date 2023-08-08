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

from google.auth import compute_engine
from google.auth import credentials
from google.auth.transport import requests
from google.oauth2 import service_account

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.system import environment

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
      environment.get_value('UNTRUSTED_RUNNER_TESTS') or
      environment.get_value('UTASK_TESTS')):
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


@retry.wrap(
    retries=FAIL_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.credentials.get_signing_credentials')
def get_signing_credentials():
  """Returns signing credentials for signing URLs."""
  if _use_anonymous_credentials():
    return None

  google_application_credentials = os.getenv(
    'GOOGLE_APPLICATION_CREDENTIALS', None)
  if google_application_credentials is None:
    # The normal case, when we are on GCE.
    creds, _ = get_default()
    request = requests.Request()
    creds.refresh(request)
    signing_creds = compute_engine.IDTokenCredentials(
      request, '', service_account_email=creds.service_account_email)
  else:
    # Handle cases like android and Mac where bots are run outside of Google
    # Cloud Platform and don't have access to metadata server.
    signing_creds = service_account.Credentials.from_service_account_file(
      google_application_credentials)
  return signing_creds
