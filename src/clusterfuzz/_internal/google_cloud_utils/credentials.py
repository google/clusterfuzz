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
import os

from google.auth import compute_engine
from google.auth import credentials
from google.auth.transport import requests
from google.oauth2 import service_account

from clusterfuzz._internal.base import retry
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.google_cloud_utils import secret_manager
from clusterfuzz._internal.system import environment

try:
  import google.auth
except ImportError:
  # Can't be imported on App Engine.
  pass

# Retry params.
FAIL_RETRIES = 5
FAIL_WAIT = 10

_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/prodxmon'
]

_SIGNING_KEY_SECRET_ID = 'gcs-signer-key'


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


def _set_gcs_signing_service_account():
  project_id = utils.get_application_id()
  service_account_key = secret_manager.get(_SIGNING_KEY_SECRET_ID, project_id)
  service_account_key_path = os.path.join(
      environment.get_value('ROOT_DIR'), 'bot', 'gcs_key')
  with open(service_account_key_path, 'w') as fp:
    fp.write(service_account_key)
  return service_account_key_path


@retry.wrap(
    retries=FAIL_RETRIES,
    delay=FAIL_WAIT,
    function='google_cloud_utils.credentials.get_signing_service_account')
def get_storage_signing_service_account():
  """Gets a dedicated signing account for signing storage objects."""
  if _use_anonymous_credentials():
    return None
  google_application_credentials = os.getenv('GOOGLE_APPLICATION_CREDENTIALS',
                                             None)
  if google_application_credentials:
    return google_application_credentials

  return _set_gcs_signing_service_account()


def get_signing_credentials(service_account_path):
  """Returns signing credentials for signing URLs."""
  if _use_anonymous_credentials():
    return None

  if service_account_path is not None:
    # Handle cases like android and Mac where bots are run outside of Google
    # Cloud Platform and don't have access to metadata server.
    signing_creds = service_account.Credentials.from_service_account_file(
        service_account, scopes=_SCOPES)
    request = requests.Request()
    signing_creds.refresh(request)
    token = signing_creds.token
  else:
    # The normal case, when we are on GCE.
    creds, _ = get_default()

    request = requests.Request()
    creds.refresh(request)

    signing_creds = compute_engine.IDTokenCredentials(
        request, '', service_account_email=creds.service_account_email)
    token = creds.token
  return signing_creds, token
