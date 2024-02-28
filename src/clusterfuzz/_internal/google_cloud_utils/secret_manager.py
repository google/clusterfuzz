# Copyright 2024 Google LLC
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
"""Code for Google Cloud's Secret Manager."""
from google.cloud import secretmanager


def get_secret_manager_client():
  """Returns the secretmanager client."""
  return secretmanager.SecretManagerServiceClient()


def get(secret_id, project):
  """Returns the value of the secret identified by |secret_id| in
    |project|."""
  client = get_secret_manager_client()
  name = f'projects/{project}/secrets/{secret_id}/versions/1'
  response = client.access_secret_version(request={'name': name})
  return response.payload.data
