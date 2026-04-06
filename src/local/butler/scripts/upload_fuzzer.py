# Copyright 2026 Google LLC
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
"""Script to upload a local fuzzer with a JSON config."""

import json
import os
import requests

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from libs import form
from libs import gcs


def execute(args):
  """Upload a local fuzzer."""
  if args.script_args is None or len(args.script_args) < 3:
    print('Usage: butler.py run -c configs/test --local --non-dry-run upload_fuzzer --script_args FUZZER_NAME FUZZER_ARCHIVE_PATH CONFIG_PATH')
    print('Example: butler.py run -c configs/test --local --non-dry-run upload_fuzzer --script_args test_fuzzer dummy.zip config.json')
    return

  fuzzer_name = args.script_args[0]
  fuzzer_archive_path = args.script_args[1]
  config_path = args.script_args[2]

  if not args.non_dry_run:
    print('Running in dry-run mode. Fuzzer will NOT be uploaded/created.')
    print('Re-run with --non-dry-run to actually perform the operation.')
    return

  print(f'Uploading fuzzer: {fuzzer_name}')

  # 1. Read the config file
  with open(config_path, 'r') as f:
    config_data = json.load(f)

  # 2. Check if fuzzer already exists to determine if we edit or create
  existing_fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
  is_edit = existing_fuzzer is not None

  # 3. Generate CSRF token and GCS upload info
  # Environment should be LOCAL_DEVELOPMENT, which defaults to user@localhost
  csrf_token = form.generate_csrf_token()
  upload_info = gcs.prepare_blob_upload()

  print(f'Generated CSRF Token: {csrf_token}')
  print(f'Generated Upload Key: {upload_info.key}')

  # 4. Upload the archive to local GCS
  print(f'Uploading archive {fuzzer_archive_path} to GCS...')

  # The multipart fields required by prepare_upload
  gcs_data = {
      'bucket': upload_info.bucket,
      'key': upload_info.key,
      'GoogleAccessId': upload_info.google_access_id,
      'policy': upload_info.policy,
      'signature': upload_info.signature,
      'x-goog-meta-filename': os.path.basename(fuzzer_archive_path)
  }

  with open(fuzzer_archive_path, 'rb') as f:
    files = {'file': (os.path.basename(fuzzer_archive_path), f)}
    response = requests.post(upload_info.url, data=gcs_data, files=files)

  if response.status_code not in (200, 204):
    print(f'Failed to upload archive to GCS: {response.status_code} - {response.text}')
    return

  print('Archive successfully uploaded to GCS.')

  # 5. Submit Fuzzer Configuration
  print('Submitting fuzzer configuration...')

  # Construct the final POST payload
  payload = config_data.copy()
  payload['csrf_token'] = csrf_token
  payload['upload_key'] = upload_info.key
  payload['name'] = fuzzer_name

  if is_edit:
    payload['key'] = existing_fuzzer.key.id()
    endpoint = 'http://localhost:9000/fuzzers/edit'
  else:
    endpoint = 'http://localhost:9000/fuzzers/create'

  print(f'Endpoint: {endpoint}')
  print(f'Payload: {payload}')

  # Make the request to the local server
  response = requests.post(endpoint, json=payload)

  if response.status_code == 200:
    print(f"Successfully uploaded and {'edited' if is_edit else 'created'} fuzzer '{fuzzer_name}'.")
  else:
    print(f"Failed to submit fuzzer config: {response.status_code} - {response.text}")
