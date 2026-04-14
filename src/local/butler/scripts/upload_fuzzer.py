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
"""Script to upload a fuzzer with a JSON config."""

import argparse
import json
import os

import requests

from appengine.libs import form
from appengine.libs import gcs
from clusterfuzz._internal.datastore import data_types

_FUZZERS_ENDPOINT = 'http://localhost:9000/fuzzers'


def _upload_fuzzer_archive(upload_info: gcs.GcsUpload,
                           fuzzer_archive_path: str) -> requests.Response:
  """Uploads a fuzzer archive to GCS."""
  print(f'Uploading archive {fuzzer_archive_path} to GCS...')

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
    return requests.post(
        upload_info.url, data=gcs_data, files=files, timeout=60)


def _submit_fuzzer(payload: dict, existing_fuzzer: data_types.Fuzzer | None
                  ) -> requests.Response:
  """Submits a fuzzer via the fuzzers/edit or fuzzers/create endpoint."""
  print('Submitting fuzzer configuration...')

  if existing_fuzzer:
    payload['key'] = existing_fuzzer.key.id()
    endpoint = _FUZZERS_ENDPOINT + '/edit'
  else:
    endpoint = _FUZZERS_ENDPOINT + '/create'

  return requests.post(endpoint, json=payload, timeout=60)


def execute(args):
  """Upload a fuzzer with a JSON config."""
  parser = argparse.ArgumentParser(prog='upload_fuzzer')
  parser.add_argument('--fuzzer-name', required=True, help='Name of the fuzzer')
  parser.add_argument(
      '--fuzzer-archive-path', required=True, help='Path to the fuzzer archive')
  parser.add_argument(
      '--config-path',
      required=True,
      help='Path to the fuzzer JSON config. The config should contain the jobs,'
      ' corpus, and other optional fuzzer arguments.')

  script_args = parser.parse_args(args.script_args or [])

  fuzzer_name = script_args.fuzzer_name
  fuzzer_archive_path = script_args.fuzzer_archive_path
  config_path = script_args.config_path

  with open(config_path, 'r') as f:
    config_data = json.load(f)

  csrf_token = form.generate_csrf_token()
  upload_info = gcs.prepare_blob_upload()

  payload = config_data.copy()
  payload['csrf_token'] = csrf_token
  payload['upload_key'] = upload_info.key
  payload['name'] = fuzzer_name

  print(f'Uploading fuzzer: {fuzzer_name} with payload {payload}')

  if not args.non_dry_run:
    print('Running in dry-run mode. Fuzzer will NOT be uploaded/created.')
    print('Re-run with --non-dry-run to actually perform the operation.')
    return

  upload_response = _upload_fuzzer_archive(upload_info, fuzzer_archive_path)

  if upload_response.status_code not in (200, 204):
    print(f'Failed to upload archive to GCS: {upload_response.status_code}\n'
          f'Response: {upload_response.text}')
    return

  print('Archive successfully uploaded to GCS.')

  # Check if the fuzzer already exists to determine whether to edit or create.
  existing_fuzzer = data_types.Fuzzer.query(
      data_types.Fuzzer.name == fuzzer_name).get()

  fuzzer_response = _submit_fuzzer(
      payload=payload, existing_fuzzer=existing_fuzzer)

  if fuzzer_response.status_code == 200:
    print(f"Successfully {'edited' if existing_fuzzer else 'created'} fuzzer "
          f"'{fuzzer_name}'.")
  else:
    print(f"Failed to submit fuzzer config: {fuzzer_response.status_code}\n"
          f"Response: {fuzzer_response.text}")
