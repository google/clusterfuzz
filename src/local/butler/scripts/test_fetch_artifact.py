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
"""Script for testing Android Build API (v3/v4) via fetch_artifact module."""

import argparse
import os
import re
import tempfile

from clusterfuzz._internal.platforms.android import fetch_artifact


def test_api_version():
  """Tests that the API version feature flag can be read."""
  use_v4 = fetch_artifact._use_v4()  # pylint: disable=protected-access
  api_version = 'v4' if use_v4 else 'v3'
  assert api_version in ('v3', 'v4'), f'Invalid API version: {api_version}'
  print(f'Active Android Build API version: {api_version.upper()}')
  return api_version


def test_client_initialization():
  """Tests initializing the Android Build API client."""
  try:
    client = fetch_artifact._get_client()  # pylint: disable=protected-access
    assert client is not None, (
        'Failed to initialize client. Check db_config for build apiary key.')
    print('Client initialized successfully.')
    return client
  except Exception as e:
    print(f'Error initializing client: {e}')
    raise


def test_get_latest_artifact_info(branch, target, signed, stable_build):
  """Tests retrieving build metadata for a branch and target."""
  build_info = fetch_artifact.get_latest_artifact_info(
      branch=branch, target=target, signed=signed, stable_build=stable_build)
  assert build_info is not None, f'No build info for {branch}, {target}.'
  assert 'bid' in build_info, 'Build info missing "bid".'
  assert 'target' in build_info, 'Build info missing "target".'
  print(f'Retrieved latest build: bid={build_info["bid"]}, '
        f'target={build_info["target"]}')
  print(f'Branch: {build_info.get("branch")}')
  return build_info


def test_list_artifacts(client, bid, target):
  """Tests listing build artifacts for a build ID and target."""
  # pylint: disable=protected-access
  artifacts = fetch_artifact._get_artifacts_for_build(
      client=client, bid=bid, target=target, attempt_id='latest', regexp=None)
  assert artifacts is not None, f'Failed to list artifacts: {bid}, {target}.'
  assert len(artifacts) > 0, f'No artifacts returned for {bid}, {target}.'
  print(f'Successfully listed {len(artifacts)} artifacts.')
  print('Sample artifacts:')
  for art in artifacts[:5]:
    print(f'  - {art.get("name")} ({art.get("size", "unknown")} bytes)')
  return artifacts


def test_download_artifact(bid, target, regex, output_dir):
  """Tests downloading artifacts matching a regex."""
  downloaded_files = fetch_artifact.get(
      bid=bid, target=target, regex=regex, output_directory=output_dir)
  assert downloaded_files is not None, f'Download failed for regex={regex}.'
  assert len(downloaded_files) > 0, f'No files downloaded for regex={regex}.'
  print(f'Successfully downloaded {len(downloaded_files)} file(s):')
  for filepath in downloaded_files:
    assert os.path.exists(filepath), f'File not found: {filepath}'
    size = os.path.getsize(filepath)
    assert size > 0, f'Downloaded file is empty: {filepath}'
    print(f'  - {filepath} ({size} bytes)')
  return downloaded_files


def _select_smallest_artifact(artifacts):
  """Helper to select the smallest non-empty artifact for download testing."""
  valid_artifacts = [
      a for a in artifacts if not a.get('name', '').endswith('.SIGN_INFO') and
      int(a.get('size', 0)) > 0
  ]
  assert valid_artifacts, 'No valid non-empty artifacts found for testing.'
  valid_artifacts.sort(key=lambda x: int(x.get('size', 0)))
  return valid_artifacts[0]


def execute(args):
  """Executes the Android Build API test suite."""
  parser = argparse.ArgumentParser(
      description='Test Android Build API via fetch_artifact module.')
  parser.add_argument(
      '--branch',
      default='git_main',
      help='Android build branch to query (default: git_main).')
  parser.add_argument(
      '--target',
      default='cf_x86_64_phone-next-userdebug',
      help='Android build target (default: cf_x86_64_phone-next-userdebug).')
  parser.add_argument(
      '--build-id',
      default=None,
      help='Specific build ID (if omitted, queries latest build info).')
  parser.add_argument(
      '--regex',
      default=None,
      help='Regex of artifact to download (default: smallest file).')
  parser.add_argument(
      '--output-dir',
      default=None,
      help='Directory for download (if omitted, uses a temp dir).')
  parser.add_argument(
      '--signed',
      action='store_true',
      help='Query signed builds in get_latest_artifact_info.')
  parser.add_argument(
      '--stable-build',
      action='store_true',
      help='Use stable cuttlefish build info.')
  parser.add_argument(
      '--use-v3',
      action='store_true',
      help='Force using Android Build API V3 (overrides db_config).')

  script_args = parser.parse_args(args.script_args or [])

  if script_args.use_v3:
    fetch_artifact._use_v4 = lambda: False  # pylint: disable=protected-access
  else:
    fetch_artifact._use_v4 = lambda: True  # pylint: disable=protected-access

  print('=== Android Build API Test Suite ===\n')

  print('[Test 1] Checking API version...')
  test_api_version()

  print('\n[Test 2] Initializing build apiary client...')
  client = test_client_initialization()

  branch = script_args.branch
  target = script_args.target
  build_id = script_args.build_id

  if not build_id:
    print(f'\n[Test 3] Querying latest info: branch={branch}, target={target}')
    build_info = test_get_latest_artifact_info(
        branch=branch,
        target=target,
        signed=script_args.signed,
        stable_build=script_args.stable_build)
    build_id = build_info['bid']
    target = build_info['target']
  else:
    print(f'\n[Test 3] Using provided build_id={build_id} (skipping query)')

  print(f'\n[Test 4] Listing artifacts for bid={build_id}, target={target}...')
  artifacts = test_list_artifacts(client, build_id, target)

  regex = script_args.regex
  if not regex:
    target_artifact = _select_smallest_artifact(artifacts)
    regex = f"^{re.escape(target_artifact['name'])}$"
    print('\n[Test 5] No --regex specified. Selected smallest artifact:')
    print(f'  {target_artifact["name"]} ({target_artifact["size"]} bytes)')
  else:
    print(f'\n[Test 5] Testing artifact download with regex={regex}...')

  temp_dir = None
  output_dir = script_args.output_dir
  if not output_dir:
    temp_dir = tempfile.TemporaryDirectory()
    output_dir = temp_dir.name
    print(f'Using temporary directory for download: {output_dir}')
  else:
    os.makedirs(output_dir, exist_ok=True)
    print(f'Using output directory: {output_dir}')

  try:
    test_download_artifact(
        bid=build_id, target=target, regex=regex, output_dir=output_dir)
    print('\n=== All Android Build API tests passed successfully! ===')
  finally:
    if temp_dir:
      temp_dir.cleanup()
