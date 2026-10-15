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
"""Download fuzzer config, archive, and associated job configs."""

import argparse
import os
import sys

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from local.butler.scripts import download_fuzzer_config
from local.butler.scripts import download_job_config


def _parse_script_args(script_args):
  """Parses the script specific arguments."""
  parser = argparse.ArgumentParser(prog='download_fuzzer_bundle')
  parser.add_argument(
      'fuzzer_names', nargs='+', help='Names of the fuzzers to download.')
  parser.add_argument(
      '--output-dir',
      default='.',
      help='Base directory to write <fuzzer_name>/ bundles to.')
  parser.add_argument(
      '--jobs',
      nargs='*',
      default=None,
      help='Optional subset of job names to download. Defaults to all jobs '
      'listed on the fuzzer.')
  parser.add_argument(
      '--skip-archive',
      action='store_true',
      help='Skip downloading the fuzzer archive from GCS blobstore.')
  return parser.parse_args(script_args)


def download_fuzzer_archive(
    fuzzer: data_types.Fuzzer,
    fuzzer_dir: str,
    non_dry_run: bool = True,
) -> None:
  """Downloads the GCS blobstore archive for a fuzzer to fuzzer_dir."""
  if not non_dry_run:
    print(f'Skipping archive download for {fuzzer.name} in dry-run mode.')
    return

  if not fuzzer.blobstore_key:
    print(f'Fuzzer {fuzzer.name} has no blobstore_key.')
    return

  os.makedirs(fuzzer_dir, exist_ok=True)
  ext = os.path.splitext(fuzzer.filename or '.zip')[1] or '.zip'
  archive_path = os.path.join(fuzzer_dir, f'{fuzzer.name}{ext}')
  if blobs.read_blob_to_disk(fuzzer.blobstore_key, archive_path):
    print(f'Saved archive for {fuzzer.name} to {archive_path}.')
  else:
    print(f'Failed to download archive for {fuzzer.name}.')


def execute(args):
  """Download each fuzzer's config, archive, and job configs into its own subdir."""
  if not args.script_args:
    print('Please provide a list of fuzzer names as script arguments.')
    sys.exit(1)

  script_args = _parse_script_args(script_args=args.script_args)
  for fuzzer_name in script_args.fuzzer_names:
    fuzzer_dir = os.path.join(script_args.output_dir, fuzzer_name)
    fuzzers = download_fuzzer_config.download_fuzzer_configs(
        fuzzer_names=[fuzzer_name],
        output_dir=fuzzer_dir,
        non_dry_run=args.non_dry_run,
    )
    if not fuzzers:
      continue

    # download_fuzzer_configs takes multiple fuzzers, but we only pass in one.
    fuzzer = fuzzers[0]
    if not script_args.skip_archive:
      download_fuzzer_archive(
          fuzzer=fuzzer,
          fuzzer_dir=fuzzer_dir,
          non_dry_run=args.non_dry_run,
      )

    if script_args.jobs is not None:
      job_names = [j for j in script_args.jobs if j in (fuzzer.jobs or [])]
    else:
      job_names = list(fuzzer.jobs or [])

    if job_names:
      jobs_dir = os.path.join(fuzzer_dir, 'jobs')
      download_job_config.download_job_configs(
          job_names=job_names,
          output_dir=jobs_dir,
          non_dry_run=args.non_dry_run,
      )
