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
"""Cleans up orphaned FuzzerJob entities that have no corresponding Fuzzer."""

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils


def execute(args):
  """Query all FuzzerJobs and delete any mapped to a non-existent fuzzer."""
  print('Starting invalid FuzzerJob cleanup pass.')

  valid_fuzzers = {fuzzer.name for fuzzer in data_types.Fuzzer.query()}

  fuzzer_jobs = data_types.FuzzerJob.query()

  fuzzer_jobs_to_delete = []
  for mapping in fuzzer_jobs:
    # A invalid FuzzerJob has an empty fuzzer name or a fuzzer name
    # that no longer maps to an active Fuzzer entity.
    if not mapping.fuzzer or mapping.fuzzer not in valid_fuzzers:
      fuzzer_jobs_to_delete.append(mapping.key)
      print(f'Found invalid mapping to delete: ID={mapping.key.id()}, '
            f'fuzzer="{mapping.fuzzer}", job="{mapping.job}"')

  print(f'Total invalid mappings found: {len(fuzzer_jobs_to_delete)}')

  if not fuzzer_jobs_to_delete:
    print('No mappings to delete.')

  if args.non_dry_run:
    print('Executing datastore deletion...')
    ndb_utils.delete_multi(fuzzer_jobs_to_delete)
    print('Deletion complete.')
  else:
    print('Run with --non-dry-run to actually delete the mappings.')
