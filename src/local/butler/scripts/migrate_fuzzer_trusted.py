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
"""Migration script to set trusted=True for existing Fuzzers."""

from clusterfuzz._internal.datastore import data_types


def execute(args):
  """Migrate Fuzzer entities to set trusted=True.

  Existing fuzzers are assumed to be trusted.
  """
  print('Starting Fuzzer.trusted migration.')
  count = 0

  # We query all fuzzers. Since 'trusted' is a new field with default=False,
  # existing entities might not have it set, or it might be False.
  # We want to set it to True for all of them to maintain existing behavior.
  for fuzzer in data_types.Fuzzer.query():
    if not args.non_dry_run:
      print(f'DRY RUN: Would set trusted=True for fuzzer: {fuzzer.name}')
    else:
      fuzzer.trusted = True
      fuzzer.put()
      print(f'Updated fuzzer: {fuzzer.name} to trusted=True')
    count += 1

  print(f'Migration complete. Processed {count} Fuzzer entities.')
