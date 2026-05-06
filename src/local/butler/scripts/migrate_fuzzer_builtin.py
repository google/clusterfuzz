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
"""Migration script to index Fuzzer.builtin field."""

from clusterfuzz._internal.datastore import data_types


def execute(args):
  """Migrate Fuzzer entities to index builtin field.

  See
  https://docs.cloud.google.com/datastore/docs/concepts/indexes#unindexed_properties
  for details on how rewriting the entity is required to index properties
  that were previously unindexed.
  """
  print('Starting Fuzzer.builtin migration.')
  count = 0

  for fuzzer in data_types.Fuzzer.query():
    if not args.non_dry_run:
      print(f'DRY RUN: Would update fuzzer: {fuzzer.name}')
    else:
      # Rewrite the fuzzer to the datastore to build the index.
      fuzzer.put()
      print(f'Updated fuzzer: {fuzzer.name}')
    count += 1

  print(f'Migration complete. Updated {count} Fuzzer entities.')
