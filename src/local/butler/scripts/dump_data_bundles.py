# Copyright 2025 Google LLC
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
"""Dumps data bundle metadata from the database in CSV format."""

import csv

from clusterfuzz._internal.datastore import data_types


def _dump(f) -> None:
  """Dumps data bundle metadata from the database to the given file."""
  writer = csv.DictWriter(
      f,
      fieldnames=[
          'name',
          'bucket_name',
          'source',
          'timestamp',
          'sync_to_worker',
      ])
  writer.writeheader()

  for bundle in data_types.DataBundle.query():
    writer.writerow({
        'name': bundle.name,
        'bucket_name': bundle.bucket_name,
        'source': bundle.source,
        'timestamp': str(bundle.timestamp),
        'sync_to_worker': bundle.sync_to_worker,
    })


def execute(args):
  """Dumps data bundle metadata from the database in CSV format."""
  if not args.script_args or len(args.script_args) != 1:
    print('Usage: dump_data_bundles --script_arg OUTPUT_FILE')
    return

  with open(args.script_args[0], 'w') as f:
    _dump(f)
