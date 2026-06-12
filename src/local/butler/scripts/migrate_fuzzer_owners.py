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
"""Script to migrate fuzzer owners."""

import argparse
import os
import sys

# Ensure the local project root is in the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
sys.path.append(os.path.join(os.path.dirname(__file__), '../src/appengine'))

from google.cloud import ndb

from clusterfuzz._internal.datastore import data_types
from libs import helpers


def migrate(dry_run=True, default_owner='default-owner@example.com'):
  """Migrates fuzzer owners."""
  query = data_types.Fuzzer.query(
      ndb.OR(
          data_types.Fuzzer.primary_owner == None,  # pylint: disable=singleton-comparison
          data_types.Fuzzer.primary_owner == ''))

  count = 0
  for fuzzer in query.fetch():
    print(f"Processing fuzzer: {fuzzer.name}")
    if not dry_run:
      fuzzer.primary_owner = default_owner
      fuzzer.put()
      helpers.log(
          f"Backfilled primary_owner for {fuzzer.name} to {default_owner}",
          helpers.MODIFY_OPERATION)
    count += 1

  mode = "DRY RUN" if dry_run else "LIVE"
  print(f"{mode}: Processed {count} fuzzers.")


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Backfill primary_owner for Fuzzers.')
  parser.add_argument(
      '--live', action='store_true', help='Perform live updates.')
  parser.add_argument(
      '--owner',
      default='default-owner@example.com',
      help='Default owner email.')
  args = parser.parse_args()

  migrate(dry_run=not args.live, default_owner=args.owner)
