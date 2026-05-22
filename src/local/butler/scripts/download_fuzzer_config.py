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
"""Download fuzzer config as a JSON file."""

import json
import sys

from clusterfuzz._internal.datastore import data_types


def execute(args):
  """Download fuzzer config."""
  if not args.script_args:
    print('Please provide a list of fuzzer names as script arguments.')
    sys.exit(1)

  fuzzers = data_types.Fuzzer.query(
      data_types.Fuzzer.name.IN(args.script_args)).fetch()

  existing_fuzzer_names = {fuzzer.name for fuzzer in fuzzers}

  for fuzzer_name in args.script_args:
    if fuzzer_name not in existing_fuzzer_names:
      print(f'Fuzzer {fuzzer_name} not found.')

  if not args.non_dry_run:
    print('Skipping writes in dry-run mode.')
    return

  for fuzzer in fuzzers:
    config = fuzzer.get_config_dict()
    filename = f'{fuzzer.name}_config.json'

    with open(filename, 'w') as f:
      json.dump(config, f, indent=4)

    print(f'Saved config for {fuzzer.name} to {filename}.')
