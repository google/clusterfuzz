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

import argparse
import json
import os
import sys

from clusterfuzz._internal.datastore import data_types


def _parse_script_args(script_args):
  """Parses the script specific arguments."""
  parser = argparse.ArgumentParser(prog='download_fuzzer_config')
  parser.add_argument(
      'fuzzer_names', nargs='+', help='Names of the fuzzers to download.')
  parser.add_argument(
      '--output-dir',
      default='.',
      help='Directory to write <fuzzer_name>_config.json files to. Created if '
      'it does not exist. Defaults to the current working directory.')
  return parser.parse_args(script_args)


def execute(args):
  """Download fuzzer config."""
  if not args.script_args:
    print('Please provide a list of fuzzer names as script arguments.')
    sys.exit(1)

  script_args = _parse_script_args(args.script_args)
  fuzzer_names = script_args.fuzzer_names
  output_dir = script_args.output_dir

  fuzzers = data_types.Fuzzer.query(
      data_types.Fuzzer.name.IN(fuzzer_names)).fetch()

  existing_fuzzer_names = {fuzzer.name for fuzzer in fuzzers}

  for fuzzer_name in fuzzer_names:
    if fuzzer_name not in existing_fuzzer_names:
      print(f'Fuzzer {fuzzer_name} not found.')

  if not args.non_dry_run:
    print('Skipping writes in dry-run mode.')
    return

  if fuzzers:
    os.makedirs(output_dir, exist_ok=True)

  for fuzzer in fuzzers:
    config = fuzzer.get_config_dict()
    filename = os.path.join(output_dir, f'{fuzzer.name}_config.json')

    with open(filename, 'w') as f:
      json.dump(config, f, indent=4)

    print(f'Saved config for {fuzzer.name} to {filename}.')
