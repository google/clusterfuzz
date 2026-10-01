#!/usr/bin/env python3
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
"""Fake blackbox fuzzer for integration tests. It does not fuzz.

Follows the ClusterFuzz blackbox fuzzer contract:
  run.py --input_dir=<dir> --output_dir=<dir> --no_of_files=<n>

Writes <n> Python testcases named `fuzz-<i>.py` to the output directory, meant
to be executed with `APP_NAME = python3`. The first `failing_cases` testcases
raise an uncaught exception (non-zero exit code), so ClusterFuzz records a
crash; the rest exit cleanly. All those crashes share the same crash state, so
ClusterFuzz groups them into a single testcase.

With `unique_crashes`, each of those `failing_cases` testcases gets a unique
crash state instead (top frame `crash_case_<i>`), so ClusterFuzz records
`failing_cases` unique crashes. It has no effect without `failing_cases`.

Since ClusterFuzz only passes the three contract flags, each option can also be
set through the environment (e.g. the job environment string):
  --failing_cases=<k>   or  FAILING_CASES = <k>
  --unique_crashes      or  UNIQUE_CRASHES = True
The command line takes precedence over the environment.
"""

import argparse
import os
import sys

TESTCASE_PREFIX = 'fuzz-'
TESTCASE_EXTENSION = '.py'
FAILING_CASES_ENV_VAR = 'FAILING_CASES'
UNIQUE_CRASHES_ENV_VAR = 'UNIQUE_CRASHES'

FAILING_TESTCASE_TEMPLATE = '''\
import sys

# Testcase {index}: failing case.
sys.stderr.write('=== Uncaught Python exception: ===\\n')
sys.stderr.flush()
raise RuntimeError('Simulated crash in testcase {index}')
'''

UNIQUE_FAILING_TESTCASE_TEMPLATE = '''\
import sys


def crash_case_{index}():
  raise RuntimeError('Simulated crash in testcase {index}')


# Testcase {index}: failing case with a unique crash state.
sys.stderr.write('=== Uncaught Python exception: ===\\n')
sys.stderr.flush()
crash_case_{index}()
'''

SUCCESSFULL_TESTCASE_TEMPLATE = '''\
import sys

# Testcase {index}: passing case.
sys.exit(0)
'''


def _parse_args(argv):
  """Parses command line arguments."""
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--input_dir', default='')
  parser.add_argument('--output_dir', required=True)
  parser.add_argument('--no_of_files', type=int, required=True)
  parser.add_argument('--failing_cases', type=int, default=None)
  parser.add_argument('--unique_crashes', action='store_true')
  return parser.parse_args(argv)


def get_failing_cases(cli_value):
  """Returns the number of failing cases from the CLI or the environment."""
  if cli_value is not None:
    return cli_value
  return int(os.environ.get(FAILING_CASES_ENV_VAR, 0))


def get_unique_crashes(cli_value):
  """Returns whether unique crashes are enabled by the CLI or environment."""
  return cli_value or os.environ.get(UNIQUE_CRASHES_ENV_VAR) == 'True'


def _get_template(index, failing_cases, unique_crashes):
  """Returns the testcase template for testcase |index|."""
  if index >= failing_cases:
    return SUCCESSFULL_TESTCASE_TEMPLATE
  if unique_crashes:
    return UNIQUE_FAILING_TESTCASE_TEMPLATE
  return FAILING_TESTCASE_TEMPLATE


def generate_testcases(output_dir,
                       no_of_files,
                       failing_cases,
                       unique_crashes=False):
  """Writes testcases to |output_dir|. Returns the list of written paths."""
  os.makedirs(output_dir, exist_ok=True)
  failing_cases = max(0, min(failing_cases, no_of_files))

  paths = []
  for index in range(no_of_files):
    template = _get_template(index, failing_cases, unique_crashes)
    path = os.path.join(output_dir,
                        f'{TESTCASE_PREFIX}{index}{TESTCASE_EXTENSION}')
    with open(path, 'w') as f:
      f.write(template.format(index=index))
    os.chmod(path, 0o755)
    paths.append(path)

  return paths


def main(argv=None):
  args = _parse_args(argv)
  failing_cases = get_failing_cases(args.failing_cases)
  unique_crashes = get_unique_crashes(args.unique_crashes)
  paths = generate_testcases(args.output_dir, args.no_of_files, failing_cases,
                             unique_crashes)
  failing = min(failing_cases, args.no_of_files)
  if failing < 0:
    raise ValueError(
        f'Number of failing testcases must be >= 0, got {failing_cases}')
  mode = ', unique crash states' if unique_crashes and failing else ''
  print(f'Generated {len(paths)}/{args.no_of_files} testcases '
        f'({failing} failing, {len(paths) - failing} successfull{mode}).')
  return 0


if __name__ == '__main__':
  sys.exit(main())
