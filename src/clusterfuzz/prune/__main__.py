# Copyright 2021 Google LLC
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
"""Prune module."""

import argparse
import os
import shlex

import clusterfuzz.fuzz


def main():
  os.environ['CF_INTERACTIVE'] = 'True'
  os.environ['PROJECT_NAME'] = 'libClusterFuzz'

  parser = argparse.ArgumentParser(description='Fuzzing tool')
  parser.add_argument('-t', '--target', help='Path to target.', required=True)
  parser.add_argument(
      '-e',
      '--engine',
      help='Fuzzing engine.',
      choices=clusterfuzz.fuzz.ENGINES,
      default='libFuzzer')
  parser.add_argument(
      '-s',
      '--sanitizer',
      help='Sanitizer.',
      choices=['address', 'memory', 'undefined'],
      default='address')
  parser.add_argument(
      '-i',
      '--input',
      action='append',
      help='Path to input corpus.',
      required=True)
  parser.add_argument(
      '-o',
      '--output',
      help='Path to output (pruned) corpus.',
      required=True)
  parser.add_argument(
      '-c',
      '--crashers',
      help='Path to crashers found during pruning.',
      default=os.getcwd())
  parser.add_argument(
      '-d', '--max-duration', help='Max time in seconds to run.', type=int)
  args = parser.parse_args()

  # TODO(ochang): Find a cleaner way to propagate this.
  if args.sanitizer == 'address':
    os.environ['JOB_NAME'] = 'libfuzzer_asan'
  elif args.sanitizer == 'memory':
    os.environ['JOB_NAME'] = 'libfuzzer_msan'
  elif args.sanitizer == 'undefined':
    os.environ['JOB_NAME'] = 'libfuzzer_ubsan'

  os.environ['BUILD_DIR'] = os.path.dirname(args.target)

  engine_impl = clusterfuzz.fuzz.get_engine(args.engine)
  result = engine_impl.minimize_corpus(args.target, [], args.input, args.output,
                                       args.crashers, args.max_duration)
  print('Command: ', ' '.join([shlex.quote(part) for part in result.command]))


if __name__ == '__main__':
  main()
