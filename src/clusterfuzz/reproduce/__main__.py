# Copyright 2020 Google LLC
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
"""Reproduction module."""

import argparse
import shlex
import sys

from clusterfuzz.environment import Environment
import clusterfuzz.fuzz


def main():
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
      '-r', '--reproducer', help='Path to reproducer.', required=True)
  parser.add_argument(
      '-d',
      '--max-duration',
      help='Max time in seconds to run.',
      type=int,
      default=25)
  parser.add_argument('engine_args', nargs='*')
  args = parser.parse_args()

  with Environment(args.engine, args.sanitizer, args.target, interactive=True):
    engine_impl = clusterfuzz.fuzz.get_engine(args.engine)
    result = engine_impl.reproduce(args.target, args.reproducer,
                                   args.engine_args, args.max_duration)

  print('Command: ', ' '.join([shlex.quote(part) for part in result.command]))
  sys.exit(result.return_code)


if __name__ == '__main__':
  main()
