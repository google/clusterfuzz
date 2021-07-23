# Copyright 2019 Google LLC
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
"""Run minimizers with default configuration from the command line."""

import argparse
import os
import sys

from . import chunk_minimizer
from . import delta_minimizer
from . import html_minimizer
from . import js_minimizer
from . import minimizer
from . import utils


def main():
  """Minimize a file."""
  minimizers = {
      'chunk': chunk_minimizer.ChunkMinimizer,
      'html': html_minimizer.HTMLMinimizer,
      'js': js_minimizer.JSMinimizer,
      'line': delta_minimizer.DeltaMinimizer,
  }

  parser = argparse.ArgumentParser()
  parser.add_argument(
      '-t',
      '--threads',
      default=minimizer.DEFAULT_THREAD_COUNT,
      type=int,
      help='number of parallel instances')
  parser.add_argument(
      '-m',
      '--minimizer',
      choices=list(minimizers.keys()),
      default='line',
      help='minimization strategy')
  parser.add_argument(
      '-o', '--output-file', help='path to minimized output file')
  parser.add_argument(
      'COMMAND', help='command (quoted) to run for an individual test')
  parser.add_argument('FILE', help='file to minimize')
  args = vars(parser.parse_args(sys.argv[1:]))

  thread_count = args['threads']
  selected_minimizer = minimizers[args['minimizer']]
  command = args['COMMAND']
  file_path = args['FILE']
  file_extension = os.path.splitext(file_path)[1]
  output_file_path = args['output_file']
  if not output_file_path:
    output_file_path = '%s.min' % file_path

  utils.set_test_command(command)

  try:
    with open(file_path, 'rb') as file_handle:
      data = file_handle.read()
  except IOError:
    print('Unable to open input file %s.' % file_path)
    sys.exit(1)

  # Do not print an additional newline after minimization.
  minimized_output = selected_minimizer.run(
      data, thread_count=thread_count, file_extension=file_extension)
  print('Writing minimized output to %s.' % output_file_path)
  try:
    with open(output_file_path, 'wb') as file_handle:
      file_handle.write(minimized_output)
  except IOError:
    print('Unable to write output file %s.' % output_file_path)
    sys.exit(1)


if __name__ == '__main__':
  main()
