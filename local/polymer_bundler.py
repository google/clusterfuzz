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
"""Uses polymer-bundler to combine resources to reduce number of requests."""

import multiprocessing
import os
import sys

APPENGINE_DIRECTORY = os.path.join(
    os.path.dirname(__file__), os.pardir, 'src', 'appengine')


def get_file_modified_times(directory):
  """Return a list of last modified times for the files in a directory."""
  modified_times = []
  for root, _, filenames in os.walk(directory):
    for filename in filenames:
      modified_times.append(os.path.getmtime(os.path.join(root, filename)))

  return modified_times


def build_file(filename):
  """Build a single file using polymer-bundler."""
  input_filename = os.path.join('private', 'templates', filename)
  output_filename = os.path.join('templates', filename)
  os.system('polymer-bundler --inline-scripts --inline-css --strip-comments '
            '--out-file={output_filename} {input_filename}'.format(
                output_filename=output_filename, input_filename=input_filename))

  if os.path.exists(output_filename) and os.path.getsize(output_filename):
    return True

  print('Failed to build template: ' + output_filename)
  return False


def main():
  """Use polymer-bundler to compile templates."""
  os.chdir(APPENGINE_DIRECTORY)

  bundled_change_times = get_file_modified_times('templates')
  first_bundled_time = min(bundled_change_times) if bundled_change_times else 0
  latest_unbundled_time = max(get_file_modified_times('private'))
  if latest_unbundled_time < first_bundled_time:
    print('App Engine templates are up to date.')
    return

  print('Building templates for App Engine...')

  if not os.path.exists('templates'):
    os.mkdir('templates')

  template_names = os.listdir(os.path.join('private', 'templates'))
  pool = multiprocessing.Pool(max(multiprocessing.cpu_count() // 2, 1))
  result = pool.map(build_file, template_names)

  if not all(result):
    print('Failed to build App Engine templates.')
    sys.exit(1)

  print('App Engine templates built successfully.')


if __name__ == '__main__':
  main()
