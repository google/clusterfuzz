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
"""Copy corpus from one bucket to another, keeping project name in mind."""

import argparse
import datetime
import random
import subprocess
import sys
import time

GSUTIL_CMD = 'gsutil'
RETRY_COUNT = 5
SLEEP_WAIT = 60

USAGE_REMINDER_MESSAGE = """If you set up two or more experimental jobs,
remember to copy production buckets only once. For creating two or more buckets
with the same content, copy the first experimental bucket over to the others to
make sure that contents of the buckets will be exactly the same."""


def _run_command(command):
  """Runs a command and prints it."""
  print(
      'Running command [{time}]:'.format(
          time=datetime.datetime.now().strftime('%H:%M:%S')),
      ' '.join(command))

  for _ in range(RETRY_COUNT):
    try:
      return subprocess.check_output(command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      print('Command failed with non-zero exit code. Output:\n%s' % e.output)

    print('Sleeping a few seconds before retrying.')
    time.sleep(random.randint(0, SLEEP_WAIT))

  print('Failed to run command, exiting.')
  sys.exit(-1)


def _copy_corpus(source_bucket, source_project, target_bucket, target_project):
  """Copy corpus from a source bucket to target bucket, keeping their project
  names into account."""
  # Ensure that gsutil is installed.
  subprocess.check_call([GSUTIL_CMD, '-v'])

  source_urls_fetch_command = [
      GSUTIL_CMD, 'ls', 'gs://{bucket}/*/'.format(bucket=source_bucket)
  ]
  source_urls = _run_command(source_urls_fetch_command).splitlines()
  filtered_source_urls = [
      s.rstrip('/') for s in source_urls if s.strip() and not s.endswith(':')
  ]

  assert filtered_source_urls, 'No matching items found in source corpus.'
  for source_url in filtered_source_urls:
    url_part, fuzz_target = source_url.rsplit('/', 1)

    # Strip source project prefix and add target project prefix (if exists).
    if source_project and fuzz_target.startswith(source_project + '_'):
      fuzz_target = fuzz_target[len(source_project) + 1:]
    if target_project:
      fuzz_target = '%s_%s' % (target_project, fuzz_target)

    # Replace source bucket with target bucket for target url.
    url_part = url_part.replace('gs://%s' % source_bucket,
                                'gs://%s' % target_bucket)
    target_url = '%s/%s' % (url_part, fuzz_target)

    _run_command(
        [GSUTIL_CMD, '-m', 'rsync', '-d', '-r', source_url, target_url])

  print('Copy corpus finished successfully.')


def main():
  arg_parser = argparse.ArgumentParser(description='Corpus copier. %s' %
                                       USAGE_REMINDER_MESSAGE)
  arg_parser.add_argument(
      '-sb',
      '--source-bucket',
      type=str,
      required=True,
      help='Source bucket to copy corpus from.')
  arg_parser.add_argument(
      '-tb',
      '--target-bucket',
      type=str,
      required=True,
      help='Target bucket to copy corpus to.')
  arg_parser.add_argument(
      '-sp',
      '--source-project',
      nargs='?',
      type=str,
      const='',
      required=False,
      help='Source project. Leave empty if fuzz target has project prefix.')
  arg_parser.add_argument(
      '-tp',
      '--target-project',
      nargs='?',
      type=str,
      const='',
      required=False,
      help='Target project.')

  args = arg_parser.parse_args()
  _copy_corpus(args.source_bucket, args.source_project, args.target_bucket,
               args.target_project)


if __name__ == '__main__':
  main()
