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
"""Download job config as a JSON file."""

import argparse
import json
import os
import sys

from clusterfuzz._internal.datastore import data_types


def _parse_script_args(script_args):
  """Parses the script specific arguments."""
  parser = argparse.ArgumentParser(prog='download_job_config')
  parser.add_argument(
      'job_names', nargs='+', help='Names of the jobs to download.')
  parser.add_argument(
      '--output-dir',
      default='.',
      help='Directory to write <job_name>_job_config.json files to. Created if '
      'it does not exist. Defaults to the current working directory.')
  return parser.parse_args(script_args)


def download_job_configs(
    job_names: list[str],
    output_dir: str,
    non_dry_run: bool = True,
) -> list[data_types.Job]:
  """Downloads job configs (including resolved template envs) to output_dir."""
  jobs = data_types.Job.query(data_types.Job.name.IN(job_names)).fetch()

  if not non_dry_run:
    print('Skipping writes in dry-run mode.')
    return jobs

  if jobs:
    os.makedirs(output_dir, exist_ok=True)

  for job in jobs:
    config = {
        'name': job.name,
        'platform': job.platform,
        'project': job.project,
        'templates': job.templates,
        'description': job.description,
        'environment_string': job.environment_string,
        'environment': job.get_environment(),
    }
    filename = os.path.join(output_dir, f'{job.name}_job_config.json')
    with open(filename, 'w') as f:
      json.dump(config, f, indent=4, sort_keys=True)

    print(f'Saved config for job {job.name} to {filename}.')

  return jobs


def execute(args):
  """Download job config."""
  if not args.script_args:
    print('Please provide a list of job names as script arguments.')
    sys.exit(1)

  script_args = _parse_script_args(args.script_args)
  download_job_configs(
      job_names=script_args.job_names,
      output_dir=script_args.output_dir,
      non_dry_run=args.non_dry_run,
  )
