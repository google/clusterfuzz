# Copyright 2025 Google LLC
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
"""Reproduces testcases for an OSS-Fuzz project locally."""

import concurrent.futures
from datetime import datetime
import os
import subprocess
import sys
import tempfile
from typing import Dict
from typing import Optional
import warnings

from casp.utils import config
from casp.utils import container
from casp.utils import docker_utils
import click

# Imports do contexto
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


# --- SIMPLIFIED WORKER ---
def worker_reproduce(tc_id: str, base_binds: Dict,
                     container_config_dir: Optional[str],
                     docker_image: str, log_file_path: str) -> bool:
  """
  Runs the reproduction of a testcase in a Docker container.
  """
  with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_f:
    sys.stdout = log_f
    sys.stderr = log_f

    def file_logger(line):
      if line:
        print(line)
        sys.stdout.flush()

    try:
      binds = base_binds.copy()
      binds[os.path.abspath('.')] = {'bind': '/app', 'mode': 'rw'}

      env_vars = {
          'CASP_STRUCTURED_LOGGING': '1',
          'PYTHONUNBUFFERED': '1',
          'PYTHONWARNINGS': 'ignore',
          'TEST_BOT_ENVIRONMENT': '1',
          'PYTHONPATH': '/app/src',
      }

      cmd = [
          'python3.11', '/app/butler.py', '--local-logging', 'reproduce',
          f'--testcase-id={tc_id}'
      ]

      if container_config_dir:
        cmd.append(f'--config-dir={container_config_dir}')

      docker_utils.run_command(
          cmd,
          binds,
          docker_image,
          privileged=True,
          environment_vars=env_vars,
          log_callback=file_logger,
          silent=True)

      log_f.flush()

      try:
        with open(
            log_file_path, 'r', encoding='utf-8', errors='ignore') as f_read:
          log_content = f_read.read()
          if "Crash is reproducible" in log_content or "The testcase reliably reproduces" in log_content:
            return True
      except Exception:
        pass

      return False

    except Exception as e:
      print(f"CRITICAL EXCEPTION in worker for TC-{tc_id}: {e}")
      return False


# --- MAIN CLI ---
@click.command('project')
@click.option('--project-name', required=True, help='OSS-Fuzz project name.')
@click.option(
    '--config-dir',
    '-c',
    required=False,
    default='../clusterfuzz-config',
    help=('Path to the root of the ClusterFuzz config checkout, e.g., '
          '../clusterfuzz-config.'),
)
@click.option(
    '-n', '--parallelism', default=10, type=int, help='Parallel workers.')
@click.option(
    '--os-version',
    type=click.Choice(
        ['legacy', 'ubuntu-20-04', 'ubuntu-24-04'], case_sensitive=False),
    default='legacy',
    help='OS version to use for reproduction.')
@click.option(
    '--environment',
    '-e',
    type=click.Choice(['external', 'internal', 'dev'], case_sensitive=False),
    default='external',
    help='The ClusterFuzz environment (instance type).')
def cli(project_name, config_dir, parallelism, os_version, environment):
  """
  Reproduces testcases for an OSS-Fuzz project, saving logs to files.
  """

  # 1. Environment Setup
  config_path = os.path.join(config_dir, 'configs', environment)
  if not os.path.isdir(config_path):
    click.secho(
        f'Error: Config directory not found: {config_path}\n'
        f'Please provide the correct path to the root of your '
        f'clusterfuzz-config checkout using the -c/--config-dir option.',
        fg='red')
    sys.exit(1)

  cfg = config.load_and_validate_config()
  volumes, _ = docker_utils.prepare_docker_volumes(cfg, config_path)

  mount_point = '/custom_config'
  volumes[os.path.abspath(config_path)] = {'bind': mount_point, 'mode': 'ro'}
  worker_config_dir_arg = mount_point

  # Attempt to set local environment for Datastore access
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(config_path)
  local_config.ProjectConfig().set_environment()

  # 2. Prepare Temporary Log Directory
  timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
  log_dir = tempfile.mkdtemp(prefix=f'casp-{project_name}-{timestamp}-')
  click.echo(f"Logs will be saved in: {log_dir}")

  # 3. Fetch Testcases from Datastore
  click.echo(f"Fetching testcases for {project_name}...")
  try:
    with ndb_init.context():
      query = data_types.Testcase.query(
          data_types.Testcase.project_name == project_name,
          ndb_utils.is_true(data_types.Testcase.open))
      testcases = list(ndb_utils.get_all_from_query(query))
  except Exception as e:
    click.secho(f"Error fetching testcases: {e}", fg='red')
    return

  if not testcases:
    click.secho(f'No open testcases found for {project_name}.', fg='yellow')
    return

  total_testcases_count = len(testcases)

  to_reproduce = []
  skipped = []

  for t in testcases:
    is_unreproducible = t.status and t.status.startswith('Unreproducible')
    is_one_time = t.one_time_crasher_flag
    is_timeout = t.crash_type == 'Timeout'
    is_flaky_stack = t.flaky_stack
    is_pending_status = t.status == 'Pending'

    if (is_unreproducible or is_one_time or is_timeout or is_flaky_stack or
        is_pending_status):
      skipped.append(t)
    else:
      to_reproduce.append(t)

  skipped_count = len(skipped)
  if skipped_count > 0:
    click.echo(
        f"Found {total_testcases_count} open testcases. {skipped_count} skipped (Unreproducible, Flaky, Pending, etc)."
    )
  else:
    click.echo(f"Found {total_testcases_count} open testcases.")

  if not to_reproduce:
    click.echo("No reproducible testcases to run.")
    return

  # 4. Docker Image Pre-pull (Silent)
  try:
    docker_image = docker_utils.get_image_name(environment, os_version)
  except ValueError as e:
    click.secho(f'Error: {e}', fg='red')
    return

  click.echo(
      f"Checking Docker image: {docker_image} (this may take a moment)...")
  try:
    subprocess.run(
        ["docker", "pull", docker_image],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    click.echo("Docker image check complete.")
  except Exception:
    click.secho(
        "Warning: Docker pull failed or docker not found. Proceeding anyway...",
        fg='yellow')

  click.echo(
      f"\nStarting reproduction for {len(to_reproduce)} testcases with {parallelism} parallel workers using {environment} environment and {os_version} OS."
  )

  # 5. Parallel Worker Execution
  with concurrent.futures.ProcessPoolExecutor(
      max_workers=parallelism) as executor:
    future_to_tc = {}

    for t in to_reproduce:
      tid = str(t.key.id())
      log_file = os.path.join(log_dir, f"tc-{tid}.log")
      with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"--- Starting reproduction for Testcase ID: {tid} ---\n")

      f = executor.submit(worker_reproduce, tid, volumes, worker_config_dir_arg,
                          docker_image, log_file)
      future_to_tc[f] = tid

    completed_count = 0
    success_count = 0
    failure_count = 0
    for future in concurrent.futures.as_completed(future_to_tc):
      completed_count += 1
      tid = future_to_tc[future]
      try:
        is_success = future.result()
        if is_success:
          success_count += 1
          click.secho(
              f"✔ TC-{tid} Success ({completed_count}/{len(to_reproduce)})",
              fg='green')
        else:
          failure_count += 1
          click.secho(
              f"✖ TC-{tid} Failed ({completed_count}/{len(to_reproduce)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
              fg='red')
      except Exception as exc:
        failure_count += 1
        click.secho(
            f"! TC-{tid} Error: {exc} ({completed_count}/{len(to_reproduce)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
            fg='red')

  click.echo("\nAll reproduction tasks completed.")

  reproducible_count = len(to_reproduce)
  success_rate = (
      success_count / reproducible_count) * 100 if reproducible_count else 0.0
  failure_rate = (
      failure_count / reproducible_count) * 100 if reproducible_count else 0.0

  click.echo(f"Summary: {reproducible_count} testcases attempted.")
  click.secho(f"  ✔ Success: {success_count} ({success_rate:.2f}%)", fg='green')
  click.secho(f"  ✖ Failed:  {failure_count} ({failure_rate:.2f}%)", fg='red')
  click.secho(
      f"  ⚠ Skipped: {len(skipped)} - Unreliable (Unreproducible/One-time)",
      fg='yellow')
  click.echo(f"Detailed logs are available in: {log_dir}")


if __name__ == "__main__":
  cli()
