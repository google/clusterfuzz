import click
import concurrent.futures
import os
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime
from typing import Dict, List, Optional

# Imports do contexto
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from casp.utils import docker_utils
from casp.utils import config
from casp.utils import container

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


# --- SIMPLIFIED WORKER ---
def worker_reproduce(tc_id: str, base_binds: Dict, container_config_dir: Optional[str],
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
          'PYTHONPATH': '/app/src'
      }

      cmd = [
          'python3.11', '/app/butler.py', '--local-logging', 'reproduce', f'--testcase-id={tc_id}'
      ]

      if container_config_dir:
        cmd.append(f'--config-dir={container_config_dir}')

      run_command_success = docker_utils.run_command(
          cmd,
          binds,
          docker_image,
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
    default=str(container.CONTAINER_CONFIG_PATH / 'config'),
    help=('Path to the config directory. If you set a custom '
          'config directory, this argument is not used.'),
)
@click.option(
    '-n', '--parallelism', default=10, type=int, help='Parallel workers.')
@click.option(
    '--os-version',
    type=click.Choice(['legacy', 'ubuntu-20-04', 'ubuntu-24-04'],
                      case_sensitive=False),
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
  cfg = config.load_and_validate_config()
  volumes, container_config_dir_path = docker_utils.prepare_docker_volumes(
      cfg, config_dir)
  
  default_container_config_path = str(container.CONTAINER_CONFIG_PATH / 'config')
  worker_config_dir_arg = None

  if container_config_dir_path != default_container_config_path:
    # If the resolved config path is not the default, pass it to the worker.
    worker_config_dir_arg = str(container_config_dir_path)

  # If config_dir is a local path and not the default container path, mount it manually.
  if os.path.isdir(config_dir) and config_dir != default_container_config_path:
      mount_point = '/custom_config'
      volumes[os.path.abspath(config_dir)] = {'bind': mount_point, 'mode': 'ro'}
      worker_config_dir_arg = mount_point

  # Attempt to set local environment for Datastore access
  local_config_dir = None
  if 'custom_config_path' in cfg:
    local_config_dir = cfg['custom_config_path']
  elif config_dir and os.path.isdir(config_dir):
    local_config_dir = config_dir

  if local_config_dir:
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(local_config_dir)
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

    if is_unreproducible or is_one_time:
      skipped.append(t)
    else:
      to_reproduce.append(t)

  skipped_count = len(skipped)
  if skipped_count > 0:
    click.echo(
        f"Found {total_testcases_count} open testcases. {skipped_count} skipped (Unreproducible or One-time crasher)."
    )
  else:
    click.echo(f"Found {total_testcases_count} open testcases.")

  tc_ids = [str(t.key.id()) for t in to_reproduce]

  if not tc_ids:
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
      f"\nStarting reproduction for {len(tc_ids)} testcases with {parallelism} parallel workers using {environment} environment and {os_version} OS."
  )

  # 5. Parallel Worker Execution
  with concurrent.futures.ProcessPoolExecutor(
      max_workers=parallelism) as executor:
    future_to_tc = {}

    for tid in tc_ids:
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
              f"✔ TC-{tid} Success ({completed_count}/{len(tc_ids)})",
              fg='green')
        else:
          failure_count += 1
          click.secho(
              f"✖ TC-{tid} Failed ({completed_count}/{len(tc_ids)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
              fg='red')
      except Exception as exc:
        failure_count += 1
        click.secho(
            f"! TC-{tid} Error: {exc} ({completed_count}/{len(tc_ids)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
            fg='red')

  click.echo("\nAll reproduction tasks completed.")

  skipped_count = len(skipped)
  success_rate = (success_count / total_testcases_count) * 100 if total_testcases_count else 0.0
  failure_rate = (failure_count / total_testcases_count) * 100 if total_testcases_count else 0.0
  skipped_rate = (skipped_count / total_testcases_count) * 100 if total_testcases_count else 0.0

  click.echo(f"Summary: {total_testcases_count} testcases processed.")
  click.secho(f"  ✔ Success: {success_count} ({success_rate:.2f}%)", fg='green')
  click.secho(f"  ✖ Failed:  {failure_count} ({failure_rate:.2f}%)", fg='red')
  click.secho(f"  ⚠ Skipped: {skipped_count} ({skipped_rate:.2f}%) - Unreliable (Unreproducible/One-time)", fg='yellow')
  click.echo(f"Detailed logs are available in: {log_dir}")


if __name__ == "__main__":
  cli()
