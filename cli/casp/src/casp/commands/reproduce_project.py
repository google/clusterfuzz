import click
import os
import concurrent.futures
import subprocess
import warnings
import tempfile
import sys
from datetime import datetime
from typing import List

# Imports do contexto
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from casp.utils import docker_utils

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


# --- SIMPLIFIED WORKER ---
def worker_reproduce(tc_id: str, config_dir: str, docker_image: str,
                     log_file_path: str) -> bool:
  """
  Runs the reproduction of a testcase in a Docker container.
  Captures all container output and saves it to the specified log file.
  Returns True if the Docker command was successful, False otherwise.
  """
  # Redirect stdout and stderr to the log file to capture output from libraries (e.g. gcloud)
  with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_f:
    sys.stdout = log_f
    sys.stderr = log_f

    def file_logger(line):
      """Callback to write each log line."""
      if line:
        print(line)
        sys.stdout.flush()  # Ensure immediate flush

    try:
      binds = {
          os.path.abspath(config_dir): {
              'bind': '/app/configs/external',
              'mode': 'ro'
          },
          os.path.abspath('.'): {
              'bind': '/app',
              'mode': 'rw'
          },
          os.path.expanduser('~/.config/gcloud'): {
              'bind': '/root/.config/gcloud',
              'mode': 'ro'
          }
      }

      env_vars = {
          'CASP_STRUCTURED_LOGGING': '1',
          'PYTHONUNBUFFERED': '1',
          'PYTHONWARNINGS': 'ignore',
          'TEST_BOT_ENVIRONMENT': '1',
          'PYTHONPATH': '/app/src'
      }

      cmd = [
          'python3.11', '/app/butler.py', 'reproduce', f'--testcase-id={tc_id}',
          '--config-dir=/app/configs/external'
      ]

      # Execute the Docker command. The log_callback directs all output to the file.
      run_command_success = docker_utils.run_command(
          cmd,
          binds,
          docker_image,
          environment_vars=env_vars,
          log_callback=file_logger,
          silent=True)

      # Check the log file for success markers. We re-read the file from disk.
      # Note: Since we are holding it open in 'log_f', we should flush first.
      log_f.flush()

      try:
        with open(
            log_file_path, 'r', encoding='utf-8', errors='ignore') as f_read:
          log_content = f_read.read()
          if "Crash is reproducible" in log_content or "The testcase reliably reproduces" in log_content:
            return True
      except Exception:
        pass

      return run_command_success

    except Exception as e:
      # Captures critical worker exceptions and logs them.
      print(f"CRITICAL EXCEPTION in worker for TC-{tc_id}: {e}")
      return False


# --- MAIN CLI ---
@click.command('project')
@click.option('--project-name', required=True, help='OSS-Fuzz project name.')
@click.option('-c', '--config-dir', required=True, help='Path to config.')
@click.option('--non-dry-run', is_flag=True, help='Execute real logic.')
@click.option(
    '-n', '--parallelism', default=3, type=int, help='Parallel workers.')
def cli(project_name, config_dir, non_dry_run, parallelism):
  """
  Reproduces testcases for an OSS-Fuzz project, saving logs to files.
  """

  # 1. Environment Setup
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(config_dir)
  local_config.ProjectConfig().set_environment()

  # 2. Prepare Temporary Log Directory
  timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
  log_dir = tempfile.mkdtemp(prefix=f'casp-{project_name}-{timestamp}-')
  click.echo(f"Logs will be saved in: {log_dir}")

  # 3. Fetch Testcases from Datastore
  click.echo(f"Fetching testcases for {project_name}...")
  with ndb_init.context():
    query = data_types.Testcase.query(
        data_types.Testcase.project_name == project_name,
        ndb_utils.is_true(data_types.Testcase.open))
    testcases = list(
        ndb_utils.get_all_from_query(query))  # Force generator evaluation here

  if not testcases:
    click.secho(f'No open testcases found for {project_name}.', fg='yellow')
    return

  tc_ids = [str(t.key.id()) for t in testcases]
  click.echo(f"Found {len(tc_ids)} open testcases.")

  if not non_dry_run:
    click.secho("DRY RUN MODE: Skipping execution.", fg='yellow')
    return

  # 4. Docker Image Pre-pull (Silent)
  docker_image = docker_utils.PROJECT_TO_IMAGE.get('external')
  if not docker_image:
    click.secho(
        'Error: Could not find "external" image in docker_utils.', fg='red')
    return

  click.echo(
      f"Checking Docker image: {docker_image} (this may take a moment)...")
  try:
    # Redirect stdout/stderr to DEVNULL to avoid polluting the terminal
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
      f"\nStarting reproduction for {len(tc_ids)} testcases with {parallelism} parallel workers."
  )

  # 5. Parallel Worker Execution
  with concurrent.futures.ProcessPoolExecutor(
      max_workers=parallelism) as executor:
    future_to_tc = {}

    for tid in tc_ids:
      log_file = os.path.join(log_dir, f"tc-{tid}.log")
      # Ensure log file starts clean for each testcase
      with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"--- Starting reproduction for Testcase ID: {tid} ---\n")

      f = executor.submit(worker_reproduce, tid, config_dir, docker_image,
                          log_file)
      future_to_tc[f] = tid

    # Monitor and report task status as they complete
    completed_count = 0
    for future in concurrent.futures.as_completed(future_to_tc):
      completed_count += 1
      tid = future_to_tc[future]
      try:
        is_success = future.result()
        if is_success:
          click.secho(
              f"✔ TC-{tid} Success ({completed_count}/{len(tc_ids)})",
              fg='green')
        else:
          click.secho(
              f"✖ TC-{tid} Failed ({completed_count}/{len(tc_ids)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
              fg='red')
      except Exception as exc:
        click.secho(
            f"! TC-{tid} Error: {exc} ({completed_count}/{len(tc_ids)}) - Check log: {os.path.join(log_dir, f'tc-{tid}.log')}",
            fg='red')

  click.echo("\nAll reproduction tasks completed.")
  click.echo(f"Detailed logs are available in: {log_dir}")


if __name__ == "__main__":
  cli()
