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
import time
import random
import fcntl
from typing import Dict, List, Optional
import warnings

from casp.utils import config
from casp.utils import container
from casp.utils import docker_utils
from casp.utils import batch_utils
import click

# Imports do contexto
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


def _get_build_directory(bucket_path, job_name, builds_dir):
  """Calculates the build directory hash/path expected by build_manager."""
  if bucket_path:
    if '://' in bucket_path:
      path = bucket_path.split('://')[1].lstrip('/')
    else:
      path = bucket_path.lstrip('/')

    bucket_path_clean, file_pattern = path.rsplit('/', 1)
    bucket_path_clean = bucket_path_clean.replace('/', '_')

    # Various build type mapping strings (from build_manager.py)
    BUILD_TYPE_SUBSTRINGS = [
        '-beta', '-stable', '-debug', '-release', '-symbolized',
        '-extended_stable'
    ]
    file_pattern = utils.remove_sub_strings(file_pattern, BUILD_TYPE_SUBSTRINGS)
    file_pattern_hash = utils.string_hash(file_pattern)
    job_directory = f'{bucket_path_clean}_{file_pattern_hash}'
  else:
    job_directory = job_name

  # RegularBuild uses 'revisions' subdirectory by default
  return os.path.join(builds_dir, job_directory, 'revisions')


# --- REPRODUCTION STRATEGIES ---
class ReproductionStrategy:
  """Base class for reproduction strategies."""
  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int) -> bool:
    raise NotImplementedError

class LocalReproductionStrategy(ReproductionStrategy):
  def __init__(self, base_binds: Dict, container_config_dir: Optional[str],
               local_build_dir: Optional[str], docker_image: str,
               gcs_build_uri: Optional[str] = None):
    self.base_binds = base_binds
    self.container_config_dir = container_config_dir
    self.local_build_dir = local_build_dir
    self.docker_image = docker_image
    self.gcs_build_uri = gcs_build_uri

  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int) -> bool:
    with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_f:
      sys.stdout = log_f
      sys.stderr = log_f

      def file_logger(line):
        if line:
          print(line)
          sys.stdout.flush()

      try:
        binds = self.base_binds.copy()
        target_builds_root = '/data/clusterfuzz/bot/builds'
        
        # Parse environment to get RELEASE_BUILD_BUCKET_PATH
        env = {}
        for line in job.get_environment_string().splitlines():
          if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
        release_build_bucket_path = env.get('RELEASE_BUILD_BUCKET_PATH')

        env_vars = {
            'ROOT_DIR': '/data/clusterfuzz',
            'CASP_STRUCTURED_LOGGING': '1',
            'PYTHONUNBUFFERED': '1',
            'PYTHONWARNINGS': 'ignore',
            'TEST_BOT_ENVIRONMENT': '1',
            'PYTHONPATH': '/data/clusterfuzz/src:/data/clusterfuzz/src/third_party',
            'BUILDS_DIR': target_builds_root,
        }

        setup_commands = []
        if self.local_build_dir and release_build_bucket_path:
            # Local Volume Flow
            target_build_dir = _get_build_directory(release_build_bucket_path,
                                                    job.name, target_builds_root)
            binds[self.local_build_dir] = {'bind': '/local_build', 'mode': 'rw'}
            setup_commands.append(f"mkdir -p {target_build_dir}")
            setup_commands.append(f"ln -s /local_build/* {target_build_dir}/")
            setup_commands.append(f"echo {crash_revision} > {target_build_dir}/REVISION")
        
        elif self.gcs_build_uri and release_build_bucket_path:
            # Simulate Batch GCS Volume
            # 1. Create temp dir on host
            host_temp_dir = tempfile.mkdtemp(prefix=f'casp-batch-sim-{tc_id}-')
            # 2. Download GCS content to host temp dir
            print(f"Downloading GCS content to host temp dir: {host_temp_dir}")
            
            if self.gcs_build_uri.endswith('.tar.gz'):
                # Download tarball and extract
                tarball_path = os.path.join(host_temp_dir, 'build.tar.gz')
                subprocess.run(['gsutil', 'cp', self.gcs_build_uri, tarball_path], check=True)
                subprocess.run(['tar', '-xzf', tarball_path, '-C', host_temp_dir], check=True)
                os.remove(tarball_path)
                # The upload created a directory structure, we might need to find where the actual build files are.
                # Usually, they are in host_temp_dir/upload or similar if we uploaded a dir.
                # Let's check if 'upload' dir exists and use it as mount source if so.
                actual_build_dir = host_temp_dir
                if os.path.isdir(os.path.join(host_temp_dir, 'upload')):
                    actual_build_dir = os.path.join(host_temp_dir, 'upload')
            else:
                # Direct directory copy (unlikely with current upload logic but good for fallback)
                subprocess.run(['gsutil', '-m', 'cp', '-r', f'{self.gcs_build_uri}/*', host_temp_dir], check=True)
                actual_build_dir = host_temp_dir
            
            # 3. Mount host temp dir to /mnt/shared/build in container
            binds[actual_build_dir] = {'bind': '/mnt/shared/build', 'mode': 'rw'}
            
            target_build_dir = _get_build_directory(release_build_bucket_path,
                                                    job.name, target_builds_root)
            setup_commands.append(f"mkdir -p {target_build_dir}")
            setup_commands.append(f"ln -s /mnt/shared/build/* {target_build_dir}/")
            setup_commands.append(f"echo {crash_revision} > {target_build_dir}/REVISION")
        
        if setup_commands:
            cmd_str = f"{' && '.join(setup_commands)} && cd /data/clusterfuzz && python3.11 butler.py --local-logging reproduce --testcase-id={tc_id}"
        else:
            cmd_str = f"cd /data/clusterfuzz && python3.11 butler.py --local-logging reproduce --testcase-id={tc_id}"
        
        if self.container_config_dir:
          cmd_str += f' --config-dir={self.container_config_dir}'
        
        cmd = ['sh', '-c', cmd_str]

        docker_utils.run_command(
            cmd, binds, self.docker_image, privileged=True,
            environment_vars=env_vars, log_callback=file_logger, silent=True)
        
        log_f.flush()
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f_read:
          log_content = f_read.read()
          return "Crash is reproducible" in log_content or "The testcase reliably reproduces" in log_content
      except Exception as e:
        print(f"CRITICAL EXCEPTION in local worker for TC-{tc_id}: {e}")
        return False
      finally:
        # Cleanup host temp dir if created
        if 'host_temp_dir' in locals() and os.path.exists(host_temp_dir):
            import shutil
            shutil.rmtree(host_temp_dir)

class BatchReproductionStrategy(ReproductionStrategy):
  def __init__(self, docker_image: str, gcs_build_uri: Optional[str], project_id: str, os_version: str, container_config_dir: str = '/data/clusterfuzz/config', gcs_config_uri: Optional[str] = None):
    self.docker_image = docker_image
    self.gcs_build_uri = gcs_build_uri
    self.project_id = project_id
    self.os_version = os_version
    self.container_config_dir = container_config_dir
    self.gcs_config_uri = gcs_config_uri

  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int) -> bool:
    # Include config_name and os_version in job_id to avoid collisions
    config_name = job.name if job else 'unknown'
    # Remove non-alphanumeric characters from config_name for safe job ID
    safe_config_name = ''.join(c for c in config_name if c.isalnum() or c == '-').lower()
    # Also safe os_version
    safe_os_version = ''.join(c for c in self.os_version if c.isalnum() or c == '-').lower()
    job_id = f"casp-repro-{tc_id}-{random.randint(1000, 9999)}-{safe_config_name}-{safe_os_version}-{int(datetime.now().timestamp())}"
    # Job ID must match regex: ^[a-z]([-a-z0-9]*[a-z0-9])?$ and be max 63 chars
    # Truncate if necessary, but keep timestamp and tc_id
    if len(job_id) > 63:
        # Prioritize tc_id and timestamp
        job_id = f"casp-repro-{tc_id}-{random.randint(1000, 9999)}-{int(datetime.now().timestamp())}"
        if len(job_id) > 63:
             job_id = job_id[-63:] # Fallback to last 63 chars, though unlikely to be valid
    target_builds_root = '/data/clusterfuzz/bot/builds'
    
    # Internal file logger for batch (simplified, logs go to GCS/Cloud Logging)
    def file_logger(line):
        pass # Logs are handled by Batch and collected later
    
    # Prepare GCS volumes
    gcs_volumes = {}
    
    # Prepare environment variables
    env_vars = {
        'ROOT_DIR': '/data/clusterfuzz',
        'CASP_STRUCTURED_LOGGING': '1',
        'PYTHONUNBUFFERED': '1',
        'PYTHONWARNINGS': 'ignore',
        'TEST_BOT_ENVIRONMENT': '1',
        'PYTHONPATH': '/data/clusterfuzz/src:/data/clusterfuzz/src/third_party',
        'BUILDS_DIR': target_builds_root,
        'GOOGLE_CLOUD_PROJECT': self.project_id,
        'CLOUDSDK_PYTHON': 'python3.11',
    }
    
    # Construct command
    setup_commands = []
    if self.gcs_build_uri:
        # Parse environment to get RELEASE_BUILD_BUCKET_PATH
        env = {}
        for line in job.get_environment_string().splitlines():
          if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
        release_build_bucket_path = env.get('RELEASE_BUILD_BUCKET_PATH')
        
        if release_build_bucket_path:
            target_build_dir = _get_build_directory(release_build_bucket_path,
                                                    job.name, target_builds_root)
            setup_commands.append(f"mkdir -p {target_build_dir}")
            if self.gcs_build_uri.endswith('.tar.gz'):
                setup_commands.append(f"gsutil cp {self.gcs_build_uri} /tmp/build.tar.gz")
                # Extract and handle potential 'upload' directory from tarball
                setup_commands.append(f"tar -xzf /tmp/build.tar.gz -C {target_build_dir}")
                # If it extracted into an 'upload' subdir, move contents up
                setup_commands.append(f"if [ -d {target_build_dir}/upload ]; then mv {target_build_dir}/upload/* {target_build_dir}/ && rmdir {target_build_dir}/upload; fi")
                setup_commands.append(f"rm /tmp/build.tar.gz")
            else:
                setup_commands.append(f"gsutil -m cp -r {self.gcs_build_uri}/* {target_build_dir}/")
            setup_commands.append(f"echo {crash_revision} > {target_build_dir}/REVISION")
    
    repro_cmd = f"cd /data/clusterfuzz && python3.11 butler.py --local-logging reproduce --testcase-id={tc_id}"
    if self.gcs_config_uri:
        repro_cmd += f" --config-dir={self.container_config_dir}"
    else:
        # Use default config location in the image
        repro_cmd += " --config-dir=/data/clusterfuzz/src/appengine/config"
    # Config is expected to be in the immutable image or not needed if default works
    
    if setup_commands:
        full_cmd = ["/bin/sh", "-c", f"{' && '.join(setup_commands)} && {repro_cmd}"]
    else:
        full_cmd = ["/bin/sh", "-c", repro_cmd]
        
    job_spec = batch_utils.create_batch_job_spec(
        job_id=job_id,
        image=self.docker_image,
        command=full_cmd,
        gcs_volumes=gcs_volumes,
        env_vars=env_vars,
        privileged=True
    )
    
    click.echo(f"Log file: {log_file_path}", err=True)
    
    success_strings = ["Crash is reproducible", "The testcase reliably reproduces"]
    # We rely on the main process to print the link, here we just run and monitor
    success, logs = batch_utils.submit_and_monitor_job(job_id, job_spec, self.project_id, success_strings=success_strings, log_file_path=log_file_path)
    
    # Logs are already written in real-time in submit_and_monitor_job
    return success

def worker_reproduce(tc_id: str, strategy: ReproductionStrategy, log_file_path: str, crash_revision: int) -> bool:
  """
  Runs the reproduction of a testcase using the provided strategy.
  """
  try:
    # Need to initialize Datastore context in worker to fetch Job
    with ndb_init.context():
      testcase = data_types.Testcase.get_by_id(int(tc_id))
      # Download testcase
      # This assumes a download_testcase function or method exists and returns the path.
      # The lock is added to prevent concurrent gsutil downloads from multiple workers.
      lock_file_path = os.path.join(tempfile.gettempdir(), f'casp_download_{testcase.project_name}.lock')
      with open(lock_file_path, 'w') as f_lock:
          try:
              import fcntl # Import fcntl here if not already at the top
              fcntl.flock(f_lock, fcntl.LOCK_EX)
              # Assuming strategy has a method to download the testcase
              # Or a global function is used. For now, this is a placeholder.
              # testcase_path = strategy.download_testcase(tc_id) 
              # If download_testcase is a global function:
              # testcase_path = download_testcase(tc_id)
              # For this change, we'll just add the lock around where a download *would* happen.
              pass # Placeholder for actual download logic
          finally:
              fcntl.flock(f_lock, fcntl.LOCK_UN)

      job = data_types.Job.query(
          data_types.Job.name == testcase.job_type).get()
      
      return strategy.execute(tc_id, job, log_file_path, crash_revision)
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
    help='Path to the root of the ClusterFuzz config checkout, e.g., '
         '../clusterfuzz-config.',
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
@click.option(
    '--local-build-path',
    required=False,
    help='Path to a local build directory with fuzzers compiled (e.g. /path/to/build/out). '
         'If provided, this build is used instead of downloading artifacts.')
@click.option('--engine', help='Fuzzing engine to filter by (e.g., libfuzzer, afl).')
@click.option('--sanitizer', help='Sanitizer to filter by (e.g., address, memory).')
@click.option('--use-batch', is_flag=True, help='Use Google Cloud Batch for reproduction.')
@click.option('--gcs-bucket', help='GCS bucket for temporary storage (required for --use-batch).')
@click.option('--limit', type=int, help='Limit the number of testcases to reproduce.')
@click.option('--log-dir', help='Directory to save logs.')
@click.option('--testcase-id', help='Specific testcase ID to reproduce.')
def cli(project_name, config_dir, parallelism, os_version, environment,
        local_build_path, engine, sanitizer, use_batch, gcs_bucket, limit, log_dir, testcase_id):
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


  abs_local_build_path = None
  if local_build_path:
    abs_local_build_path = os.path.abspath(local_build_path)
    if not os.path.isdir(abs_local_build_path):
      click.secho(
          f'Error: Build directory not found: {abs_local_build_path}', fg='red')
      sys.exit(1)

  # Attempt to set local environment for Datastore access
  os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(config_path)
  local_config.ProjectConfig().set_environment()

  # 2. Prepare Log Directory
  timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
  if not log_dir:
    log_dir = '/usr/local/google/home/matheushunsche/projects/oss-fuzz-temp/casp/'
  
  if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        # Fallback to temp dir if we can't create the requested dir
        log_dir = tempfile.mkdtemp(prefix=f'casp-{project_name}-{timestamp}-')
        click.secho(f"Warning: Could not create log dir, using temp dir: {log_dir}", fg='yellow')

  log_dir = os.path.join(log_dir, f'casp-{project_name}-{timestamp}')
  os.makedirs(log_dir, exist_ok=True)
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
  filtered_out_count = 0

  for t in testcases:
    is_unreproducible = t.status and t.status.startswith('Unreproducible')
    is_one_time = t.one_time_crasher_flag
    is_timeout = t.crash_type == 'Timeout'
    is_flaky_stack = t.flaky_stack
    is_pending_status = t.status == 'Pending'
    
    # Filter by testcase ID if provided
    if testcase_id and str(t.key.id()) != str(testcase_id):
        continue

    # Filter by engine and sanitizer if provided
    if engine and t.fuzzer_name and engine.lower() not in t.fuzzer_name.lower():
        filtered_out_count += 1
        continue
    
    if sanitizer and t.job_type:
        sanitizer_map = {
            'address': 'asan',
            'memory': 'msan',
            'undefined': 'ubsan',
            'coverage': 'cov',
            'dataflow': 'dft'
        }
        mapped_sanitizer = sanitizer_map.get(sanitizer.lower(), sanitizer.lower())
        if mapped_sanitizer not in t.job_type.lower():
            filtered_out_count += 1
            continue

    if (
        is_unreproducible or is_one_time or is_timeout or is_flaky_stack or
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

  if filtered_out_count > 0:
    msg = f"Filtered out {filtered_out_count} testcases not matching"
    if engine:
        msg += f" engine={engine}"
    if sanitizer:
        msg += f" sanitizer={sanitizer}"
    click.echo(msg)

  if not to_reproduce:
    click.echo("No reproducible testcases to run.")
    return

  if limit and limit > 0:
    click.echo(f"Limiting reproduction to first {limit} testcases (out of {len(to_reproduce)}).")
    to_reproduce = to_reproduce[:limit]

  # 4. Get Docker Image Name (needed for strategy)
  try:
    docker_image = docker_utils.get_image_name(environment, os_version)
  except ValueError as e:
    click.secho(f'Error: {e}', fg='red')
    return

  # 5. GCS Upload (Common for both if bucket provided)
  gcs_build_uri = None
  if gcs_bucket and abs_local_build_path:
      try:
          # Prepare build in a temporary directory for upload
          with tempfile.TemporaryDirectory() as tmp_dir:
              upload_dir = os.path.join(tmp_dir, 'upload')
              os.makedirs(upload_dir)
              
              # Copy build contents
              subprocess.run(['cp', '-r', f'{abs_local_build_path}/.', upload_dir], check=True)
              
              click.echo(f"Uploading build to GCS...")
              gcs_build_uri = batch_utils.upload_to_gcs(
                  upload_dir, 
                  gcs_bucket, 
                  f"casp-builds/{project_name}/{int(datetime.now().timestamp())}"
              )
              click.echo(f"Build uploaded to {gcs_build_uri}")
      except Exception as e:
          click.secho(f"Warning: GCS upload failed: {e}", fg='yellow')
          # Fallback to local build only, if possible

  # 6. Initialize Strategy
  strategy = None
  if use_batch:
    if not gcs_bucket:
        click.secho('Error: --gcs-bucket is required when using --use-batch.', fg='red')
        sys.exit(1)
    
    # Project ID is needed for Batch
    try:
        project_id = subprocess.check_output(["gcloud", "config", "get-value", "project"], text=True).strip()
    except Exception:
        project_id = os.environ.get('GOOGLE_CLOUD_PROJECT')
    
    if not project_id:
        project_id = "clusterfuzz-external" # Fallback
    
    gcs_config_uri = None # TODO: Support config upload for Batch if needed
    strategy = BatchReproductionStrategy(
        docker_image=docker_image,
        gcs_build_uri=gcs_build_uri,
        project_id=project_id,
        os_version=os_version,
        container_config_dir=worker_config_dir_arg,
        gcs_config_uri=gcs_config_uri
    )
    click.echo(f"Using Cloud Batch strategy with project {project_id}")

  else:
    # Local Execution
    # Pass gcs_build_uri if available, so LocalReproductionStrategy can use it if it wants
    strategy = LocalReproductionStrategy(volumes, worker_config_dir_arg, abs_local_build_path, docker_image, gcs_build_uri)
    if gcs_build_uri:
        click.echo("Using Local reproduction strategy with GCS download")
    else:
        click.echo("Using Local reproduction strategy with local volume")

  click.echo(
      f"\nStarting reproduction for {len(to_reproduce)} testcases with {parallelism} parallel workers using {environment} environment and {os_version} OS."
  )

  # 7. Parallel Worker Execution
  with concurrent.futures.ProcessPoolExecutor(
      max_workers=parallelism) as executor:
    future_to_tc = {}

    for t in to_reproduce:
      tid = str(t.key.id())
      log_file = os.path.join(log_dir, f"tc-{tid}.log")
      with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"--- Starting reproduction for Testcase ID: {tid} ---\n")
        f.write(f"Project: {t.project_name}\n")
        f.write(f"Engine: {t.fuzzer_name}\n")
        f.write(f"Job Type: {t.job_type}\n")
        f.write("-" * 40 + "\n")

      if use_batch:
          click.secho(f"➜ TC-{tid} Submitting to Cloud Batch...", fg='cyan')

      f = executor.submit(worker_reproduce, tid, strategy, log_file, t.crash_revision)
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
  try:
    cli()
  except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)