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
import shutil
from datetime import datetime, timedelta
import argparse
import logging
import os
import sys
import time
import json
import random
import string
import shlex
import subprocess
import tempfile
import threading
import traceback
import types
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import fcntl
import warnings


from casp.utils import config
from casp.utils import container
from casp.utils import docker_utils
from casp.utils import remote_utils
import click
from google.cloud import storage
import google.auth
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request

# Imports do contexto
from clusterfuzz._internal.base import utils
from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.build_management import build_manager
from clusterfuzz._internal.system import environment as system_environment
from google.cloud import storage as gcs
from google.oauth2 import service_account




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


def generate_signed_url(bucket_name, blob_name, expiration=3600, key_file=None, impersonate_service_account=None):
    """Generates a v4 signed URL for a blob."""
    if key_file:
        credentials = service_account.Credentials.from_service_account_file(key_file)
        storage_client = gcs.Client(credentials=credentials)
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        url = blob.generate_signed_url(
            version="v4",
            # This URL is valid for 1 hour
            expiration=timedelta(seconds=expiration),
            # Allow GET requests using this URL.
            method="GET",
        )
        return url
    else:
        # Use Python API for robust signed URL generation
        try:
            # Get default credentials
            creds, project = google.auth.default()
            
            # Handle impersonation if requested
            if impersonate_service_account:
                # Create impersonated credentials
                # We need the 'https://www.googleapis.com/auth/cloud-platform' scope usually
                target_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
                creds = impersonated_credentials.Credentials(
                    source_credentials=creds,
                    target_principal=impersonate_service_account,
                    target_scopes=target_scopes,
                    lifetime=expiration + 300
                )
            
            # Create client with credentials
            client = storage.Client(credentials=creds, project=project)
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(blob_name)
            
            # Generate signed URL
            # If we are impersonating, the credentials object handles the signing via IAM API automatically
            # when using blob.generate_signed_url with version='v4' and proper credentials.
            # However, generate_signed_url might require service_account_email argument to trigger IAM signing
            # if the credentials don't have a private key (which impersonated creds don't).
            # BUT, google-cloud-storage >= 2.0 should handle this if credentials are provided.
            # Let's try passing service_account_email if impersonating.
            
            signing_email = impersonate_service_account if impersonate_service_account else None
            # If not impersonating, we might be running as a user or SA.
            # If user, we can't sign locally without key.
            # If SA, we can sign locally if we have key, or use IAM if we don't.
            # If we are a user, we usually need to use IAM API to sign.
            # blob.generate_signed_url checks if credentials can sign.
            
            # If we are using ADC as a user, we might need to specify service_account_email to force IAM signing?
            # Actually, if we don't have a private key, we MUST use IAM signing.
            # For that, we need to pass `service_account_email`.
            # If we are impersonating, `signing_email` is the target SA.
            # If we are just a user, we might not have a "service account email" to pass unless we are acting as one?
            # But wait, the user's command uses --impersonate-service-account.
            # So we definitely have an email.
            
            kwargs = {
                "version": "v4",
                "expiration": timedelta(seconds=expiration),
                "method": "GET",
            }
            # service_account_email is not supported in some versions, and access_token neither.
            # We rely on the client credentials (impersonated) to handle signing.
            
            print("DEBUG: Calling blob.generate_signed_url...")
            url = blob.generate_signed_url(**kwargs)
            return url
            
        except Exception as e:
            print(f"Failed to generate signed URL via Python API: {e}")
            print("Attempting fallback to gcloud storage sign-url...")
            try:
                # Fallback to gcloud
                # gcloud storage sign-url gs://bucket/blob --duration=1h
                gcloud_cmd = [
                    'gcloud', 'storage', 'sign-url', 
                    f'gs://{bucket_name}/{blob_name}', 
                    f'--duration={expiration}s'
                ]
                
                if impersonate_service_account:
                    gcloud_cmd.append(f'--impersonate-service-account={impersonate_service_account}')
                    
                url = subprocess.check_output(gcloud_cmd, text=True).strip()
                return url
            except subprocess.CalledProcessError as gcloud_error:
                print(f"Failed to generate signed URL via gcloud: {gcloud_error}")
                raise e





# --- REPRODUCTION STRATEGIES ---
class ReproductionStrategy:
  """Base class for reproduction strategies."""
  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int, testcase=None, testcase_url=None, target_binary=None, fuzzer_args=None, job_env=None) -> bool:
    raise NotImplementedError


class LocalReproductionStrategy(ReproductionStrategy):
  def __init__(self, base_binds: Dict, container_config_dir: Optional[str],
               local_build_dir: Optional[str], docker_image: str,
               gcs_build_uri: Optional[str] = None, gcs_bucket: Optional[str] = None, key_file: Optional[str] = None, impersonate_service_account: Optional[str] = None):
    self.base_binds = base_binds
    self.container_config_dir = container_config_dir
    self.local_build_dir = local_build_dir
    self.docker_image = docker_image
    self.gcs_build_uri = gcs_build_uri
    self.gcs_bucket = gcs_bucket
    self.key_file = key_file
    self.impersonate_service_account = impersonate_service_account


  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int, testcase=None, testcase_url=None, target_binary=None, fuzzer_args=None, job_env=None, extra_volumes=None) -> bool:
    with open(log_file_path, 'a', encoding='utf-8', errors='ignore') as log_f:
      sys.stdout = log_f
      sys.stderr = log_f

      def file_logger(line):
        if line:
          print(line)
          sys.stdout.flush()

      try:
        binds = self.base_binds.copy()
        if extra_volumes:
            binds.update(extra_volumes)
        target_builds_root = '/data/clusterfuzz/bot/builds'
        
        # Parse environment to get RELEASE_BUILD_BUCKET_PATH
        env = {}
        if job:
            for line in job.get_environment_string().splitlines():
              if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                env[k.strip()] = v.strip()
        
        # If job is None, try to use job_env
        if not env and job_env:
            env = job_env.copy()
            
        release_build_bucket_path = env.get('RELEASE_BUILD_BUCKET_PATH')
        
        if not release_build_bucket_path and self.gcs_build_uri:
            # Try to derive from gcs_build_uri
            # e.g. gs://clusterfuzz-builds/project/build.zip -> gs://clusterfuzz-builds/project
            parts = self.gcs_build_uri.rsplit('/', 1)
            if len(parts) > 0:
                release_build_bucket_path = parts[0]
                print(f"Derived RELEASE_BUILD_BUCKET_PATH from gcs_build_uri: {release_build_bucket_path}")


        env_vars = {
            'ROOT_DIR': '/data/clusterfuzz',
            'CASP_STRUCTURED_LOGGING': '1',
            'PYTHONUNBUFFERED': '1',
            'PYTHONWARNINGS': 'ignore',
            'TEST_BOT_ENVIRONMENT': '1',
            'PYTHONPATH': '/data/clusterfuzz/src:/data/clusterfuzz/src/third_party',
            'BUILDS_DIR': target_builds_root,
        }

        print(f"DEBUG: local_build_dir={self.local_build_dir}, gcs_build_uri={self.gcs_build_uri}, release_build_bucket_path={release_build_bucket_path}")
        
        target_build_dir = None
        setup_commands = []

        if self.local_build_dir:
            # Local Volume Flow
            if release_build_bucket_path:
                target_build_dir = _get_build_directory(release_build_bucket_path,
                                                        job.name, target_builds_root)
            else:
                # Fallback if we can't determine the exact build dir
                target_build_dir = os.path.join(target_builds_root, 'reproduction')
                
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
                actual_build_dir = host_temp_dir
                if os.path.isdir(os.path.join(host_temp_dir, 'upload')):
                    actual_build_dir = os.path.join(host_temp_dir, 'upload')
            elif self.gcs_build_uri.endswith('.zip'):
                # Download zip and extract
                zip_path = os.path.join(host_temp_dir, 'build.zip')
                subprocess.run(['gsutil', 'cp', self.gcs_build_uri, zip_path], check=True)
                subprocess.run(['unzip', '-q', zip_path, '-d', host_temp_dir], check=True)
                os.remove(zip_path)
                actual_build_dir = host_temp_dir
            else:
                # Direct directory copy
                subprocess.run(['gsutil', '-m', 'cp', '-r', f'{self.gcs_build_uri}/*', host_temp_dir], check=True)
                actual_build_dir = host_temp_dir

            
            # 3. Mount host temp dir to /mnt/shared/build in container
            binds[actual_build_dir] = {'bind': '/mnt/shared/build', 'mode': 'rw'}
            
            target_build_dir = _get_build_directory(release_build_bucket_path,
                                                    job.name, target_builds_root)
            setup_commands.append(f"mkdir -p {target_build_dir}")
            setup_commands.append(f"ln -s /mnt/shared/build/* {target_build_dir}/")
            setup_commands.append(f"echo {crash_revision} > {target_build_dir}/REVISION")
        
        if testcase_url:
            # Signed URL Flow (Bypass butler.py)
            print(f"Using Signed URL flow for LocalReproductionStrategy")
            
            # 1. Download testcase
            if testcase_url.startswith('file://'):
                print(f"Skipping download for local testcase: {testcase_url}")
                download_cmd = "true"
            else:
                download_cmd = f"curl -L -o /tmp/testcase '{testcase_url}'"
            
            # 2. Prepare Fuzzer Command
            # We need target_build_dir. It was calculated above.
            if not target_build_dir:
                print("Error: target_build_dir is not set. Cannot proceed with Signed URL flow.")
                return False
                
            fuzzer_path = f"{target_build_dir}/{target_binary}"

            chmod_cmd = f"chmod +x {fuzzer_path}"
            
            # 3. Env Vars
            # We need to set them in the container.
            # job_env is passed to execute.
            if job_env:
                env_vars.update(job_env)
            
            # Set OUT to target_build_dir for reproduce script
            env_vars['OUT'] = target_build_dir
            
            # Set TESTCASE env var for reproduce script
            env_vars['TESTCASE'] = '/tmp/testcase'
            
            # Set FUZZER_ARGS to empty string if not set, as run_fuzzer expects it (set -u)
            env_vars['FUZZER_ARGS'] = env_vars.get('FUZZER_ARGS', '')
            
            # ASAN Options
            env_vars['ASAN_OPTIONS'] = env_vars.get('ASAN_OPTIONS', '') + ':symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer'
            
            # 4. Artifacts (Container-side detection)
            # We create a dir in container, run fuzzer, then check if dir is not empty.
            # If not empty -> Exit 0 (Success)
            # If empty -> Exit 1 (Failure)
            
            artifacts_dir = "/tmp/artifacts"
            setup_artifacts_cmd = f"mkdir -p {artifacts_dir}"
            
            if fuzzer_args:
                fuzzer_args += f" -artifact_prefix={artifacts_dir}/"
            else:
                fuzzer_args = f"-artifact_prefix={artifacts_dir}/"

            # Mount modified butler.py and reproduce.py to ensure we use the local versions with our changes
            # We assume the script is running from within the clusterfuzz repo or we can find it.
            # For now, let's assume we are in the root of the repo or close to it.
            # Actually, we can use the location of this file to find the root.
            # This file is in cli/casp/src/casp/commands/reproduce_project.py
            # Root is ../../../../../../..
            
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../../../..'))
            butler_path = os.path.join(repo_root, 'butler.py')
            reproduce_py_path = os.path.join(repo_root, 'src/local/butler/reproduce.py')
            
            if os.path.exists(butler_path):
                binds[butler_path] = {'bind': '/data/clusterfuzz/butler.py', 'mode': 'ro'}
            if os.path.exists(reproduce_py_path):
                binds[reproduce_py_path] = {'bind': '/data/clusterfuzz/src/local/butler/reproduce.py', 'mode': 'ro'}

            # Command to run
            # We use python3 to run butler.py
            # We pass target binary path and testcase path
            # target_binary is just the name, so we prepend OUT (which is target_build_dir)
            # testcase is at /tmp/testcase
            
            # We need job name.
            job_name = job.name if job else 'libfuzzer_asan' # Fallback?
            
            run_cmd = (
                f"cd /data/clusterfuzz && python3 butler.py reproduce "
                f"--testcase-path /tmp/testcase "
                f"--target-name {target_binary} "
                f"--job-name {job_name} "
                f"--revision {crash_revision} "
                f"--build-dir {target_build_dir} "
                f"--config-dir {self.container_config_dir or '/data/clusterfuzz/src/appengine/config'}"
            )
            
            # Ensure python3 is available (it should be)
            
            # We still need setup_commands, download_cmd, chmod_cmd, setup_artifacts_cmd
            
            cmd_str = f"{' && '.join(setup_commands)} && {download_cmd} && {chmod_cmd} && {setup_artifacts_cmd} && {run_cmd}"
            
            print(f"DEBUG: cmd_str: {cmd_str}")


            
        elif setup_commands:
            cmd_str = f"{' && '.join(setup_commands)} && cd /data/clusterfuzz && python3.11 butler.py --local-logging reproduce --testcase-id={tc_id}"
        else:
            cmd_str = f"cd /data/clusterfuzz && python3.11 butler.py --local-logging reproduce --testcase-id={tc_id}"

        
        if self.container_config_dir:
          cmd_str += f' --config-dir={self.container_config_dir}'
        
        # Use bash instead of sh to ensure better compatibility and PATH handling
        cmd = ['/bin/bash', '-c', cmd_str]

        success = docker_utils.run_command(
            cmd, binds, self.docker_image, privileged=True,
            environment_vars=env_vars, log_callback=file_logger, silent=True)
        
        log_f.flush()
        
        # Analyze log with ClusterFuzz stack_analyzer
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f_read:
            log_content = f_read.read()

        # Mock ProjectConfig to avoid config loading errors if not already mocked
        # We do this here to ensure it applies before stack_analyzer is used
        try:
            from clusterfuzz._internal.config import local_config
            from unittest.mock import MagicMock
            if not isinstance(local_config.ProjectConfig, MagicMock):
                 mock_config = MagicMock()
                 mock_config.get.return_value = []
                 local_config.ProjectConfig = MagicMock(return_value=mock_config)
        except ImportError:
            pass # Should not happen if PYTHONPATH is correct

        from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
        from clusterfuzz._internal.crash_analysis import crash_analyzer

        # Parse crash data
        crash_info = stack_analyzer.get_crash_data(log_content, symbolize_flag=False)

        if crash_info.crash_type:
            print(f"Success: ClusterFuzz detected crash type: {crash_info.crash_type}")
            print(f"Crash State:\n{crash_info.crash_state}")
            return True
        
        # Also check if it's a crash based on return code and output (for cases without stack trace)
        # We assume return code 0 is success (no crash) unless artifacts found, but here we rely on analysis.
        # If stack_analyzer didn't find anything, maybe it's a startup crash or something else.
        # crash_analyzer.is_crash checks return code.
        # We don't have the exact return code from the fuzzer process easily available here 
        # because we ran with `|| true`.
        # But we can check for generic crash signatures if stack_analyzer failed.
        
        if crash_analyzer.is_crash(1, log_content): # Pass 1 to force check content
             # is_crash returns True if it looks like a crash.
             # But is_crash is very broad.
             # Let's trust stack_analyzer primarily.
             pass

        return False
      except Exception as e:
        print(f"CRITICAL EXCEPTION in local worker for TC-{tc_id}: {e}")
        return False
      finally:
        # Cleanup host temp dir if created

        if 'host_temp_dir' in locals() and os.path.exists(host_temp_dir):
            import shutil
            shutil.rmtree(host_temp_dir)

    return False

class GCBReproductionStrategy(ReproductionStrategy):
  def __init__(self, docker_image: str, gcs_build_uri: Optional[str], project_id: str, os_version: str, gcs_bucket: Optional[str] = None, key_file: Optional[str] = None, impersonate_service_account: Optional[str] = None):
    self.docker_image = docker_image
    self.gcs_build_uri = gcs_build_uri
    self.project_id = project_id
    self.os_version = os_version
    self.gcs_bucket = gcs_bucket
    self.key_file = key_file
    self.impersonate_service_account = impersonate_service_account

  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int, testcase=None, testcase_url=None, target_binary=None, fuzzer_args=None, job_env=None) -> bool:
    if not testcase_url:
        print(f"Error: testcase_url is required for GCBReproductionStrategy")
        return False

    # Construct Cloud Build YAML
    # We need to run the same steps as Batch:
    # 1. Setup (download build)
    # 2. Download testcase (via Signed URL)
    # 3. Run fuzzer
    
    # Cloud Build steps run sequentially in the same workspace (/workspace).
    # We can use a single step with the fuzzer image if it has gsutil/curl, 
    # or multiple steps.
    # ClusterFuzz images usually have gsutil and curl.
    
    # We need to handle the build download.
    # If gcs_build_uri is provided, we download it.
    
    steps = []
    
    # Step 1: Setup and Run
    # We can combine everything in one script to share state easily (like build dir)
    # or use /workspace which is shared.
    
    # We need to set up environment variables.
    env_vars = {
        'ROOT_DIR': '/data/clusterfuzz',
        'CASP_STRUCTURED_LOGGING': '1',
        'PYTHONUNBUFFERED': '1',
        'PYTHONWARNINGS': 'ignore',
        'TEST_BOT_ENVIRONMENT': '1',
        'PYTHONPATH': '/data/clusterfuzz/src:/data/clusterfuzz/src/third_party',
        'GOOGLE_CLOUD_PROJECT': self.project_id,
    }
    
    if job_env:
        env_vars.update(job_env)
        
    # Override specific vars
    env_vars['ASAN_OPTIONS'] = env_vars.get('ASAN_OPTIONS', '') + ':symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer'
    
    # Construct the script
    script_lines = []
    
    # Create directories
    target_builds_root = '/data/clusterfuzz/bot/builds'
    # We might not have permission to write to /data in Cloud Build default user?
    # Cloud Build runs as root by default (or the user in Dockerfile).
    # ClusterFuzz images usually run as root or have permissions.
    # Let's assume we can write to /workspace and symlink or just use /workspace.
    # But ClusterFuzz expects specific paths?
    # Actually, we can set BUILDS_DIR to /workspace/builds
    
    env_vars['BUILDS_DIR'] = '/workspace/builds'
    script_lines.append("mkdir -p /workspace/builds")
    
    # Download Build
    if self.gcs_build_uri:
        # Parse environment to get RELEASE_BUILD_BUCKET_PATH
        env = {}
        for line in job.get_environment_string().splitlines():
          if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
        release_build_bucket_path = env.get('RELEASE_BUILD_BUCKET_PATH')
        
        target_build_dir = "/workspace/builds/repro" # Simplified path
        if release_build_bucket_path:
             # We try to mimic the structure if needed, but for repro, any dir works if we point to it
             pass
             
        script_lines.append(f"mkdir -p {target_build_dir}")
        
        if self.gcs_build_uri.endswith('.tar.gz'):
            script_lines.append(f"gsutil cp {self.gcs_build_uri} /workspace/build.tar.gz")
            script_lines.append(f"tar -xzf /workspace/build.tar.gz -C {target_build_dir}")
            # Handle upload dir
            script_lines.append(f"if [ -d {target_build_dir}/upload ]; then mv {target_build_dir}/upload/* {target_build_dir}/ && rmdir {target_build_dir}/upload; fi")
            script_lines.append("rm /workspace/build.tar.gz")
        elif self.gcs_build_uri.endswith('.zip'):
            script_lines.append(f"gsutil cp {self.gcs_build_uri} /workspace/build.zip")
            script_lines.append(f"unzip -q /workspace/build.zip -d {target_build_dir}")
            script_lines.append("rm /workspace/build.zip")
        else:
            script_lines.append(f"gsutil -m cp -r {self.gcs_build_uri}/* {target_build_dir}/")
            
        script_lines.append(f"echo {crash_revision} > {target_build_dir}/REVISION")
    else:
        # No build URI?
        target_build_dir = "/workspace/builds/unknown"
        script_lines.append(f"mkdir -p {target_build_dir}")

    # Download Testcase
    script_lines.append(f"curl -L -o /workspace/testcase '{testcase_url}'")
    
    # Run Fuzzer
    # Set OUT to target_build_dir so run_fuzzer knows where to find binaries
    env_vars['OUT'] = target_build_dir
    
    # Use the reproduce script which handles environment setup (ASAN_OPTIONS, etc.)
    # Usage: reproduce <fuzzer_name> <args> <testcase_path>
    # We pass fuzzer_args as separate arguments if possible, or as a string if reproduce handles it.
    # reproduce script: run_fuzzer $FUZZER $@ $TESTCASE
    # run_fuzzer script: FUZZER=$1; shift; ... $OUT/$FUZZER ...
    
    # We need to ensure fuzzer_args are passed correctly.
    # fuzzer_args is a string, we should split it if we want to pass as args, 
    # but shell splitting in the script string is also fine.
    
    script_lines.append(f"reproduce {target_binary} {fuzzer_args} /workspace/testcase")
    
    # reproduce script exits with the exit code of run_fuzzer.
    # run_fuzzer usually exits with 0 if it runs (even if crash found? No, libFuzzer exits with 1 on crash).
    # Wait, run_fuzzer script:
    # bash -c "$CMD_LINE"
    # If libFuzzer finds a crash, it exits with 1.
    # If it runs successfully (no crash), it exits with 0 (or 1 if timeout?).
    # Actually libFuzzer exits with 0 if -runs=N finishes without crash.
    # So:
    # Exit 0 -> No crash (Failure for us)
    # Exit 1 -> Crash (Success for us)
    
    script_lines.append("EXIT_CODE=$?")
    script_lines.append("echo \"reproduce exited with code $EXIT_CODE\"")
    
    script_lines.append("if [ $EXIT_CODE -ne 0 ]; then")
    script_lines.append("  echo \"Reproduction succeeded (crash detected).\"")
    script_lines.append("  exit 0")
    script_lines.append("else")
    script_lines.append("  echo \"Reproduction failed (no crash detected).\"")
    script_lines.append("  exit 1")
    script_lines.append("fi")
    
    # Construct the step
    step = {
        'name': self.docker_image,
        'script': "\n".join(script_lines),
        'env': [f"{k}={v}" for k, v in env_vars.items()],
        # We need to ensure we have gsutil and curl. 
        # Most CF images have them.
    }
    
    cloudbuild_yaml = {
        'steps': [step],
        'timeout': '3600s',
        'options': {
            'logging': 'CLOUD_LOGGING_ONLY', # Privacy!
            'machineType': 'E2_HIGHCPU_8' # Reasonable power
        }
    }
    
    # Tags
    tags = [
        'casp-repro',
        f'project-{testcase.project_name}',
        f'tc-{tc_id}',
        'private'
    ]
    
    # Submit build
    # We do NOT use impersonation for build submission, as the SA might not have permissions on the target project.
    # We use the default credentials (user) for submission.
    # We use a dedicated private bucket for logs if configured, or default to CLOUD_LOGGING_ONLY.
    # We'll use a subdirectory in the gcs_bucket if available, or a specific log bucket if we had one.
    # For now, let's assume we want to use a specific private bucket we just created: gs://casp-repro-logs-private-1764897405
    # Ideally this should be passed in __init__, but for this fix we'll hardcode or derive it.
    # Let's use the gcs_bucket passed to CLI if it's safe, or the one we created.
    # The user asked to be careful.
    gcs_log_dir = "gs://casp-repro-logs-private-1764897405/logs"
    
    success, logs = remote_utils.submit_and_monitor_build(self.project_id, cloudbuild_yaml, tags, log_file_path=log_file_path, gcs_log_dir=gcs_log_dir)
    
    # Analyze logs with stack_analyzer
    try:
        from clusterfuzz._internal.config import local_config
        from unittest.mock import MagicMock
        if not isinstance(local_config.ProjectConfig, MagicMock):
             mock_config = MagicMock()
             mock_config.get.return_value = []
             local_config.ProjectConfig = MagicMock(return_value=mock_config)
    except ImportError:
        pass 

    from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
    from clusterfuzz._internal.crash_analysis import crash_analyzer

    crash_info = stack_analyzer.get_crash_data(logs, symbolize_flag=False)

    if crash_info.crash_type:
        print(f"Success: ClusterFuzz detected crash type: {crash_info.crash_type}")
        print(f"Crash State:\n{crash_info.crash_state}")
        return True
    
    if crash_analyzer.is_crash(1, logs):
         pass

    return False

  def generate_build_steps(self, project_name: str, project_yaml: Dict, project_src_uri: Optional[str] = None, workdir: str = None) -> Tuple[List[Dict], Dict[str, str]]:
      """
      Generates Cloud Build steps to build the project for all combinations.
      Returns a list of steps and a mapping of (engine, sanitizer, architecture) -> build_dir.
      """
      steps = []
      build_map = {}
      
      # Parse project.yaml
      engines = project_yaml.get('fuzzing_engines', ['libfuzzer'])
      sanitizers = project_yaml.get('sanitizers', ['address'])
      architectures = project_yaml.get('architectures', ['x86_64'])
      
      # Step 0: Clone OSS-Fuzz
      steps.append({
          'name': 'gcr.io/cloud-builders/git',
          'args': ['clone', '--depth', '1', 'https://github.com/google/oss-fuzz.git', '/workspace/oss-fuzz'],
          'id': 'clone-oss-fuzz'
      })
      
      # Step 0.1: Clone ClusterFuzz (for reproduction verification)
      steps.append({
          'name': 'gcr.io/cloud-builders/git',
          'args': ['clone', '--depth', '1', 'https://github.com/google/clusterfuzz.git', '/workspace/clusterfuzz'],
          'waitFor': ['clone-oss-fuzz'], # Run after oss-fuzz clone to avoid concurrency issues on git? No, parallel is fine but let's be safe.
          'id': 'clone-clusterfuzz'
      })
      
      # Step 0.5: Download and overlay local project source if provided
      if project_src_uri:
          # We assume project_src_uri is a tar.gz of the project directory
          # We want to extract it to /workspace/oss-fuzz/projects/{project_name}
          # The tarball created by upload_to_gcs usually contains the directory itself at root if we tarred the dir.
          # remote_utils.upload_to_gcs uses tar -czf ... -C parent dir ... basename
          # So it contains {project_name}/...
          # So if we extract to /workspace/oss-fuzz/projects/, it should overwrite {project_name} correctly.
          
          steps.append({
              'name': 'gcr.io/cloud-builders/gsutil',
              'script': f"""
                gsutil cp {project_src_uri} /workspace/project_src.tar.gz
                # Remove existing project dir to ensure clean overlay or just overwrite?
                # Overwriting is safer to keep other files if any (though clone is fresh).
                # But if we want to be sure we use OUR files, we can just extract.
                tar -xzf /workspace/project_src.tar.gz -C /workspace/oss-fuzz/projects/
                rm /workspace/project_src.tar.gz
              """,
              'waitFor': ['clone-oss-fuzz'],
              'waitFor': ['clone-oss-fuzz'],
              'id': 'overlay-project-src'
          })
      
      # Step 0.6: Auto-migrate to Ubuntu 24.04 (if requested or always?)
      # The user said "precisamos garantir que tenhamos o Dockerfile com a regra correta... e coloar o ubuntu-24 no project.yaml"
      # We should do this for ALL projects running in this flow, as the goal is to verify migration.
      
      project_dir = f"/workspace/oss-fuzz/projects/{project_name}"
      
      build_image_wait_for = ['clone-oss-fuzz']
      if project_src_uri:
          build_image_wait_for.append('overlay-project-src')
      
      steps.append({
          'name': 'ubuntu',
          'script': f"""
            # 1. Update project.yaml
            if grep -q "base_os_version:" {project_dir}/project.yaml; then
              sed -i 's/base_os_version:.*/base_os_version: ubuntu-24-04/' {project_dir}/project.yaml
            else
              echo "base_os_version: ubuntu-24-04" >> {project_dir}/project.yaml
            fi
            
            # 2. Update Dockerfile
            # Replace FROM ...base-builder... with ...base-builder:ubuntu-24-04
            # We use a regex to capture the image name but change the tag.
            # Or simpler: just replace the line if it matches standard patterns.
            # Standard pattern: FROM gcr.io/oss-fuzz-base/base-builder
            # We want: FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
            
            sed -i 's|FROM gcr.io/oss-fuzz-base/base-builder\\([^: ]*\\).*|FROM gcr.io/oss-fuzz-base/base-builder\\1:ubuntu-24-04|g' {project_dir}/Dockerfile
            sed -i 's|FROM gcr.io/oss-fuzz-base/base-runner\\([^: ]*\\).*|FROM gcr.io/oss-fuzz-base/base-runner\\1:ubuntu-24-04|g' {project_dir}/Dockerfile
            
            echo "--- Auto-migrated project.yaml and Dockerfile to Ubuntu 24.04 ---"
            cat {project_dir}/project.yaml
            head -n 5 {project_dir}/Dockerfile
          """,
          'waitFor': build_image_wait_for,
          'id': 'auto-migrate'
      })
      
      # Update wait dependencies for build-image
      build_image_wait_for = ['auto-migrate']
      
      steps.append({
          'name': 'gcr.io/cloud-builders/docker',
          'args': ['build', '-t', f'gcr.io/oss-fuzz/{project_name}', project_dir],
          'waitFor': build_image_wait_for,
          'id': 'build-image'
      })
      
      # Step 2: Compile for each combination.
      for engine in engines:
          for sanitizer in sanitizers:
              for arch in architectures:
                  # We only support x86_64 for now in standard GCB (unless we use specific workers).
                  if arch != 'x86_64':
                      continue
                      
                  # Build ID
                  build_id = f"build-{engine}-{sanitizer}"
                  
                  # Output dir for this build
                  out_dir = f"/workspace/builds/{engine}/{sanitizer}"
                  steps.append({
                      'name': 'ubuntu', # Lightweight step to create dir
                      'script': f"mkdir -p {out_dir}",
                      'waitFor': ['build-image'],
                      'id': f"mkdir-{build_id}"
                  })
                  
                  steps.append({
                      'name': f'gcr.io/oss-fuzz/{project_name}',
                      'args': [
                          'bash', '-c',
                        f'cd {workdir} && compile' if workdir else f'cd /src && if [ -d "{project_name}" ]; then cd "{project_name}"; fi && if [ ! -f "build.sh" ]; then cd $(dirname $(find . -maxdepth 2 -name build.sh | head -n 1)); fi && compile'
                    ],
                      'env': [
                          f'FUZZING_ENGINE={engine}',
                          f'SANITIZER={sanitizer}',
                          f'ARCHITECTURE={arch}',
                          f'OUT={out_dir}',
                          f'FUZZING_LANGUAGE={project_yaml.get("language", "c++")}',
                          'CIFUZZ=True' # To avoid some local checks?
                      ],
                      'waitFor': ['build-image', f"mkdir-{build_id}"],
                      'id': build_id
                  })
                  
                  build_map[(engine, sanitizer, arch)] = out_dir
                  
      return steps, build_map

  def get_workdir_from_dockerfile(self, dockerfile_path: str) -> str:
    """Extracts the last WORKDIR from Dockerfile and resolves $SRC."""
    workdir = None
    try:
      with open(dockerfile_path, 'r') as f:
        for line in f:
          line = line.strip()
          if line.upper().startswith('WORKDIR '):
            workdir = line[8:].strip()
    except FileNotFoundError:
      return None

    if workdir:
      # Resolve $SRC
      workdir = workdir.replace('$SRC', '/src')
      if not workdir.startswith('/'):
        workdir = f'/src/{workdir}'
      return workdir
    return None

  def reproduce_batch(self, testcases_data: List[Dict], log_dir: str, project_name: str = None, tag: str = None, async_mode: bool = False) -> Dict[str, bool]:
    """
    Submits a single Cloud Build with multiple steps for all testcases.
    Returns a dict mapping tc_id to success boolean.
    """
    if not testcases_data and not project_name:
      return {}

    # Common setup (build download)
    if not project_name:
      first_tc = testcases_data[0]
      project_name = first_tc['project_name'] # We assume all are same project
    
    # We need project.yaml to generate build steps.
    project_yaml_path = f"/usr/local/google/home/matheushunsche/projects/oss-fuzz/projects/{project_name}/project.yaml"
    if not os.path.exists(project_yaml_path):
        # Fallback to local path if running from CLI
        project_yaml_path = os.path.abspath(f"projects/{project_name}/project.yaml")
    
    if not os.path.exists(project_yaml_path):
        print(f"Error: Could not find project.yaml for {project_name}")
        return {}
        
    import yaml
    with open(project_yaml_path, 'r') as f:
        project_yaml = yaml.safe_load(f)
        
    # Check if we have local source to upload
    project_local_path = os.path.dirname(project_yaml_path)
    
    # Upload project source to GCS
    # We use a timestamped folder to avoid conflicts
    timestamp = int(time.time())
    gcs_path = f"repro-projects/{project_name}-{timestamp}.tar.gz"
    
    # Check if we should use upstream or local
    # For now, we always try to upload local if it exists
    project_src_uri = None
    workdir = None
    
    if self.gcs_bucket:
       if os.path.exists(project_local_path):
         try:
           print(f"Uploading local project source from {project_local_path}...")
           project_src_uri = remote_utils.upload_to_gcs(project_local_path, self.gcs_bucket, gcs_path)
           print(f"Uploaded project source to {project_src_uri}")
           
           # Extract WORKDIR
           dockerfile_path = os.path.join(project_local_path, 'Dockerfile')
           workdir = self.get_workdir_from_dockerfile(dockerfile_path)
           if workdir:
             print(f"Detected WORKDIR from Dockerfile: {workdir}")
         except Exception as e:
           print(f"Warning: Failed to upload project source: {e}")
       else:
         print(f"Warning: Local project path {project_local_path} not found. Using upstream.")
    
    steps, build_map = self.generate_build_steps(project_name, project_yaml, project_src_uri, workdir=workdir)
    
    # Embed verify_reproduction.py content
    verify_reproduction_script = r'''
import os
import sys
import json
import traceback

# Add ClusterFuzz source to path
sys.path.append(os.environ.get('ROOT_DIR', '/workspace'))
sys.path.append(os.path.join(os.environ.get('ROOT_DIR', '/workspace'), 'oss-fuzz/infra')) 
sys.path.append(os.path.join(os.environ.get('ROOT_DIR', '/workspace'), 'clusterfuzz/src'))

try:
    from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
    from clusterfuzz._internal.crash_analysis import crash_analyzer
    from clusterfuzz._internal.crash_analysis.crash_comparer import CrashComparer
    from clusterfuzz.stacktraces import StackParser
except ImportError:
    print("Warning: Could not import ClusterFuzz modules. Fallback to simple check.")
    stack_analyzer = None
    CrashComparer = None

def verify_reproduction(fuzzer_output, expected_crash_state, expected_crash_type, exit_code):
    """
    Verifies if the reproduction was successful using ClusterFuzz logic.
    """
    if not stack_analyzer:
        # Fallback: Check for crash state in output
        print("Fallback: ClusterFuzz modules not found.")
        
        # If we have an expected crash state, look for it
        if expected_crash_state and expected_crash_state.strip():
            if expected_crash_state in fuzzer_output:
                return True
            print(f"Fallback: Expected state '{expected_crash_state}' not found in output.")
        
        # If exit code indicates failure (crash), and we either didn't find state or didn't have one
        if exit_code != 0:
            print(f"Fallback: Exit code {exit_code} indicates crash/failure.")
            # If we had a specific state and didn't find it, strictly speaking it's a mismatch.
            # But often we accept any crash if we can't parse it.
            # However, for reproduction, we usually want the specific crash.
            # If we have NO expected state, then any crash is a success.
            if not expected_crash_state or not expected_crash_state.strip():
                return True
            
            # If we had expected state but didn't find it, we might still return True if we are lenient?
            # Let's be strict if state is provided.
            return False
            
        print("Fallback: No crash detected (Exit code 0) and state not found.")
        return False

    # Parse the stack trace
    crash_info = stack_analyzer.get_crash_data(fuzzer_output, symbolize_flag=False)

    print(f"Parsed Crash Type: {crash_info.crash_type}")
    print(f"Parsed Crash State: {crash_info.crash_state}")

    # Check if crash type matches (loose check)
    if expected_crash_type and expected_crash_type not in crash_info.crash_type:
        print(f"Mismatch: Expected type '{expected_crash_type}', got '{crash_info.crash_type}'")
    
    # Check if crash state matches using CrashComparer
    if expected_crash_state:
        if CrashComparer:
            comparer = CrashComparer(crash_info.crash_state, expected_crash_state)
            if comparer.is_similar():
                print("CrashComparer: Crash state is similar.")
                return True
            else:
                print("CrashComparer: Crash state is NOT similar.")
                return False
        else:
            # Fallback manual check
            parsed_state = crash_info.crash_state.strip()
            expected_state = expected_crash_state.strip()
            
            if parsed_state == expected_state:
                return True
                
            if expected_state in parsed_state or parsed_state in expected_state:
                return True
                
            print(f"Mismatch: Expected state '{expected_state}', got '{parsed_state}'")
            return False
        
    # If no expected state, but we parsed a crash, return True?
    # Or check exit code?
    if crash_info.crash_type:
        return True
        
    return exit_code != 0

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: verify_reproduction.py <log_file> <expected_state> <expected_type> <exit_code>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    expected_state = sys.argv[2]
    expected_type = sys.argv[3]
    try:
        exit_code = int(sys.argv[4])
    except ValueError:
        exit_code = 0
    
    with open(log_file, 'r', errors='replace') as f:
        content = f.read()
        
    if verify_reproduction(content, expected_state, expected_type, exit_code):
        print("VERIFICATION_SUCCESS")
        sys.exit(0)
    else:
        print("VERIFICATION_FAILURE")
        sys.exit(1)
'''

    # Step 1: Setup (Directories and Scripts)
    setup_script = []
    setup_script.append("mkdir -p /workspace/testcases")
    setup_script.append("mkdir -p /workspace/artifacts") 
    setup_script.append("mkdir -p /workspace/status") # Directory for status files
    
    # Clone ClusterFuzz for verification logic
    # setup_script.append("git clone https://github.com/google/clusterfuzz.git /workspace/clusterfuzz")
    # ALREADY CLONED in step clone-clusterfuzz
    
    # Write verify_reproduction.py
    setup_script.append("cat <<EOF > /workspace/verify_reproduction.py")
    setup_script.append(verify_reproduction_script)
    setup_script.append("EOF")
    
    steps.append({
      'name': 'ubuntu',
      'script': "\n".join(setup_script),
      'id': 'setup-dirs',
      'waitFor': ['clone-clusterfuzz']
    })
    
    env_vars = {
      'ROOT_DIR': '/workspace', # Changed to /workspace as we clone there
      'CASP_STRUCTURED_LOGGING': '1',
      'PYTHONUNBUFFERED': '1',
      'TEST_BOT_ENVIRONMENT': '1',
      'PYTHONPATH': '/workspace/clusterfuzz/src:/workspace/clusterfuzz/src/third_party', # Updated pythonpath
      'GOOGLE_CLOUD_PROJECT': self.project_id,
      'BUILDS_DIR': '/workspace/builds'
    }
    
    env_vars['ASAN_OPTIONS'] = 'symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer'

    # Steps for each testcase
    for tc in testcases_data:
      tc_id = tc.get('tc_id', tc.get('id'))
      if tc_id == 'build-only':
          print("Skipping reproduction steps for build-only job.")
          continue

      tc_url = tc['testcase_url']
      target_binary = tc['target_binary']
      fuzzer_args = tc['fuzzer_args']
      crash_state = tc.get('crash_state', '')
      crash_type = tc.get('crash_type', '')
      
      # Determine which build to use
      job_env = tc.get('job_env', {})
      engine = job_env.get('FUZZING_ENGINE', 'libfuzzer')
      sanitizer = job_env.get('SANITIZER', 'address')
      arch = 'x86_64' # Default
      
      # Find the build dir
      build_dir = build_map.get((engine, sanitizer, arch))
      if not build_dir:
        print(f"Warning: No build found for {engine}/{sanitizer}/{arch}. Skipping TC-{tc_id}.")
        continue
        
      build_id = f"build-{engine}-{sanitizer}"
      
      tc_script = []
      tc_script.append(f"echo '--- Starting reproduction for Testcase ID: {tc_id} ---'")
      
      # Download Testcase
      tc_path = f"/workspace/testcases/{tc_id}"
      tc_script.append(f"curl -L -o {tc_path} '{tc_url}'")
      tc_script.append("if [ $? -ne 0 ]; then")
      tc_script.append(f"  echo \"TC-{tc_id} RESULT: DOWNLOAD_FAILED\"")
      tc_script.append(f"  echo '{{\"result\": \"DOWNLOAD_FAILED\", \"tc_id\": \"{tc_id}\"}}' > /workspace/status/{tc_id}.json")
      tc_script.append("  exit 1")
      tc_script.append("fi")
      
      # Run Fuzzer
      fuzzer_path = f"{build_dir}/{target_binary}"
      
      # Check if binary exists (Build might have failed)
      tc_script.append(f"if [ ! -f {fuzzer_path} ]; then")
      tc_script.append(f"  echo \"TC-{tc_id} RESULT: BUILD_FAILED (Binary not found)\"")
      tc_script.append(f"  echo '{{\"result\": \"BUILD_FAILED\", \"tc_id\": \"{tc_id}\"}}' > /workspace/status/{tc_id}.json")
      tc_script.append(f"  exit 1") # Fail step if binary missing
      tc_script.append(f"fi")
      
      tc_script.append(f"chmod +x {fuzzer_path}")
      
      # Run Fuzzer
      tc_script.append("set +e")
      # Capture output to log file for verification
      log_file = f"/workspace/artifacts/tc-{tc_id}.log"
      tc_script.append(f"{fuzzer_path} -rss_limit_mb=2560 -timeout=60 {tc_path} > {log_file} 2>&1")
      tc_script.append("EXIT_CODE=$?")
      tc_script.append("set -e")
      
      tc_script.append(f"cat {log_file}") # Show log in build output
      
      # Verify Reproduction using Python script
      tc_script.append(f"echo 'Verifying reproduction...'")
      # Escape quotes for python script args
      safe_crash_state = crash_state.replace("'", "'\\''")
      safe_crash_type = crash_type.replace("'", "'\\''")
      
      tc_script.append("set +e")
      tc_script.append(f"python3 /workspace/verify_reproduction.py {log_file} '{safe_crash_state}' '{safe_crash_type}' $EXIT_CODE")
      tc_script.append("VERIFY_EXIT_CODE=$?")
      tc_script.append("set -e")
      
      tc_script.append(f"if [ $VERIFY_EXIT_CODE -eq 0 ]; then")
      tc_script.append(f"  echo \"TC-{tc_id} RESULT: REPRODUCED\"")
      tc_script.append(f"  echo '{{\"result\": \"REPRODUCED\", \"tc_id\": \"{tc_id}\"}}' > /workspace/status/{tc_id}.json")
      tc_script.append(f"else")
      tc_script.append(f"  echo \"TC-{tc_id} RESULT: FAILED_TO_REPRODUCE\"")
      tc_script.append(f"  echo '{{\"result\": \"FAILED_TO_REPRODUCE\", \"tc_id\": \"{tc_id}\"}}' > /workspace/status/{tc_id}.json")
      tc_script.append(f"fi")
      
      steps.append({
        'name': f'gcr.io/oss-fuzz/{project_name}',
        'script': "\n".join(tc_script),
        'env': [f"{k}={v}" for k, v in env_vars.items()],
        'waitFor': [build_id, 'setup-dirs'], 
        'id': f'repro-{tc_id}',
        'allowFailure': True 
      })

    # Summary Step
    summary_script = []
    summary_script.append("echo '--- REPRODUCTION SUMMARY ---'")
    summary_script.append("echo '[' > /workspace/artifacts/summary.json")
    summary_script.append("first=true")
    summary_script.append("for f in /workspace/status/*.json; do")
    summary_script.append("  if [ \"$first\" = true ]; then")
    summary_script.append("    first=false")
    summary_script.append("  else")
    summary_script.append("    echo ',' >> /workspace/artifacts/summary.json")
    summary_script.append("  fi")
    summary_script.append("  cat $f >> /workspace/artifacts/summary.json")
    summary_script.append("done")
    summary_script.append("echo ']' >> /workspace/artifacts/summary.json")
    summary_script.append("cat /workspace/artifacts/summary.json")
    
    # Check failure threshold (30%)
    summary_script.append("python3 -c '")
    summary_script.append("import json, sys")
    summary_script.append("try:")
    summary_script.append("  with open(\"/workspace/artifacts/summary.json\") as f: data = json.load(f)")
    summary_script.append("  total = len(data)")
    summary_script.append("  if total == 0:")
    summary_script.append("    print(\"Error: No reproduction results found (status files missing).\")")
    summary_script.append("    sys.exit(1)")
    summary_script.append("  failed = sum(1 for item in data if item[\"result\"] != \"REPRODUCED\")")
    summary_script.append("  fail_rate = failed / total")
    summary_script.append("  print(f\"Summary: Total={total}, Failed={failed}, Rate={fail_rate:.2%}\")")
    summary_script.append("  if fail_rate > 0.3:")
    summary_script.append("    print(\"Failure rate > 30%. Marking build as FAILED.\")")
    summary_script.append("    sys.exit(1)")
    summary_script.append("except Exception as e:")
    summary_script.append("  print(f\"Error checking threshold: {e}\")")
    summary_script.append("  sys.exit(1)")
    summary_script.append("'")
    
    steps.append({
        'name': 'python:3.9-slim',
        'script': "\n".join(summary_script),
        'id': 'summary',
        'waitFor': [f'repro-{tc.get("tc_id", tc.get("id"))}' for tc in testcases_data if tc.get("tc_id", tc.get("id")) != 'build-only'] # Wait for all repro steps
    })

    cloudbuild_yaml = {
      'steps': steps,
      'timeout': '43200s', # 12 hours
      'queueTtl': '86400s', # 24 hours queue wait time
      'options': {
        'logging': 'CLOUD_LOGGING_ONLY',
        'machineType': 'E2_HIGHCPU_32'
      }
    }
    
    tags = ['casp-repro-batch', 'private', project_name] + [f"tc-{tc.get('tc_id', tc.get('id'))}" for tc in testcases_data if tc.get('tc_id', tc.get('id')) != 'build-only']
    if tag:
        tags.append(tag)
    
    if len(tags) > 64:
      tags = tags[:64]

    gcs_log_dir = "gs://casp-repro-logs-private-1764897405/logs"
    
    print(f"Submitting batch build (with compilation) for {len(testcases_data)} testcases...")
    import yaml
    print("DEBUG: Generated Cloud Build YAML:")
    print(yaml.dump(cloudbuild_yaml))
    # return {} # Uncomment to skip submission
    
    success, logs = remote_utils.submit_and_monitor_build(self.project_id, cloudbuild_yaml, tags, gcs_log_dir=gcs_log_dir, async_mode=async_mode)
    
    if async_mode:
        if not success:
            print(f"Error submitting async build: {logs}")
            return {}

        # logs contains the JSON output of gcloud builds submit
        try:
            build_info = json.loads(logs)
            build_id = build_info.get('id')
            log_url = build_info.get('logUrl')
            print(f"Build submitted successfully. ID: {build_id}")
            print(f"Logs: {log_url}")
            
            # Save to JSON file
            submission_file = os.path.join(log_dir, 'repro_submissions.json')
            submission_data = {
                'project': project_name,
                'build_id': build_id,
                'log_url': log_url,
                'tag': tag,
                'timestamp': int(time.time())
            }
            
            # Append to file (list of objects)
            existing_data = []
            if os.path.exists(submission_file):
                try:
                    with open(submission_file, 'r') as f:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            existing_data = [existing_data]
                except:
                    pass
            
            existing_data.append(submission_data)
            
            with open(submission_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
                
            print(f"Submission recorded in {submission_file}")
            return {} # Return empty results as we don't have them yet
            
        except Exception as e:
            print(f"Error parsing async build output: {e}")
            print(f"Raw output: {logs}")
            return {}
    
    import re
    results = {}
    for tc in testcases_data:
      tc_id = tc['tc_id']
      # We use regex to match the actual output.
      # Updated to match the new format from verify_reproduction.py
      if re.search(rf"TC-{tc_id} RESULT: REPRODUCED", logs):
        results[tc_id] = True
      elif re.search(rf"TC-{tc_id} RESULT: BUILD_FAILED", logs):
        # We could mark this as a specific failure type if needed, but for now False is fine.
        # The user will see "Failed" in the summary.
        print(f"TC-{tc_id} failed to build (binary not found).")
        results[tc_id] = False
      elif re.search(rf"TC-{tc_id} RESULT: DOWNLOAD_FAILED", logs):
        print(f"TC-{tc_id} failed to download.")
        results[tc_id] = False
      else:
        results[tc_id] = False
          
    full_log_path = os.path.join(log_dir, f"batch-gcb-{int(time.time())}.log")
    with open(full_log_path, 'w') as f:
        f.write(logs)
    print(f"Full batch log saved to {full_log_path}")
    
    return results


class BatchReproductionStrategy(ReproductionStrategy):
  def __init__(self, docker_image: str, gcs_build_uri: Optional[str], project_id: str, os_version: str, container_config_dir: str = '/data/clusterfuzz/config', gcs_config_uri: Optional[str] = None, gcs_bucket: Optional[str] = None, key_file: Optional[str] = None, impersonate_service_account: Optional[str] = None):
    self.docker_image = docker_image
    self.gcs_build_uri = gcs_build_uri
    self.project_id = project_id
    self.os_version = os_version
    self.container_config_dir = container_config_dir
    self.gcs_config_uri = gcs_config_uri
    self.gcs_bucket = gcs_bucket
    self.key_file = key_file
    self.impersonate_service_account = impersonate_service_account



  def execute(self, tc_id: str, job, log_file_path: str, crash_revision: int, testcase=None, testcase_url=None, target_binary=None, fuzzer_args=None, job_env=None) -> bool:
    if not testcase_url:
        print(f"Error: testcase_url is required for BatchReproductionStrategy")
        return False

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
    
    # Custom command for Signed URL approach
    # We need to download the testcase from the signed URL
    # And then run the fuzzer with the args
    
    # Filter job_env to only include strings (sometimes they might be non-strings?)
    # And exclude some internal ones if needed
    
    # We'll pass job_env as env_vars to the batch job, so they are already set!
    # We just need to add the ones we extracted from job.get_environment_string()
    
    # Merge job_env into env_vars
    if job_env:
        env_vars.update(job_env)
        
    # Override specific vars for Batch
    env_vars['ASAN_OPTIONS'] = env_vars.get('ASAN_OPTIONS', '') + ':symbolize=1:external_symbolizer_path=/usr/bin/llvm-symbolizer'
    
    # Download command
    download_cmd = f"curl -L -o /tmp/testcase '{testcase_url}'"
    
    # Fuzzer command
    # We need to find the binary. It's usually in the build dir.
    # We assume the build is mounted at /mnt/shared/build (from GCS) or we need to find it.
    # The setup_commands already link /mnt/shared/build/* to target_build_dir
    # target_build_dir is usually /data/clusterfuzz/bot/builds/clusterfuzz-builds_.../revisions
    
    # We need to know where the binary is.
    # In LocalReproductionStrategy, we link to target_build_dir.
    # We should use the same target_build_dir here.
    
    # We need to recalculate target_build_dir here as it was calculated in setup_commands logic
    # But wait, setup_commands logic is inside this function too (lines 247-249).
    # We should reuse that variable.
    
    # Let's verify if target_build_dir is defined
    if 'target_build_dir' not in locals():
         # If no GCS build URI, we might be in trouble or using a pre-baked image
         # But usually we have GCS build URI.
         # If not, we assume standard path?
         target_build_dir = "/data/clusterfuzz/bot/builds/unknown" 
    
    # Set OUT to target_build_dir
    env_vars['OUT'] = target_build_dir

    # Use reproduce script
    run_cmd = f"reproduce {target_binary} {fuzzer_args} /tmp/testcase"
    
    full_cmd_str = f"{' && '.join(setup_commands)} && {download_cmd} && {run_cmd}"
    
    full_cmd = ["/bin/sh", "-c", full_cmd_str]
        
    job_spec = remote_utils.create_batch_job_spec(
        job_id=job_id,
        image=self.docker_image,
        command=full_cmd,
        gcs_volumes=gcs_volumes,
        env_vars=env_vars,
        privileged=True
    )
    
    click.echo(f"Log file: {log_file_path}", err=True)
    
    success_strings = None # We will use stack_analyzer for robust detection
    # We rely on the main process to print the link, here we just run and monitor
    # We pass success_strings=None so it returns True if job succeeded (exit code 0)
    # But wait, if job fails (exit code non-zero), it returns False.
    # If fuzzer crashes, it might exit with non-zero?
    # In LocalReproductionStrategy, we ran with `|| true`.
    # Here, we run `... && run_cmd`. If run_cmd fails, the whole command fails?
    # run_cmd is `fuzzer ...`. If fuzzer finds crash, it exits with 0 usually (libFuzzer default) or 1?
    # LibFuzzer exits with 1 on crash usually?
    # If it exits with 1, Batch job status will be FAILED.
    # If Batch job status is FAILED, submit_and_monitor_job returns False.
    # But we want to check logs even if it failed.
    # submit_and_monitor_job returns (success, logs).
    # If status is FAILED, success is False.
    # We should ignore the boolean success from submit_and_monitor_job and check logs ourselves using stack_analyzer.
    
    _, logs = remote_utils.submit_and_monitor_job(job_id, job_spec, self.project_id, success_strings=success_strings, log_file_path=log_file_path)

    # Analyze logs with ClusterFuzz stack_analyzer (same logic as LocalReproductionStrategy)
    # Mock ProjectConfig to avoid config loading errors if not already mocked
    try:
        from clusterfuzz._internal.config import local_config
        from unittest.mock import MagicMock
        if not isinstance(local_config.ProjectConfig, MagicMock):
             mock_config = MagicMock()
             mock_config.get.return_value = []
             local_config.ProjectConfig = MagicMock(return_value=mock_config)
    except ImportError:
        pass 

    from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
    from clusterfuzz._internal.crash_analysis import crash_analyzer

    # Parse crash data from logs
    # logs variable contains the full log text returned by submit_and_monitor_job
    crash_info = stack_analyzer.get_crash_data(logs, symbolize_flag=False)

    if crash_info.crash_type:
        print(f"Success: ClusterFuzz detected crash type: {crash_info.crash_type}")
        print(f"Crash State:\n{crash_info.crash_state}")
        return True
    
    # Fallback check
    if crash_analyzer.is_crash(1, logs):
         pass

    return False

def prepare_reproduction_data(tc_id: str, strategy: ReproductionStrategy) -> Optional[Dict]:
  """
  Prepares data for reproduction (fetches testcase, uploads to GCS, etc).
  Returns a dictionary with necessary data or None if failed.
  """
  try:
    with ndb_init.context():
      testcase = data_types.Testcase.get_by_id(int(tc_id))
      
      # Download testcase content logic
      blob_key = testcase.fuzzed_keys or testcase.minimized_keys
      if not blob_key:
          print(f"Error: No blob key found for testcase {tc_id}")
          return None
          
      # Resolve BlobKey to GCS path
      gcs_path = blobs.get_gcs_path(blob_key)
      if not gcs_path:
          print(f"Error: Could not resolve GCS path for blob key {blob_key}")
          return None
          
      # gcs_path is usually /bucket/object_name
      if gcs_path.startswith('/'):
          gcs_path = gcs_path[1:]
          
      parts = gcs_path.split('/', 1)
      if len(parts) != 2:
          print(f"Error: Invalid GCS path format: {gcs_path}")
          return None
          
      bucket_name, blob_name = parts
      
      print(f"DEBUG: TC-{tc_id} resolved bucket={bucket_name}, key={blob_name}")

      # generate_signed_url is defined in this file, not remote_utils
      testcase_url = None
      extra_volumes = {}
      
      try:
          testcase_url = generate_signed_url(
              bucket_name=bucket_name, 
              blob_name=blob_name,
              key_file=strategy.key_file,
              impersonate_service_account=strategy.impersonate_service_account
          )
      except Exception as e:
          print(f"Warning: Failed to generate signed URL: {e}")
          # Fallback: Download locally and mount
          print("Attempting to download testcase locally...")
          try:
              # Create a temp file for the testcase in the current directory (workspace)
              # This ensures Docker can mount it if we are in a container/dev environment
              fd, local_testcase_path = tempfile.mkstemp(prefix=f"testcase-{tc_id}-", dir=os.getcwd())
              os.close(fd)
              
              # Download using blob.download_to_filename (uses default creds)
              storage_client = storage.Client()
              bucket = storage_client.bucket(bucket_name)
              blob = bucket.blob(blob_name)
              blob.download_to_filename(local_testcase_path)
              
              print(f"Downloaded testcase to {local_testcase_path}")
              
              # Add to extra_volumes
              # Mount it to /tmp/testcase in the container
              # We use os.path.abspath to ensure we have the full path
              abs_local_path = os.path.abspath(local_testcase_path)
              extra_volumes = {
                  abs_local_path: {'bind': '/tmp/testcase', 'mode': 'ro'}
              }
              testcase_url = "file:///tmp/testcase" # Placeholder
              
          except Exception as download_error:
              print(f"Error downloading testcase locally: {download_error}")
              return None

      if not testcase_url:
          print(f"Error: Could not generate signed URL or download testcase for {tc_id}")
          return None
          
      print(f"DEBUG: TC-{tc_id} generated url={testcase_url}")

      job = data_types.Job.query(data_types.Job.name == testcase.job_type).get()
      
      target_binary = testcase.get_metadata('fuzzer_binary_name') or testcase.fuzzer_name
      fuzzer_args = testcase.minimized_arguments or ""
      
      job_env = {}
      if job:
          for line in job.get_environment_string().splitlines():
            if '=' in line and not line.startswith('#'):
              k, v = line.split('=', 1)
              job_env[k.strip()] = v.strip()
              
      return {
          'tc_id': tc_id,
          'job_name': job.name if job else 'unknown',
          'crash_revision': testcase.crash_revision,
          'testcase_url': testcase_url,
          'target_binary': target_binary,
          'fuzzer_args': fuzzer_args,
          'job_env': job_env,
          'project_name': testcase.project_name,
          'job': job,
          'extra_volumes': extra_volumes
      }

  except Exception as e:
    print(f"CRITICAL EXCEPTION in prepare_reproduction_data for TC-{tc_id}: {e}")
    traceback.print_exc()
    return None

def worker_reproduce(tc_id: str, strategy: ReproductionStrategy, log_file_path: str, crash_revision: int, data: Optional[Dict] = None) -> bool:
  """
  Runs the reproduction of a testcase using the provided strategy.
  """
  if not data:
      # Fallback if data not provided (should not happen with new flow)
      data = prepare_reproduction_data(tc_id, strategy)
  
  if not data:
      return False
      
  # We use a simple namespace for job to pass name
  job_name = data.get('job_name', 'unknown')
  job = types.SimpleNamespace(name=job_name, get_environment_string=lambda: '')
  
  return strategy.execute(
      tc_id=tc_id,
      job=job,
      log_file_path=log_file_path,
      crash_revision=data['crash_revision'],
      testcase=None, 
      testcase_url=data['testcase_url'],
      target_binary=data['target_binary'],
      fuzzer_args=data['fuzzer_args'],
      job_env=data['job_env'],
      extra_volumes=data.get('extra_volumes')
  )


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
@click.option('--use-gcb', is_flag=True, help='Use Google Cloud Build for reproduction (Private logs).')
@click.option('--gcs-bucket', help='GCS bucket for temporary storage (required for --use-batch/--use-gcb).')
@click.option('--service-account-key-file', help='Path to service account key file for signing URLs.')
@click.option('--impersonate-service-account', help='Service account to impersonate for signing URLs (if no key file).')
@click.option('--limit', type=int, help='Limit the number of testcases to reproduce.')
@click.option('--log-dir', help='Directory to save logs.')
@click.option('--tag', help='Custom tag for execution tracking.')
@click.option('--async', 'async_mode', is_flag=True, help='Submit GCB build and exit immediately.')
@click.option('--resume', is_flag=True, help='Resume mass reproduction by skipping already processed projects.')
@click.option('--testcase-id', help='Specific testcase ID to reproduce.')
def cli(project_name, config_dir, parallelism, os_version, environment,
        local_build_path, engine, sanitizer, use_batch, use_gcb, gcs_bucket, service_account_key_file, impersonate_service_account, limit, log_dir, tag, async_mode, resume, testcase_id):

  print(f"DEBUG: cli called with project_name={project_name}, testcase_id={testcase_id}")
  """Reproduces testcases for an OSS-Fuzz project locally."""
  
  # Handle 'all' projects
  if project_name == 'all':
      click.secho("Running reproduction for ALL non-migrated projects...", fg='cyan')
      
      # 1. Find all projects
      # Script is in clusterfuzz/cli/casp/src/casp/commands/reproduce_project.py
      # We want oss-fuzz/projects which is in ../../../../../../oss-fuzz/projects relative to this file
      projects_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../../../oss-fuzz/projects'))
      if not os.path.exists(projects_dir):
           # Fallback to current dir/projects if relative
           projects_dir = os.path.abspath('projects')
      
      if not os.path.exists(projects_dir):
          click.secho(f"Error: Could not find projects directory at {projects_dir}", fg='red')
          sys.exit(1)
          
      click.echo(f"Scanning projects in {projects_dir}...")
      
      # Resume logic
      processed_projects = set()
      if resume:
          scan_dir = log_dir if log_dir else os.path.join(tempfile.gettempdir(), 'casp')
          click.echo(f"Scanning for processed projects in {scan_dir}...")
          if os.path.exists(scan_dir):
              for root, dirs, files in os.walk(scan_dir):
                  if 'repro_submissions.json' in files:
                      try:
                          with open(os.path.join(root, 'repro_submissions.json'), 'r') as f:
                              data = json.load(f)
                              if isinstance(data, list):
                                  for item in data:
                                      if 'project' in item:
                                          processed_projects.add(item['project'])
                              elif isinstance(data, dict) and 'project' in data:
                                  processed_projects.add(data['project'])
                      except Exception as e:
                          pass
          click.secho(f"Found {len(processed_projects)} processed projects.", fg='green')
      
      projects_to_run = []
      for p in os.listdir(projects_dir):
          if resume and p in processed_projects:
              continue

          p_dir = os.path.join(projects_dir, p)
          if not os.path.isdir(p_dir):
              continue
              
          project_yaml = os.path.join(p_dir, 'project.yaml')
          if not os.path.exists(project_yaml):
              continue
              
          # Check if migrated
          is_migrated = False
          try:
              with open(project_yaml, 'r') as f:
                  content = f.read()
                  if 'ubuntu-24-04' in content:
                      is_migrated = True
          except Exception:
              pass
              
          if not is_migrated:
              projects_to_run.append(p)
              
      click.secho(f"Found {len(projects_to_run)} projects to reproduce (not on ubuntu-24-04).", fg='yellow')
      
      if not projects_to_run:
          click.secho("No projects found to reproduce.", fg='green')
          sys.exit(0)
          
      # 2. Run reproduction for each project
      # We call the main logic for each project.
      # To avoid recursion issues or complex refactoring, we can just loop here and call a helper function
      # that contains the main logic, OR we can subprocess call ourselves (safer for cleanup).
      # Subprocess is better to ensure clean state for each project.
      
      submissions = []
      
      for p in projects_to_run:
          click.secho(f"\n=== Starting reproduction for project: {p} ===", fg='magenta')
          
          cmd = [sys.executable, sys.argv[0], '--project-name', p]
          
          # Pass through all other args
          if config_dir: cmd.extend(['--config-dir', config_dir])
          if parallelism: cmd.extend(['--parallelism', str(parallelism)])
          if os_version: cmd.extend(['--os-version', os_version])
          if environment: cmd.extend(['--environment', environment])
          if local_build_path: cmd.extend(['--local-build-path', local_build_path])
          if engine: cmd.extend(['--engine', engine])
          if sanitizer: cmd.extend(['--sanitizer', sanitizer])
          if use_batch: cmd.append('--use-batch')
          if use_gcb: cmd.append('--use-gcb')
          if gcs_bucket: cmd.extend(['--gcs-bucket', gcs_bucket])
          if service_account_key_file: cmd.extend(['--service-account-key-file', service_account_key_file])
          if impersonate_service_account: cmd.extend(['--impersonate-service-account', impersonate_service_account])
          if limit: cmd.extend(['--limit', str(limit)])
          if log_dir: cmd.extend(['--log-dir', log_dir])
          if tag: cmd.extend(['--tag', tag])
          if async_mode: cmd.append('--async')
          if testcase_id: cmd.extend(['--testcase-id', testcase_id])
          
          try:
              # If async, we capture output to get build ID?
              # But subprocess prints to stdout.
              # If async_mode is on, the subprocess will print the build ID or save it?
              # The subprocess (this script running for one project) will handle saving if async.
              # But we might want to collect them all here.
              # Let's let the subprocess run and we just wait for it.
              subprocess.run(cmd, check=True)
          except subprocess.CalledProcessError:
              click.secho(f"Error reproducing project {p}", fg='red')
              # Continue to next project?
              continue
              
      click.secho("\nAll projects processed.", fg='green')
      sys.exit(0)

  # Normal flow for single project
  abs_local_build_path = None

  # 1. Environment Setup
  print(f"DEBUG: cli called with local_build_path={local_build_path}, gcs_bucket={gcs_bucket}")
  print(f"DEBUG: sys.path: {sys.path}")
  print(f"DEBUG: build_manager file: {build_manager.__file__}")
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
          data_types.Testcase.status == 'Processed',
          ndb_utils.is_false(data_types.Testcase.is_a_duplicate_flag),
          ndb_utils.is_true(data_types.Testcase.is_leader),
          ndb_utils.is_true(data_types.Testcase.open))
      testcases = list(ndb_utils.get_all_from_query(query))
  except Exception as e:
    click.secho(f"Error fetching testcases: {e}", fg='red')
    return
  
  dummy_tc = None
  if not testcases:
    click.secho(f'No open testcases found for {project_name}.', fg='yellow')
    # Create dummy testcase for build validation
    click.secho("Submitting build-only job for validation.", fg='cyan')
    
    # Determine job type (sanitizer)
    job_type = 'libfuzzer_asan' # Default
    if sanitizer:
        sanitizer_map = {
            'address': 'asan',
            'memory': 'msan',
            'undefined': 'ubsan',
            'coverage': 'cov',
            'dataflow': 'dft'
        }
        mapped_sanitizer = sanitizer_map.get(sanitizer.lower(), sanitizer.lower())
        job_type = f'libfuzzer_{mapped_sanitizer}'
    
    dummy_tc = {
        'id': 'build-only',
        'crash_type': 'Build Validation',
        'crash_state': 'N/A',
        'fuzzer_name': engine if engine else 'libfuzzer',
        'job_type': job_type,
        'testcase_url': None,
        'job_env': {},
        'fuzzer_args': '',
        'target_binary': '',
        'security_flag': False,
        'gestures': [],
        'redzone': 128,
        'additional_metadata': {},
        'crash_revision': '12345', # Dummy revision
        'job_name': job_type
    }
    
    # We need to pass this to reproduce_batch.
    # reproduce_batch expects a list of dicts (testcases_data).
    # But cli usually converts Testcase objects to dicts later.
    # We can just skip the filtering loop and directly populate testcases_data.
    to_reproduce = [] # Empty
    # We will handle this by checking if to_reproduce is empty AND testcases was empty
    
  total_testcases_count = len(testcases) if testcases else 0

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
    click.echo("No reproducible testcases to run. Proceeding with build verification only.")
    # return # Removed to allow build verification

  if limit and limit > 0:
    click.echo(f"Limiting reproduction to first {limit} testcases (out of {len(to_reproduce)}).")
    to_reproduce = to_reproduce[:limit]

  # 4. Get Docker Image Name (needed for strategy)
  try:
    docker_image = docker_utils.get_image_name(environment, os_version)
  except ValueError as e:
    click.secho(f'Error: {e}', fg='red')
    return

  # 5. Build Setup (Download if not provided)
  gcs_build_uri = None
  if not abs_local_build_path and to_reproduce:
      # Use the first testcase to determine the build
      # This assumes all testcases use the same build or compatible builds
      # If not, this logic needs to be moved to per-testcase execution
      t = to_reproduce[0]
      crash_revision = t.crash_revision
      
      # Set up environment for build_manager
      system_environment.set_value('PROJECT_NAME', project_name)
      system_environment.set_value('JOB_NAME', t.job_type)

      
      # Ensure BUILD_URLS_DIR is set
      if not system_environment.get_value('BUILD_URLS_DIR'):
          build_urls_dir = os.path.join(tempfile.gettempdir(), 'clusterfuzz-build-urls')
          os.makedirs(build_urls_dir, exist_ok=True)
          system_environment.set_value('BUILD_URLS_DIR', build_urls_dir)

      # Ensure BUILDS_DIR is set
      if not system_environment.get_value('BUILDS_DIR'):
          builds_dir = os.path.join(tempfile.gettempdir(), 'clusterfuzz-builds')
          os.makedirs(builds_dir, exist_ok=True)
          system_environment.set_value('BUILDS_DIR', builds_dir)

      # Ensure BOT_TMPDIR is set
      if not system_environment.get_value('BOT_TMPDIR'):
          bot_tmp_dir = os.path.join(tempfile.gettempdir(), 'clusterfuzz-bot-tmp')
          os.makedirs(bot_tmp_dir, exist_ok=True)
          system_environment.set_value('BOT_TMPDIR', bot_tmp_dir)

      # Ensure TEST_TMPDIR is set
      if not system_environment.get_value('TEST_TMPDIR'):
          test_tmp_dir = os.path.join(tempfile.gettempdir(), 'clusterfuzz-test-tmp')
          os.makedirs(test_tmp_dir, exist_ok=True)
          system_environment.set_value('TEST_TMPDIR', test_tmp_dir)




      # We need to set FUZZING_ENGINE and SANITIZER if possible
      # t.fuzzer_name usually contains them, e.g. libFuzzer_asan_...
      # But build_manager might need explicit vars.
      # Let's try to infer them or just rely on what's needed.
      # build_manager.setup_build uses environment.get_value('FUZZING_ENGINE') etc.
      
      # For now, let's try to call setup_build with just revision and let it figure out or fail.
      # But we should set minimal env.
      # We can get job info to be more precise.
      # But we don't have job info here easily without querying.
      # We can query the job for the first testcase.
      try:
          with ndb_init.context():
              job = data_types.Job.query(data_types.Job.name == t.job_type).get()
              if job:
                  print(f"DEBUG: Found job {job.name}. Environment:")
                  for line in job.get_environment_string().splitlines():
                      if '=' in line and not line.startswith('#'):
                          k, v = line.split('=', 1)
                          system_environment.set_value(k.strip(), v.strip())
                          print(f"  {k.strip()}={v.strip()}")
      except Exception as e:
          print(f"Warning: Could not fetch job environment for build setup: {e}")
          traceback.print_exc()

      click.echo(f"Setting up build for revision {crash_revision}...")
      try:
          # Avoid downloading the build locally if we just need the URL for GCB/Batch
          from clusterfuzz._internal.build_management import revisions
          
          bucket_path = system_environment.get_value('RELEASE_BUILD_BUCKET_PATH')
          if bucket_path:
              print(f"DEBUG: Resolving build URL from {bucket_path} for revision {crash_revision}")
              build_urls = build_manager.get_build_urls_list(bucket_path)
              if build_urls:
                  build_url = revisions.find_build_url(bucket_path, build_urls, crash_revision)
                  if build_url:
                      gcs_build_uri = build_url
                      print(f"DEBUG: Found build URL: {gcs_build_uri}")
                  else:
                      print(f"Warning: Could not find build for revision {crash_revision}")
              else:
                  print(f"Warning: No build URLs found in {bucket_path}")
          else:
              print("Warning: RELEASE_BUILD_BUCKET_PATH not set")

          if not gcs_build_uri:
              # Fallback to setup_build if we couldn't resolve it (e.g. custom binary or other types)
              print(f"DEBUG: Calling build_manager.setup_build(revision={crash_revision}) as fallback")
              build_path = build_manager.setup_build(revision=crash_revision)
              print(f"DEBUG: build_manager.setup_build returned: {build_path}")

              if build_path:
                  # build_path is likely a RegularBuild object, not a string
                  if hasattr(build_path, 'build_url'):
                      gcs_build_uri = build_path.build_url
                      print(f"DEBUG: Extracted gcs_build_uri from RegularBuild: {gcs_build_uri}")
                  elif isinstance(build_path, str):
                      if build_path.startswith('gs://'):
                          gcs_build_uri = build_path
                      else:
                          abs_local_build_path = build_path
                  else:
                      print(f"Warning: Unknown build_path type: {type(build_path)}")

      except Exception as e:
          click.secho(f"Warning: Build setup failed: {e}", fg='yellow')
          traceback.print_exc()


  # 6. GCS Upload (Common for both if bucket provided)
  if gcs_bucket and abs_local_build_path:

      try:
          # Prepare build in a temporary directory for upload
          with tempfile.TemporaryDirectory() as tmp_dir:
              upload_dir = os.path.join(tmp_dir, 'upload')
              os.makedirs(upload_dir)
              
              # Copy build contents
              subprocess.run(['cp', '-r', f'{abs_local_build_path}/.', upload_dir], check=True)
              
              click.echo(f"Uploading build to GCS...")
              gcs_build_uri = remote_utils.upload_to_gcs(
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
  
  if use_batch and use_gcb:
      click.secho('Error: Cannot use both --use-batch and --use-gcb.', fg='red')
      sys.exit(1)
      
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
        gcs_config_uri=gcs_config_uri,
        gcs_bucket=gcs_bucket,
        key_file=service_account_key_file,
        impersonate_service_account=impersonate_service_account
    )



    click.echo(f"Using Cloud Batch strategy with project {project_id}")
    
  elif use_gcb:
    if not gcs_bucket:
        click.secho('Error: --gcs-bucket is required when using --use-gcb (for testcase upload).', fg='red')
        sys.exit(1)
        
    # Project ID is needed for GCB
    # User requested 'oss-fuzz' project for GCB
    project_id = "oss-fuzz"
    
    strategy = GCBReproductionStrategy(
        docker_image=docker_image,
        gcs_build_uri=gcs_build_uri,
        project_id=project_id,
        os_version=os_version,
        gcs_bucket=gcs_bucket,
        key_file=service_account_key_file,
        impersonate_service_account=impersonate_service_account
    )
    
    click.echo(f"Using Google Cloud Build strategy with project {project_id}")

  else:
    # Local Execution
    # Pass gcs_build_uri if available, so LocalReproductionStrategy can use it if it wants
    print(f"DEBUG: Creating LocalReproductionStrategy with abs_local_build_path={abs_local_build_path}, gcs_build_uri={gcs_build_uri}")
    strategy = LocalReproductionStrategy(volumes, worker_config_dir_arg, abs_local_build_path, docker_image, gcs_build_uri, gcs_bucket, service_account_key_file, impersonate_service_account)


    if gcs_build_uri:
        click.echo("Using Local reproduction strategy with GCS download")
    else:
        click.echo("Using Local reproduction strategy with local volume")

  click.echo(
      f"\nStarting reproduction for {len(to_reproduce)} testcases with {parallelism} parallel workers using {environment} environment and {os_version} OS."
  )

  # 7. Parallel Worker Execution
  if use_gcb:
      click.echo(f"\nPreparing batch reproduction for {len(to_reproduce)} testcases on Cloud Build...")
      
      # Collect data for all testcases
      testcases_data = []
      
      if dummy_tc:
          testcases_data.append(dummy_tc)
      else:
          # We need to prepare data for each testcase (Signed URLs etc)
          # We can use a thread pool for preparation if it's slow (GCS uploads)
          # But for now let's do it sequentially or use a small pool.
          # GCS uploads might take time.
          
          with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as preparer:
              future_to_tc = {preparer.submit(prepare_reproduction_data, str(t.key.id()), strategy): t for t in to_reproduce}
              
              for future in concurrent.futures.as_completed(future_to_tc):
                  t = future_to_tc[future]
                  try:
                      data = future.result()
                      if data:
                          testcases_data.append(data)
                      else:
                          click.secho(f"✖ TC-{t.key.id()} Failed to prepare data.", fg='red')
                  except Exception as exc:
                      click.secho(f"✖ TC-{t.key.id()} Exception during preparation: {exc}", fg='red')
      
      if not testcases_data:
          click.secho("No testcases were successfully prepared. Proceeding with build verification only.", fg='yellow')
          # We continue to reproduce_batch which will generate build steps but no repro steps.

      # Submit Batch
      results = strategy.reproduce_batch(testcases_data, log_dir, project_name=project_name, tag=tag, async_mode=async_mode)
      
      if async_mode:
          click.echo("Async mode enabled. Skipping result verification.")
      else:
          # Report Results
          completed_count = 0
          success_count = 0
          failure_count = 0
          
          for tc_id, is_success in results.items():
              completed_count += 1
              if is_success:
                  success_count += 1
                  click.secho(f"✔ TC-{tc_id} Success ({completed_count}/{len(results)})", fg='green')
              else:
                  failure_count += 1
                  click.secho(f"✖ TC-{tc_id} Failed ({completed_count}/{len(results)})", fg='red')
              
  else:
      # Local or Batch (Legacy Loop)
      with concurrent.futures.ProcessPoolExecutor(
          max_workers=parallelism) as executor:
        future_to_tc = {}
        preparation_failures = 0
    
        for t in to_reproduce:
          tid = str(t.key.id())
          log_file = os.path.join(log_dir, f"tc-{tid}.log")
          with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"--- Starting reproduction for Testcase ID: {tid} ---\n")
            f.write(f"Project: {t.project_name}\n")
            f.write(f"Engine: {t.fuzzer_name}\n")
            f.write(f"Job Type: {t.job_type}\n")
            f.write("-" * 40 + "\n")
            
          # Prepare data in main process to avoid NDB context issues in workers
          data = prepare_reproduction_data(tid, strategy)
          if not data:
              click.secho(f"✖ TC-{tid} Failed to prepare data.", fg='red')
              preparation_failures += 1
              continue
    
          if use_batch:
              click.secho(f"➜ TC-{tid} Submitting to Cloud Batch...", fg='cyan')
    
          f = executor.submit(worker_reproduce, tid, strategy, log_file, t.crash_revision, data)
          future_to_tc[f] = tid
    
        completed_count = preparation_failures
        success_count = 0
        failure_count = preparation_failures
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

  if async_mode:
      click.echo("\nAsync submission completed. Check repro_submissions.json for details.")
      return

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