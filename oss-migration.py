#!/usr/bin/env python3
import argparse
import json
import time
import os
import re
import shutil
import sys
import asyncio
import signal
import tempfile
import logging
import random
import string
import datetime
from typing import Dict, Optional, Tuple
import shlex
import subprocess
import traceback

# Paths (adjust if necessary)
OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'
CLUSTERFUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/clusterfuzz'
CASP_PYTHONPATH = 'cli/casp/src:src'
BASE_MIGRATION_DIR = '/usr/local/google/home/matheushunsche/projects/oss-migration'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='\r[%(asctime)s] %(message)s', # Added \r at the beginning
    datefmt='%H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Global list to track active subprocesses for clean termination
active_processes = []

def restore_terminal():
    """Restores terminal settings to a sane state."""
    try:
        import subprocess
        subprocess.run(['stty', 'sane'], check=False)
        # Clear any leftover input
        if sys.stdin.isatty():
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except:
        pass

def force_exit_handler(signum, frame):
    # Use print to avoid dependency on logger if it's not ready
    print("\nCtrl+C detected! Force terminating active processes...", flush=True)
    for p in active_processes:
        try:
            # Try to get process group ID
            pgid = os.getpgid(p.pid)
            os.killpg(pgid, signal.SIGKILL)
        except:
            try:
                p.terminate()
            except:
                pass
    restore_terminal()
    os._exit(1)

signal.signal(signal.SIGINT, force_exit_handler)
signal.signal(signal.SIGTERM, force_exit_handler)

def safe_print(message):
    logger.info(message)

def safe_rmtree(path):
    if not os.path.exists(path):
        return
    try:
        if os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    except Exception:
        try:
            # Try using Docker to delete, as files might be owned by root
            parent_dir = os.path.dirname(os.path.abspath(path))
            base_name = os.path.basename(path)
            subprocess.run(['docker', 'run', '--rm', '-v', f'{parent_dir}:/tmp/parent', 'busybox', 'rm', '-rf', f'/tmp/parent/{base_name}'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

def recursive_chmod(path, mode):
    if not os.path.exists(path):
        return
    try:
        os.chmod(path, mode)
    except:
        pass
    for root, dirs, files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), mode)
            except:
                pass
        for f in files:
            full_path = os.path.join(root, f)
            if not os.path.islink(full_path):
                    try:
                        os.chmod(full_path, mode)
                    except:
                        pass

# Global list to track active subprocesses for clean termination
active_processes = []

async def run_command(cmd, cwd, env=None, capture_output=False, dry_run=False, prefix=None, stdout=None, stderr=None):
    if isinstance(cmd, list):
        cmd_str = ' '.join(cmd)
        cmd_args = cmd
        is_shell = False
    else:
        cmd_str = cmd
        cmd_args = cmd
        is_shell = True

    # safe_print(f"Running command: {cmd_str} in {cwd}") # Removed redundant print
    try:
        # Determine stdout/stderr for subprocess creation
        _stdout = stdout if stdout else asyncio.subprocess.PIPE
        _stderr = stderr if stderr else asyncio.subprocess.STDOUT # Original default

        if is_shell:
            process = await asyncio.create_subprocess_shell(
                cmd_args,
                cwd=cwd,
                env=env,
                stdout=_stdout,
                stderr=_stderr,
                preexec_fn=os.setsid
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *cmd_args,
                cwd=cwd,
                env=env,
                stdout=_stdout,
                stderr=_stderr,
                preexec_fn=os.setsid
            )
        active_processes.append(process)

        output_lines = []
        if process.stdout: # Check if process.stdout exists before trying to read from it
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                try:
                    decoded_line = line.decode('utf-8').strip()
                except:
                    decoded_line = line.decode('latin-1', errors='replace').strip()
                
                if capture_output:
                    output_lines.append(decoded_line)
                if prefix:
                    logger.info(f"{prefix} {decoded_line}")
                elif not capture_output:
                    logger.info(decoded_line)
        
        await process.wait()
        if process in active_processes:
            active_processes.remove(process)
        if process.returncode != 0:
            raise Exception(f"Command failed with exit code {process.returncode}: {cmd}")
        return "\n".join(output_lines)
    except Exception as e:
        safe_print(f"Error running command: {e}")
        raise e

async def get_gcb_builds(project):
    safe_print(f"\n--- Step 1: Checking GCB builds for {project} ---")
    import shlex
    import subprocess
    import traceback
    
    cmd_us_central1_str = f"gcloud builds list --project=oss-fuzz --region=us-central1 --filter=\"tags='{project}' AND tags='fuzzing'\" --limit=3 --format=json --sort-by=\"~createTime\""
    safe_print(f"Running command: {cmd_us_central1_str} in {OSS_FUZZ_DIR}")
    try:
        cmd_args = shlex.split(cmd_us_central1_str)
        output = subprocess.check_output(cmd_args, cwd=OSS_FUZZ_DIR, text=True)
    except Exception as e:
        safe_print(f"Error running subprocess: {e}")
        output = ""
    
    builds = json.loads(output) if output else []
    
    if not builds:
        safe_print("No builds found in us-central1, trying global...")
        cmd_global_str = f"gcloud builds list --project=oss-fuzz --filter=\"tags='{project}' AND tags='fuzzing'\" --limit=3 --format=json --sort-by=\"~createTime\""
        safe_print(f"Running command: {cmd_global_str} in {OSS_FUZZ_DIR}")
        try:
            cmd_args = shlex.split(cmd_global_str)
            output = subprocess.check_output(cmd_args, cwd=OSS_FUZZ_DIR, text=True)
        except Exception as e:
            safe_print(f"Error running subprocess: {e}")
            output = ""
        builds = json.loads(output) if output else []

    if output:
        try:
            builds = json.loads(output)
            if not builds:
                return []
            
            # Check if all 3 are successful
            all_success = all(b.get('status') == 'SUCCESS' for b in builds)
            if all_success and len(builds) >= 3:
                safe_print("GCB builds are healthy (3/3 SUCCESS).")
            else:
                safe_print(f"GCB builds are not healthy. Statuses: {[b.get('status') for b in builds]}")
            return builds # Return the builds list
        except json.JSONDecodeError:
            safe_print("Error decoding GCB builds output.")
            return []
    return []

async def run_reproduction(project, local_build_path=None, os_version='legacy', engine=None, sanitizer=None, dry_run=False, use_batch=False, gcs_bucket=None, limit=None):
    safe_print(f"\n--- Running reproduction for {project} (OS: {os_version}, Engine: {engine}, Sanitizer: {sanitizer}, Local Build: {local_build_path}, Batch: {use_batch}) ---")
    
    env = os.environ.copy()
    env['PYTHONPATH'] = CASP_PYTHONPATH
    
    cmd = f"python3.11 -m casp.main reproduce project --project-name {project}"
    if os_version:
        cmd += f" --os-version {os_version}"
    if local_build_path:
        cmd += f" --local-build-path {local_build_path}"
    if engine:
        cmd += f" --engine {engine}"
    if sanitizer:
        cmd += f" --sanitizer {sanitizer}"
    if use_batch:
        cmd += " --use-batch"
    if limit:
        cmd += f" --limit {limit}"
    
    cmd += " -n 20"
        
    if gcs_bucket:
        cmd += f" --gcs-bucket {gcs_bucket}"
    
    prefix_engine = engine if engine else "all"
    prefix_sanitizer = sanitizer if sanitizer else "all"
    
    # Add random jitter to avoid burst requests to Datastore/GCS
    jitter = random.uniform(0, 10)
    safe_print(f"[{os_version}-{prefix_engine}-{prefix_sanitizer}] Waiting {jitter:.2f}s jitter before starting...")
    await asyncio.sleep(jitter)
    
    safe_print(f"[{os_version}-{prefix_engine}-{prefix_sanitizer}] Running command: {cmd}")
    output = await run_command(cmd, CLUSTERFUZZ_DIR, env=env, capture_output=True, dry_run=False, prefix=f"[{os_version}-{prefix_engine}-{prefix_sanitizer}]")
    
    if not output:
        return 0, 0, []
    
    success_match = re.search(r"Success: (\d+)", output)
    failed_match = re.search(r"Failed:\s+(\d+)", output)
    
    success_count = int(success_match.group(1)) if success_match else 0
    failed_count = int(failed_match.group(1)) if failed_match else 0
    
    failures = []
    if failed_count > 0:
        log_dir_match = re.search(r"Detailed logs are available in: (\S+)", output)
        if log_dir_match:
            log_dir = log_dir_match.group(1)
            if os.path.exists(log_dir):
                for f in os.listdir(log_dir):
                    if f.endswith('.log') and f.startswith('tc-'):
                        log_path = os.path.join(log_dir, f)
                        with open(log_path, 'r') as log_file:
                            content = log_file.read()
                            is_success = "Success" in content or "Crash is reproducible" in content or "The testcase reliably reproduces" in content
                            if not is_success:
                                tc_id = f.replace('tc-', '').replace('.log', '')
                                failures.append({
                                    'tc_id': tc_id,
                                    'os_version': os_version,
                                    'engine': engine,
                                    'sanitizer': sanitizer,
                                    'log_path': log_path
                                })
    
    return success_count, failed_count, failures

def get_project_config(project):
    project_yaml = os.path.join(OSS_FUZZ_DIR, 'projects', project, 'project.yaml')
    engines = ['libfuzzer']
    sanitizers = ['address']
    if os.path.exists(project_yaml):
        with open(project_yaml, 'r') as f:
            content = f.read()
            match_eng = re.search(r'fuzzing_engines:\n((?:\s+-\s+\w+\n)+)', content)
            if match_eng:
                engines = [line.strip().replace('- ', '') for line in match_eng.group(1).splitlines()]
            match_san = re.search(r'sanitizers:\n((?:\s+-\s+\w+\n)+)', content)
            if match_san:
                sanitizers = [line.strip().replace('- ', '') for line in match_san.group(1).splitlines()]
    return engines, sanitizers

def get_project_contacts(project):
    project_yaml = os.path.join(OSS_FUZZ_DIR, 'projects', project, 'project.yaml')
    contacts = ['@DavidKorczynski']
    if os.path.exists(project_yaml):
        with open(project_yaml, 'r') as f:
            content = f.read()
            pc_match = re.search(r'primary_contact:\s+"?([^"\n]+)"?', content)
            if pc_match:
                contacts.append(pc_match.group(1))
            cc_match = re.search(r'auto_ccs:\n((?:\s+-\s+"?[^"\n]+"?\n)+)', content)
            if cc_match:
                for line in cc_match.group(1).splitlines():
                    email = line.strip().replace('- ', '').replace('"', '')
                    if email not in contacts:
                        contacts.append(email)
    return contacts

async def build_local_combo(project, combo_temp_dir, engine, sanitizer, os_version, rebuild, build_project_name, oss_fuzz_dir, dry_run, use_batch, gcs_bucket, pull=False, cpu_limit=None, mem_limit=None, limit=None):
    if not oss_fuzz_dir:
        oss_fuzz_dir = OSS_FUZZ_DIR
    if not build_project_name:
        build_project_name = project
    
    import random
    import string
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    combo_dir_name = f"{os_version}-{engine}-{sanitizer}-{random_suffix}"
    
    safe_print(f"[{os_version}-{engine}-{sanitizer}] Using combo_dir_name: {combo_dir_name}")
    
    # New structure: oss-migration/<project>/builds/<os_version>-<engine>-<sanitizer>
    project_migration_dir = os.path.join(BASE_MIGRATION_DIR, project)
    builds_dir = os.path.join(project_migration_dir, 'builds')
    combo_temp_dir = os.path.join(builds_dir, combo_dir_name)
    
    os.makedirs(combo_temp_dir, exist_ok=True)
    recursive_chmod(combo_temp_dir, 0o755) # Ensure dir is accessible
    
    # If rebuild is True, we want a clean build, so remove existing dir if it exists
    if rebuild and os.path.exists(combo_temp_dir):
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Removing existing build dir for clean build: {combo_temp_dir}")
        safe_rmtree(combo_temp_dir)
        os.makedirs(combo_temp_dir, exist_ok=True)
        recursive_chmod(combo_temp_dir, 0o755)
    
    # The build output will stay within this directory
    combo_out_dir = os.path.join(combo_temp_dir, 'build', 'out', build_project_name)

    repro_results = (0, 0, []) # Default to 0 successes/failures, no failures list
    build_failures = []

    if not rebuild and os.path.exists(combo_out_dir) and os.listdir(combo_out_dir):
        safe_print(f"Skipping build for {engine}-{sanitizer} ({os_version}) as directory exists and is not empty.")
        # Still need to run reproduction if skipped build? Yes, usually.
        repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False, use_batch=use_batch, gcs_bucket=gcs_bucket if use_batch else None, limit=limit)
        return combo_out_dir, combo_temp_dir, repro_results, build_failures

    if not os.path.exists(combo_temp_dir):
        os.makedirs(combo_temp_dir, exist_ok=True)
        recursive_chmod(combo_temp_dir, 0o755) # Ensure combo dir is accessible
        safe_print(f"Created persistent isolated build dir: {combo_temp_dir}")
        
        # Set up OSS-Fuzz environment in temp dir
        # We need to create infra dir and symlink contents except helper.py
        infra_dir = os.path.join(combo_temp_dir, 'infra')
        os.makedirs(infra_dir, exist_ok=True)
        original_infra_dir = os.path.join(oss_fuzz_dir, 'infra')
        for item in os.listdir(original_infra_dir):
            if item == 'helper.py':
                continue
            s = os.path.join(original_infra_dir, item)
            d = os.path.join(infra_dir, item)
            if os.path.isdir(s):
                os.symlink(s, d, target_is_directory=True)
            else:
                os.symlink(s, d)
        
        # Copy modified helper.py
        shutil.copy2(os.path.join(os.path.dirname(__file__), 'helper_modified.py'), os.path.join(infra_dir, 'helper.py'))
        os.chmod(os.path.join(infra_dir, 'helper.py'), 0o755)

        os.symlink(os.path.join(oss_fuzz_dir, 'base-images'), os.path.join(combo_temp_dir, 'base-images'))
        os.symlink(os.path.join(oss_fuzz_dir, 'build.py'), os.path.join(combo_temp_dir, 'build.py'))
    else:
        safe_print(f"Using existing isolated build dir: {combo_temp_dir}")
    
    # Ensure project directory exists and is correctly linked/copied
    project_temp_dir = os.path.join(combo_temp_dir, 'projects', build_project_name)
    if os.path.exists(project_temp_dir) or os.path.islink(project_temp_dir):
        if os.path.islink(project_temp_dir):
            os.remove(project_temp_dir)
        elif os.path.isdir(project_temp_dir):
            safe_rmtree(project_temp_dir)
        else:
            os.remove(project_temp_dir)
    
    os.makedirs(os.path.dirname(project_temp_dir), exist_ok=True)
    if os_version == 'ubuntu-24-04':
        # For 24.04, copy from the modified OSS-Fuzz dir (which is oss_fuzz_dir here)
        shutil.copytree(os.path.join(oss_fuzz_dir, 'projects', build_project_name), project_temp_dir)
    else:
        # For Legacy, just symlink from original OSS_FUZZ_DIR
        os.symlink(os.path.join(OSS_FUZZ_DIR, 'projects', build_project_name), project_temp_dir)

    # Ensure essential symlinks exist even if directory existed
    for link_name in ['base-images', 'build.py']:
        link_path = os.path.join(combo_temp_dir, link_name)
        if os.path.exists(link_path) or os.path.islink(link_path):
            try:
                if os.path.islink(link_path):
                    os.remove(link_path)
                elif os.path.isdir(link_path):
                    safe_rmtree(link_path)
                else:
                    os.remove(link_path)
            except:
                pass
        os.symlink(os.path.join(oss_fuzz_dir, link_name), link_path)
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Created symlink: {link_path} -> {os.path.join(oss_fuzz_dir, link_name)}")
    
    # Handle infra separately to keep modified helper.py
    infra_link_path = os.path.join(combo_temp_dir, 'infra')
    if not os.path.exists(infra_link_path):
        os.makedirs(infra_link_path, exist_ok=True)
        original_infra_dir = os.path.join(oss_fuzz_dir, 'infra')
        for item in os.listdir(original_infra_dir):
            if item == 'helper.py':
                continue
            s = os.path.join(original_infra_dir, item)
            d = os.path.join(infra_link_path, item)
            if os.path.islink(d) or os.path.exists(d):
                continue
            if os.path.isdir(s):
                os.symlink(s, d, target_is_directory=True)
            else:
                os.symlink(s, d)
        # Copy modified helper.py
        shutil.copy2(os.path.join(os.path.dirname(__file__), 'helper_modified.py'), os.path.join(infra_link_path, 'helper.py'))
        os.chmod(os.path.join(infra_link_path, 'helper.py'), 0o755)

    # Fallback check in case helper.py still used real OSS_FUZZ_DIR (unlikely now but safe)
    real_oss_fuzz_out = os.path.join(oss_fuzz_dir, 'build', 'out', build_project_name)
    if os.path.exists(real_oss_fuzz_out) and os.listdir(real_oss_fuzz_out):
            safe_print(f"[{os_version}-{engine}-{sanitizer}] Found output in real OSS_FUZZ_DIR, moving to persistent dir.")
            if os.path.exists(combo_out_dir):
                if not dry_run:
                    safe_rmtree(combo_out_dir)
            if not dry_run:
                os.makedirs(os.path.dirname(combo_out_dir), exist_ok=True)
                shutil.move(real_oss_fuzz_out, combo_out_dir)
                os.makedirs(real_oss_fuzz_out, exist_ok=True) # Recreate empty dir to avoid issues
            else:
                safe_print(f"Dry run: Would move {real_oss_fuzz_out} to {combo_out_dir}")
            # Run reproduction immediately after move
            repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False, use_batch=use_batch, gcs_bucket=gcs_bucket, limit=limit)
            return combo_out_dir, combo_temp_dir, repro_results, build_failures

    # Run build using helper.py within the isolated environment
    # We need to run this from within combo_temp_dir to use the local infra and projects
    build_log_path = os.path.join(combo_temp_dir, 'build.log')
    try:
        # 1. Build Image
        build_image_cmd = f"python3 infra/helper.py build_image --pull {build_project_name}"
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Running build command: {build_image_cmd} in {combo_temp_dir} (Log: {build_log_path})")
        # Log build output to file
        with open(build_log_path, 'a') as log_file:
            await run_command(build_image_cmd, combo_temp_dir, capture_output=False, dry_run=False, prefix=f"[{os_version}-{engine}-{sanitizer}]", stdout=log_file, stderr=log_file)

        cmd = f"python3 infra/helper.py build_fuzzers --engine {engine} --sanitizer {sanitizer} {build_project_name}"
        if cpu_limit:
            cmd += f" --docker-arg=\"--cpus={cpu_limit}\""
        if mem_limit:
            cmd += f" --docker-arg=\"--memory={mem_limit}g\""
        
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Running build command: {cmd} in {combo_temp_dir} (Log: {build_log_path})")
        with open(build_log_path, 'a') as log_file:
            await run_command(cmd, combo_temp_dir, capture_output=False, dry_run=False, prefix=f"[{os_version}-{engine}-{sanitizer}]", stdout=log_file, stderr=log_file)
    except Exception as e:
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Build failed: {e}")
        build_failures.append({
            'os_version': os_version,
            'engine': engine,
            'sanitizer': sanitizer,
            'error': str(e),
            'log_path': build_log_path
        })
        return combo_out_dir, combo_temp_dir, (0, 0, []), build_failures

    # After build, ensure permissions are correct for Docker access
    # First, fix ownership of the output directory (Docker creates files as root)
    # Use Docker itself to fix permissions to avoid sudo password prompt on host
    try:
        uid = os.getuid()
        gid = os.getgid()
        # We need to mount the parent directory to handle the directory itself if needed, 
        # but mounting the directory directly is simpler for its contents.
        # Since combo_out_dir is what we want to fix:
        cmd = f"docker run --rm -v {combo_out_dir}:/out busybox chown -R {uid}:{gid} /out"
        # Run this command. We don't need to be in combo_temp_dir for this.
        await run_command(cmd, os.getcwd(), capture_output=False, prefix=f"[{os_version}-{engine}-{sanitizer}]")
    except Exception as e:
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Warning: Failed to fix ownership with Docker: {e}")

    recursive_chmod(combo_temp_dir, 0o755)

    # After build, check if output exists
    if not os.path.exists(combo_out_dir) or not os.listdir(combo_out_dir):
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Build failed or no output generated in {combo_out_dir}")
        build_failures.append({
            'os_version': os_version,
            'engine': engine,
            'sanitizer': sanitizer,
            'error': 'No output generated'
        })
        return combo_out_dir, combo_temp_dir, (0, 0, []), build_failures
    
    # Run reproduction
    repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False, use_batch=use_batch, gcs_bucket=gcs_bucket, limit=limit)
    
    return combo_out_dir, combo_temp_dir, repro_results, build_failures

async def build_local(project, engines=None, sanitizers=None, dry_run=False, rebuild=False, os_version='legacy', build_project_name=None, oss_fuzz_dir=None, use_batch=False, gcs_bucket=None, pull=False, cpu_limit=None, mem_limit=None, limit=None):
    if build_project_name is None:
        build_project_name = project
    if oss_fuzz_dir is None:
        oss_fuzz_dir = OSS_FUZZ_DIR
    
    safe_print(f"\n--- Building local fuzzers for {build_project_name} ({os_version}) ---")
    if not engines:
        engines = ['libfuzzer']
    if not sanitizers:
        sanitizers = ['address']
    
    tasks = []
    for engine in engines:
        for sanitizer in sanitizers:
            tasks.append(build_local_combo(project, None, engine, sanitizer, os_version, rebuild, build_project_name, oss_fuzz_dir, dry_run, use_batch, gcs_bucket, pull=pull, cpu_limit=cpu_limit, mem_limit=mem_limit, limit=limit))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    build_paths = []
    temp_dirs = []
    total_success = 0
    total_failed = 0
    all_failures = []
    all_build_failures = []
    
    for res in results:
        if isinstance(res, Exception):
            safe_print(f"Build/Reproduction failed with exception: {res}")
            # We don't have engine/sanitizer here easily, but we can log the exception
        elif res:
            out_dir, temp_dir, repro_results, build_failures = res
            success, failed, failures = repro_results
            build_paths.append(out_dir)
            temp_dirs.append(temp_dir)
            total_success += success
            total_failed += failed
            all_failures.extend(failures)
            all_build_failures.extend(build_failures)
    return build_paths, temp_dirs, total_success, total_failed, all_failures, all_build_failures

async def modify_files_for_2404(project, oss_fuzz_dir, dry_run=False):
    safe_print(f"\n--- Modifying files for Ubuntu 24.04 in {oss_fuzz_dir} ---")
    project_yaml = os.path.join(oss_fuzz_dir, 'projects', project, 'project.yaml')
    dockerfile = os.path.join(oss_fuzz_dir, 'projects', project, 'Dockerfile')
    
    # Backup original files before modification
    if not dry_run:
        if os.path.exists(project_yaml):
            shutil.copy(project_yaml, project_yaml + '.bak')
        if os.path.exists(dockerfile):
            shutil.copy(dockerfile, dockerfile + '.bak')
    
        with open(project_yaml, 'a') as f:
            f.write('\nbase_os_version: "ubuntu-24-04"\n')
        
        with open(dockerfile, 'r') as f:
            content = f.read()
        
        # Robust replacement using regex to handle base images like base-builder-go
        # Matches 'FROM gcr.io/oss-fuzz-base/base-builder' optionally followed by '-lang' and optionally a tag
        import re
        new_content = re.sub(
            r'FROM\s+(gcr\.io/oss-fuzz-base/base-builder(?:-[a-z]+)?)(?::\w+)?',
            r'FROM \1:ubuntu-24-04',
            content
        )
        
        with open(dockerfile, 'w') as f:
            f.write(new_content)
    else:
        safe_print(f"Dry run: Would modify {project_yaml} and {dockerfile}")

async def run_full_suite(project, engines, sanitizers, os_version, rebuild, build_project_name=None, oss_fuzz_dir=None, use_batch=False, gcs_bucket=None, cpu_limit=None, mem_limit=None, limit=None):
    if build_project_name is None:
        build_project_name = project
    
    safe_print(f"\n--- Running Full Suite for {project} on {os_version} ---")
    build_paths, temp_dirs, total_success, total_failed, failures, build_failures = await build_local(project, engines=engines, sanitizers=sanitizers, dry_run=False, rebuild=rebuild, os_version=os_version, build_project_name=build_project_name, oss_fuzz_dir=oss_fuzz_dir, use_batch=use_batch, gcs_bucket=gcs_bucket, cpu_limit=cpu_limit, mem_limit=mem_limit, limit=limit)
    
    return total_success, total_failed, temp_dirs, failures, build_failures


async def main_async():
    parser = argparse.ArgumentParser(description='Verify OSS-Fuzz project builds and reproduction.')
    parser.add_argument('project', help='OSS-Fuzz project name')
    parser.add_argument('--rebuild', action='store_true', help='Force rebuild even if build directory exists')
    parser.add_argument('--use-batch', action='store_true', help='Use Google Cloud Batch for reproduction')
    parser.add_argument('--gcs-bucket', help='GCS bucket for temporary storage (required for --use-batch)')
    parser.add_argument('--engine', help='Specific engine to run (e.g., libfuzzer)')
    parser.add_argument('--sanitizer', help='Specific sanitizer to run (e.g., address)')
    parser.add_argument('--limit', type=int, default=None, help='Limit the number of testcases to reproduce')
    args = parser.parse_args()
    
    # Setup persistent log file for results only
    project_migration_dir = os.path.join(BASE_MIGRATION_DIR, args.project)
    results_dir = os.path.join(project_migration_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)
    
    log_filepath = os.path.join(results_dir, 'summary.log')
    
    safe_print(f"Starting main... Full output on console, results will be saved to {log_filepath}")
    safe_print(f"Args: {args}")
    
    results = {}
    temp_oss_fuzz_dir = None
    all_temp_dirs = [] # Initialize all_temp_dirs here
    
    try:
        engines, sanitizers = get_project_config(args.project)
        if args.engine:
            engines = [args.engine]
        if args.sanitizer:
            sanitizers = [args.sanitizer]
        
        safe_print(f"Found engines: {engines}")
        safe_print(f"Found sanitizers: {sanitizers}")
        
        safe_print("Starting parallel execution...")
        
        # Calculate resources per thread
        # Total resources available
        TOTAL_CPUS = 52
        TOTAL_RAM_GB = 88
        
        num_engines = len(engines)
        num_sanitizers = len(sanitizers)
        # We run legacy and 24.04 in parallel, each with engines*sanitizers builds
        total_build_threads = 2 * num_engines * num_sanitizers
        
        if total_build_threads > 0:
            cpu_per_thread = max(1, TOTAL_CPUS // total_build_threads)
            mem_per_thread = max(1, TOTAL_RAM_GB // total_build_threads)
            safe_print(f"Resource distribution: {total_build_threads} threads, {cpu_per_thread} CPUs/thread, {mem_per_thread}GB RAM/thread")
        else:
            cpu_per_thread = None
            mem_per_thread = None

        # 1. Check GCB builds first (Pre-requisite)
        gcb_builds = await get_gcb_builds(args.project)
        gcb_success = True
        if not gcb_builds:
            safe_print("No GCB builds found. Cannot proceed.")
            gcb_success = False
        else:
            for b in gcb_builds:
                if b.get('status') != 'SUCCESS':
                    safe_print(f"GCB build {b.get('id')} is not SUCCESS (status: {b.get('status')}).")
                    gcb_success = False
        
        
        # Check health based on returned builds
        is_healthy = False
        if gcb_builds and len(gcb_builds) >= 3:
            is_healthy = all(b.get('status') == 'SUCCESS' for b in gcb_builds)
        
        if not is_healthy:
            safe_print("\n❌ GCB builds are not healthy. Skipping migration.")
            # Still generate summary but with failure
            with open(log_filepath, 'w') as results_log:
                def dual_print(message):
                    logger.info(message)
                    results_log.write(message + '\n')
                dual_print("\n========================================")
                dual_print("SUMMARY REPORT")
                dual_print("========================================")
                dual_print(f"Project: {args.project}")
                if gcb_builds:
                    dual_print("-" * 40)
                    dual_print(f"{'Build ID':<36} | {'Status':<10} | {'Link'}")
                    dual_print("-" * 40)
                    for b in gcb_builds:
                        build_id = b.get('id', 'N/A')
                        status = b.get('status', 'N/A')
                        link = f"https://console.cloud.google.com/cloud-build/builds/{build_id}?project=oss-fuzz"
                        dual_print(f"{build_id:<36} | {status:<10} | {link}")
                else:
                    dual_print("GCB Builds (fuzzing): None")
                dual_print("-" * 40)
                dual_print("\n❌ Failure: GCB builds are not healthy.")
                dual_print("Skipping PR preparation.")
                dual_print("========================================")
                dual_print(f"\nResults saved to: {log_filepath}")
            return

        # 2. Proceed with other tasks if GCB is healthy
        task_remote = asyncio.create_task(run_reproduction(args.project, local_build_path=None, os_version='legacy', dry_run=False, use_batch=args.use_batch, gcs_bucket=args.gcs_bucket, limit=args.limit))
        # Legacy builds now handle their own isolation with run_id
        task_legacy = asyncio.create_task(run_full_suite(args.project, engines, sanitizers, 'legacy', args.rebuild, build_project_name=args.project, oss_fuzz_dir=OSS_FUZZ_DIR, use_batch=args.use_batch, gcs_bucket=args.gcs_bucket, cpu_limit=cpu_per_thread, mem_limit=mem_per_thread, limit=args.limit))
        # 24.04 builds now handle their own isolation and modification with run_id
        # For Ubuntu 24.04, we need a modified OSS-Fuzz dir, but we can reuse the main one for now if we are careful,
        # or create a temporary one. Given we want isolated builds, we will create a temporary OSS-Fuzz dir for 24.04
        # to avoid modifying the main one's base images if possible, though build_local_combo handles Dockerfile changes.
        # To be safe and allow parallel 24.04 builds, we'll use a temp OSS-Fuzz dir.
        
        # Create a temporary OSS-Fuzz directory for 24.04 modifications
        temp_oss_fuzz_dir = tempfile.mkdtemp(prefix=f'oss-fuzz-2404-{args.project}-')
        
        # Symlink everything from OSS_FUZZ_DIR except projects
        for item in os.listdir(OSS_FUZZ_DIR):
            if item == 'projects':
                continue
            s = os.path.join(OSS_FUZZ_DIR, item)
            d = os.path.join(temp_oss_fuzz_dir, item)
            if os.path.isdir(s):
                os.symlink(s, d, target_is_directory=True)
            else:
                os.symlink(s, d)
        
        # Create 'projects' directory and copy only the specific project
        projects_dir = os.path.join(temp_oss_fuzz_dir, 'projects')
        os.makedirs(projects_dir, exist_ok=True)
        shutil.copytree(os.path.join(OSS_FUZZ_DIR, 'projects', args.project), os.path.join(projects_dir, args.project))
        
        # Modify files for 24.04 in the temp dir
        await modify_files_for_2404(args.project, oss_fuzz_dir=temp_oss_fuzz_dir, dry_run=False)
        
        task_2404 = asyncio.create_task(run_full_suite(args.project, engines, sanitizers, 'ubuntu-24-04', args.rebuild, build_project_name=args.project, oss_fuzz_dir=temp_oss_fuzz_dir, use_batch=args.use_batch, gcs_bucket=args.gcs_bucket, cpu_limit=cpu_per_thread, mem_limit=mem_per_thread, limit=args.limit))
        
        # Wait for all tasks
        results_list = await asyncio.gather(task_remote, task_legacy, task_2404, return_exceptions=True)
        
        # Give a moment for all subprocess output to flush
        await asyncio.sleep(1)
        
        results = {
            'gcb_status': gcb_builds,
            'remote_legacy': results_list[0] if not isinstance(results_list[0], Exception) else (0, 0, []),
            'local_legacy': (results_list[1][0], results_list[1][1]) if not isinstance(results_list[1], Exception) else (0, 0),
            'local_2404': (results_list[2][0], results_list[2][1]) if not isinstance(results_list[2], Exception) else (0, 0)
        }
        
        # Collect failures
        all_failures = []
        all_build_failures = []
        if len(results_list) > 0 and results_list[0] and not isinstance(results_list[0], Exception) and len(results_list[0]) > 2:
            all_failures.extend(results_list[0][2])
        if len(results_list) > 1 and results_list[1] and not isinstance(results_list[1], Exception) and len(results_list[1]) > 3:
            all_failures.extend(results_list[1][3])
            all_build_failures.extend(results_list[1][4])
        if len(results_list) > 2 and results_list[2] and not isinstance(results_list[2], Exception) and len(results_list[2]) > 3:
            all_failures.extend(results_list[2][3])
            all_build_failures.extend(results_list[2][4])
        
        # Collect temp dirs for cleanup (only the temp oss-fuzz dir, not the builds)
        all_temp_dirs = []
        if temp_oss_fuzz_dir:
            all_temp_dirs.append(temp_oss_fuzz_dir)
        
        safe_print("\n--- Cleaning up temporary OSS-Fuzz directories ---")
        for d in all_temp_dirs:
            if os.path.exists(d):
                safe_print(f"Removing {d}")
                safe_rmtree(d)
        
        # Open results log file for writing summary and failures
        with open(log_filepath, 'w') as results_log:
            def dual_print(message):
                logger.info(message)
                results_log.write(message + '\n')

            if all_build_failures:
                dual_print("\nFAILED BUILDS")
                dual_print("-" * 80)
                dual_print(f"{'OS':<14} | {'Engine':<10} | {'Sanitizer':<10} | {'Error'}")
                dual_print("-" * 80)
                for f in all_build_failures:
                    error_msg = f.get('error', 'Unknown error')
                    log_path = f.get('log_path', 'N/A')
                    dual_print(f"{f['os_version']:<14} | {f['engine']:<10} | {f['sanitizer']:<10} | {error_msg}")
                    if log_path != 'N/A':
                        dual_print(f"{'':<14} | {'':<10} | {'':<10} | Log: {log_path}")
                dual_print("-" * 80)

            if all_failures:
                dual_print("\nFAILED TEST CASES")
                dual_print("-" * 80)
                dual_print(f"{'TC ID':<16} | {'OS':<12} | {'Engine':<10} | {'Sanitizer':<10} | Log Path")
                dual_print("-" * 80)
                for f in all_failures:
                    engine = f['engine'] if f['engine'] else 'N/A'
                    sanitizer = f['sanitizer'] if f['sanitizer'] else 'N/A'
                    dual_print(f"{f['tc_id']:<16} | {f['os_version']:<12} | {engine:<10} | {sanitizer:<10} | {f['log_path']}")
                dual_print("-" * 80)

            dual_print("\n" + "="*40)
            dual_print("SUMMARY REPORT")
            dual_print("="*40)
            dual_print(f"Project: {args.project}")
            gcb_status = results.get('gcb_status', [])
            if gcb_status and isinstance(gcb_status[0], dict):
                gcb_status_str = ', '.join([b.get('status', 'UNKNOWN') for b in gcb_status])
            else:
                gcb_status_str = ', '.join(gcb_status)
            dual_print(f"GCB Builds (fuzzing): {gcb_status_str}")
            dual_print("-" * 40)
            dual_print(f"{'Scenario':<25} | {'Success':<7} | {'Failed':<7}")
            dual_print("-" * 40)
            
            def print_res_dual(name, res):
                if isinstance(res, tuple) and len(res) >= 2:
                    dual_print(f"{name:<25} | {res[0]:<7} | {res[1]:<7}")
                else:
                    dual_print(f"{name:<25} | Error   | Error")

            print_res_dual('Remote (Legacy)', results.get('remote_legacy'))
            print_res_dual('Local (Legacy)', results.get('local_legacy'))
            print_res_dual('Local (Ubuntu 24.04)', results.get('local_2404'))
            dual_print("-" * 40)
            
            success_remote = results['remote_legacy'][0] if isinstance(results['remote_legacy'], tuple) else 0
            success_local_legacy = results['local_legacy'][0] if isinstance(results['local_legacy'], tuple) else 0
            success_local_2404 = results['local_2404'][0] if isinstance(results['local_2404'], tuple) else 0
            
            # Apply new rules:
            # 1. Legacy Local >= 70% of Legacy Remote
            # 2. Ubuntu 24.04 >= 70% of Legacy Local
            
            # Calculate 70% of legacy remote
            threshold_legacy = success_remote * 0.7
            legacy_match = (success_local_legacy >= threshold_legacy) and (success_remote > 0)
            
            # Calculate 70% of legacy local
            threshold_2404 = success_local_legacy * 0.7
            ubuntu_2404_acceptable = (success_local_2404 >= threshold_2404)
            
            if legacy_match and ubuntu_2404_acceptable and success_local_legacy > 0:
                dual_print("\n✅ Success: Results meet criteria for PR.")
                if success_local_2404 < success_local_legacy:
                    dual_print(f"⚠️ Warning: Ubuntu 24.04 had fewer successes ({success_local_2404}) than Legacy ({success_local_legacy}), but is within 30% tolerance.")
                if success_local_legacy < success_remote:
                     dual_print(f"⚠️ Warning: Legacy Local had fewer successes ({success_local_legacy}) than Remote ({success_remote}), but is within 30% tolerance.")
                if success_local_legacy > success_remote:
                    dual_print(f"ℹ️ Note: Legacy Local had more successes ({success_local_legacy}) than Remote ({success_remote}).")
                
                dual_print("PR preparation skipped (use separate script to create branch).")
            else:
                dual_print("\n❌ Failure: Results do not meet criteria for PR.")
                if not legacy_match:
                    if success_remote == 0:
                        dual_print(f"  - Legacy Remote has 0 successes.")
                    elif success_local_legacy < threshold_legacy:
                        dual_print(f"  - Legacy Local ({success_local_legacy}) is below 70% of Remote ({success_remote}). Threshold: {threshold_legacy:.1f}")
                if not ubuntu_2404_acceptable:
                    dual_print(f"  - Ubuntu 24.04 ({success_local_2404}) is below 70% of Legacy ({success_local_legacy}). Threshold: {threshold_2404:.1f}")
                if success_local_legacy == 0:
                    dual_print("  - Legacy Local has 0 successes.")
                dual_print("Skipping PR preparation.")
            dual_print("="*40)
            dual_print(f"\nResults saved to: {log_filepath}")

    except Exception as e:
        safe_print(f"An error occurred: {e}")
        traceback.print_exc()
    finally:
        # Fallback cleanup in case of exceptions before normal cleanup
        if 'all_temp_dirs' in locals():
            for d in all_temp_dirs:
                if os.path.exists(d):
                    shutil.rmtree(d)

if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    finally:
        restore_terminal()
