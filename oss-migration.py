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

# Paths (adjust if necessary)
OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'
CLUSTERFUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/clusterfuzz'
CASP_PYTHONPATH = 'cli/casp/src:src'

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
    os._exit(1)

signal.signal(signal.SIGINT, force_exit_handler)
signal.signal(signal.SIGTERM, force_exit_handler)

def safe_print(message):
    logger.info(message)

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

async def run_command(cmd, cwd, env=None, capture_output=False, dry_run=False, prefix=None):    
    safe_print(f"Running command: {cmd} in {cwd}")
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            preexec_fn=os.setsid
        )
        active_processes.append(process)
        
        output_lines = []
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            try:
                decoded_line = line.decode('utf-8').strip()
            except:
                decoded_line = line.decode('latin-1', errors='replace').strip()
            
            if decoded_line:
                # Remove ANSI escape codes and control characters for cleaner logs
                decoded_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', decoded_line)
                decoded_line = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', decoded_line)
                
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
    cmd = f"gcloud builds list --project=oss-fuzz --region=us-central1 --filter=\"tags='{project}' AND tags='fuzzing'\" --limit=3 --format=json"
    output = await run_command(cmd, OSS_FUZZ_DIR, capture_output=True)
    
    if not output or json.loads(output) == []:
        safe_print("No builds found in us-central1, trying global...")
        cmd = f"gcloud builds list --project=oss-fuzz --filter=\"tags='{project}' AND tags='fuzzing'\" --limit=3 --format=json"
        output = await run_command(cmd, OSS_FUZZ_DIR, capture_output=True)

    if output:
        try:
            builds = json.loads(output)
            safe_print(f"Found {len(builds)} recent fuzzing builds:")
            for b in builds:
                safe_print(f"  - ID: {b['id']}, Status: {b['status']}, Created: {b['createTime']}")
            return builds
        except json.JSONDecodeError:
            safe_print("Failed to parse GCB output.")
    return []

async def run_reproduction(project, local_build_path=None, os_version='legacy', engine=None, sanitizer=None, dry_run=False):
    safe_print(f"\n--- Running reproduction for {project} (OS: {os_version}, Engine: {engine}, Sanitizer: {sanitizer}, Local Build: {local_build_path}) ---")
    
    env = os.environ.copy()
    env['PYTHONPATH'] = CASP_PYTHONPATH
    
    cmd = f"python3.11 -m pipenv run python3 -m casp.main reproduce project --project-name {project} -n 10 -e external --os-version {os_version}"
    if local_build_path:
        cmd += f" --local-build-path {local_build_path}"
    if engine:
        cmd += f" --engine {engine}"
    if sanitizer:
        cmd += f" --sanitizer {sanitizer}"
    
    prefix_engine = engine if engine else "all"
    prefix_sanitizer = sanitizer if sanitizer else "all"
    safe_print(f"[{os_version}-{prefix_engine}-{prefix_sanitizer}] Running command: {cmd}")
    output = await run_command(cmd, CLUSTERFUZZ_DIR, env=env, capture_output=True, dry_run=False, prefix=f"[{os_version}-{prefix_engine}-{prefix_sanitizer}]")
    
    if not output:
        return 0, 0
    
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
                            if "Success" not in content and "Didn't crash at all" in content:
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

async def build_local_combo(project, run_id, engine, sanitizer, os_version, no_rebuild, build_project_name=None, oss_fuzz_dir=None, dry_run=False):
    if not oss_fuzz_dir:
        oss_fuzz_dir = OSS_FUZZ_DIR
    if not build_project_name:
        build_project_name = project
    
    # Create a unique but stable temporary directory for this combination
    # If run_id is provided, include it for isolation. Otherwise, use a stable name for reuse.
    combo_dir_name = f"{project}-{os_version}-{engine}-{sanitizer}"
    if run_id:
        combo_dir_name = f"{project}-{run_id}-{os_version}-{engine}-{sanitizer}"
    
    safe_print(f"[{os_version}-{engine}-{sanitizer}] Using combo_dir_name: {combo_dir_name}")
    
    temp_base_dir_root = '/usr/local/google/home/matheushunsche/projects/oss-fuzz-temp'
    os.makedirs(temp_base_dir_root, exist_ok=True)
    recursive_chmod(temp_base_dir_root, 0o755) # Ensure root dir is accessible
    combo_temp_dir = os.path.join(temp_base_dir_root, combo_dir_name)
    
    # If no_rebuild is False, we want a clean build, so remove existing dir if it exists
    if not no_rebuild and os.path.exists(combo_temp_dir):
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Removing existing build dir for clean build: {combo_temp_dir}")
        shutil.rmtree(combo_temp_dir)
    
    # The build output will stay within this directory
    combo_out_dir = os.path.join(combo_temp_dir, 'build', 'out', build_project_name)

    repro_results = (0, 0, []) # Default to 0 successes/failures, no failures list

    if no_rebuild and os.path.exists(combo_out_dir) and os.listdir(combo_out_dir):
        safe_print(f"Skipping build for {engine}-{sanitizer} ({os_version}) as directory exists and is not empty.")
        # Still need to run reproduction if skipped build? Yes, usually.
        repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False)
        return combo_out_dir, combo_temp_dir, repro_results

    if not os.path.exists(combo_temp_dir):
        os.makedirs(combo_temp_dir, exist_ok=True)
        recursive_chmod(combo_temp_dir, 0o755) # Ensure combo dir is accessible
        safe_print(f"Created persistent isolated build dir: {combo_temp_dir}")
        
        # Set up OSS-Fuzz environment in temp dir
        os.symlink(os.path.join(oss_fuzz_dir, 'infra'), os.path.join(combo_temp_dir, 'infra'))
        os.symlink(os.path.join(oss_fuzz_dir, 'base-images'), os.path.join(combo_temp_dir, 'base-images'))
        os.symlink(os.path.join(oss_fuzz_dir, 'build.py'), os.path.join(combo_temp_dir, 'build.py'))
        
        project_temp_dir = os.path.join(combo_temp_dir, 'projects', build_project_name)
        os.makedirs(os.path.dirname(project_temp_dir), exist_ok=True)

        if os_version == 'ubuntu-24-04':
            # For 24.04, copy and modify
            shutil.copytree(os.path.join(oss_fuzz_dir, 'projects', build_project_name), project_temp_dir)
            
            # Modify Dockerfile
            dockerfile_path = os.path.join(project_temp_dir, 'Dockerfile')
            if os.path.exists(dockerfile_path):
                with open(dockerfile_path, 'r') as f:
                    content = f.read()
                content = re.sub(r'FROM\s+gcr\.io/clusterfuzz-images/base/runner', 'FROM gcr.io/clusterfuzz-images/base/runner:ubuntu-24-04', content)
                content = re.sub(r'FROM\s+msan-builder', 'FROM msan-builder:ubuntu-24-04', content)
                with open(dockerfile_path, 'w') as f:
                    f.write(content)
            
            # Modify project.yaml
            yaml_path = os.path.join(project_temp_dir, 'project.yaml')
            if os.path.exists(yaml_path):
                with open(yaml_path, 'r') as f:
                    content = f.read()
                if 'base_os_version:' not in content:
                    content += '\nbase_os_version: ubuntu-24-04\n'
                else:
                    content = re.sub(r'base_os_version:.*', 'base_os_version: ubuntu-24-04', content)
                with open(yaml_path, 'w') as f:
                    f.write(content)
        # For Legacy, just symlink
        if not os.path.exists(project_temp_dir):
            os.symlink(os.path.join(oss_fuzz_dir, 'projects', build_project_name), project_temp_dir)
    else:
        safe_print(f"Using existing isolated build dir: {combo_temp_dir}")
    
    # Ensure essential symlinks exist even if directory existed
    for link_name in ['infra', 'base-images', 'build.py']:
        link_path = os.path.join(combo_temp_dir, link_name)
        if os.path.exists(link_path) or os.path.islink(link_path):
            try:
                os.remove(link_path)
            except:
                pass
        os.symlink(os.path.join(oss_fuzz_dir, link_name), link_path)
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Created symlink: {link_path} -> {os.path.join(oss_fuzz_dir, link_name)}")

    # Fallback check in case helper.py still used real OSS_FUZZ_DIR (unlikely now but safe)
    real_oss_fuzz_out = os.path.join(oss_fuzz_dir, 'build', 'out', build_project_name)
    if os.path.exists(real_oss_fuzz_out) and os.listdir(real_oss_fuzz_out):
            safe_print(f"[{os_version}-{engine}-{sanitizer}] Found output in real OSS_FUZZ_DIR, moving to persistent dir.")
            if os.path.exists(combo_out_dir):
                if not dry_run:
                    shutil.rmtree(combo_out_dir)
            if not dry_run:
                os.makedirs(os.path.dirname(combo_out_dir), exist_ok=True)
                shutil.move(real_oss_fuzz_out, combo_out_dir)
                os.makedirs(real_oss_fuzz_out, exist_ok=True) # Recreate empty dir to avoid issues
            else:
                safe_print(f"Dry run: Would move {real_oss_fuzz_out} to {combo_out_dir}")
            # Run reproduction immediately after move
            repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False)
            return combo_out_dir, combo_temp_dir, repro_results

    # Run build using helper.py within the isolated environment
    # We need to run this from within combo_temp_dir to use the local infra and projects
    cmd = f"python3 infra/helper.py build_image --no-pull {build_project_name}"
    safe_print(f"[{os_version}-{engine}-{sanitizer}] Running build command: {cmd} in {combo_temp_dir}")
    await run_command(cmd, combo_temp_dir, capture_output=False, dry_run=False, prefix=f"[{os_version}-{engine}-{sanitizer}]")

    cmd = f"python3 infra/helper.py build_fuzzers --engine {engine} --sanitizer {sanitizer} {build_project_name}"
    safe_print(f"[{os_version}-{engine}-{sanitizer}] Running build command: {cmd} in {combo_temp_dir}")
    await run_command(cmd, combo_temp_dir, capture_output=False, dry_run=False, prefix=f"[{os_version}-{engine}-{sanitizer}]")
    
    # After build, ensure permissions are correct for Docker access
    recursive_chmod(combo_temp_dir, 0o755)

    # After build, check if output exists
    if not os.path.exists(combo_out_dir) or not os.listdir(combo_out_dir):
        safe_print(f"[{os_version}-{engine}-{sanitizer}] Build failed or no output generated in {combo_out_dir}")
        return combo_out_dir, combo_temp_dir, (0, 0, [])
    
    # Run reproduction
    repro_results = await run_reproduction(project, local_build_path=combo_out_dir, os_version=os_version, engine=engine, sanitizer=sanitizer, dry_run=False)
    
    return combo_out_dir, combo_temp_dir, repro_results

async def build_local(project, run_id, engines=None, sanitizers=None, dry_run=False, no_rebuild=False, os_version='legacy', build_project_name=None, oss_fuzz_dir=None):
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
            tasks.append(build_local_combo(project, run_id, engine, sanitizer, os_version, no_rebuild, build_project_name, oss_fuzz_dir, dry_run))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    build_paths = []
    temp_dirs = []
    total_success = 0
    total_failed = 0
    all_failures = []
    
    for res in results:
        if isinstance(res, Exception):
            safe_print(f"Build/Reproduction failed: {res}")
        elif res:
            out_dir, temp_dir, (success, failed, failures) = res
            build_paths.append(out_dir)
            temp_dirs.append(temp_dir)
            total_success += success
            total_failed += failed
            all_failures.extend(failures)
    return build_paths, temp_dirs, total_success, total_failed, all_failures

async def modify_files_for_2404(project, oss_fuzz_dir, dry_run=False):
    safe_print(f"\n--- Modifying files for Ubuntu 24.04 in {oss_fuzz_dir} ---")
    project_yaml = os.path.join(oss_fuzz_dir, 'projects', project, 'project.yaml')
    dockerfile = os.path.join(oss_fuzz_dir, 'projects', project, 'Dockerfile')
    
    # Backup original files before modification
    if not dry_run:
        shutil.copy(project_yaml, project_yaml + '.bak')
        shutil.copy(dockerfile, dockerfile + '.bak')
    
        with open(project_yaml, 'a') as f:
            f.write("\nbase_os_version: 'ubuntu-24-04'\n")
        
        with open(dockerfile, 'r') as f:
            content = f.read()
        with open(dockerfile, 'w') as f:
            f.write(content.replace('FROM gcr.io/oss-fuzz-base/base-builder', 'FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04'))
    else:
        safe_print(f"Dry run: Would modify {project_yaml} and {dockerfile}")

async def revert_files(project, oss_fuzz_dir, dry_run=False):
    safe_print(f"\n--- Reverting files in {oss_fuzz_dir} ---")
    project_yaml = os.path.join(oss_fuzz_dir, 'projects', project, 'project.yaml')
    dockerfile = os.path.join(oss_fuzz_dir, 'projects', project, 'Dockerfile')
    
    if not dry_run:
        if os.path.exists(project_yaml + '.bak'):
            shutil.move(project_yaml + '.bak', project_yaml)
        if os.path.exists(dockerfile + '.bak'):
            shutil.move(dockerfile + '.bak', dockerfile)
    else:
        safe_print(f"Dry run: Would revert {project_yaml} and {dockerfile}")

async def prepare_pr_branch(project, results, dry_run=False):
    safe_print(f"\n--- Preparing PR Branch for {project} ---")
    branch_name = f"upgrade-{project}-to-ubuntu-24-04"
    
    await run_command("git checkout master", OSS_FUZZ_DIR, dry_run=dry_run)
    await run_command("git pull origin master", OSS_FUZZ_DIR, dry_run=dry_run)
    await run_command(f"git branch -D {branch_name}", OSS_FUZZ_DIR, dry_run=dry_run)
    await run_command(f"git checkout -b {branch_name}", OSS_FUZZ_DIR, dry_run=dry_run)
    
    await modify_files_for_2404(project, OSS_FUZZ_DIR, dry_run=dry_run)
    
    await run_command(f"git add projects/{project}/project.yaml projects/{project}/Dockerfile", OSS_FUZZ_DIR, dry_run=dry_run)
    commit_msg = f"Upgrade {project} to Ubuntu 24.04"
    await run_command(f"git commit -m \"{commit_msg}\"", OSS_FUZZ_DIR, dry_run=dry_run)
    
    contacts = get_project_contacts(project)
    cc_list = ", ".join(contacts)
    
    pr_body = f"""
### Summary

This pull request migrates the `{project}` project to use the new `ubuntu-24-04` base image for fuzzing.

### Changes in this PR

1.  **`projects/{project}/project.yaml`**: Sets the `base_os_version` property to `ubuntu-24-04`.
2.  **`projects/{project}/Dockerfile`**: Updates the `FROM` instruction.

CC: {cc_list}
"""
    safe_print("\n" + "="*40)
    safe_print("PR PREPARED SUCCESSFULLY")
    safe_print("="*40)
    safe_print(f"Branch '{branch_name}' created and committed.")
    safe_print("\nTo push and open PR, run:")
    safe_print(f"cd {OSS_FUZZ_DIR}")
    safe_print(f"git push origin {branch_name}")
    safe_print(f"gh pr create --title \"Upgrade {project} to Ubuntu 24.04\" --body \"{pr_body}\"")
    safe_print("="*40)

async def run_full_suite(project, run_id, engines, sanitizers, os_version, no_rebuild, build_project_name=None, oss_fuzz_dir=None):
    if build_project_name is None:
        build_project_name = project
    
    safe_print(f"\n--- Running Full Suite for {project} on {os_version} ---")
    build_paths, temp_dirs, total_success, total_failed, failures = await build_local(project, run_id, engines=engines, sanitizers=sanitizers, dry_run=False, no_rebuild=no_rebuild, os_version=os_version, build_project_name=build_project_name, oss_fuzz_dir=oss_fuzz_dir)
    
    return total_success, total_failed, temp_dirs, failures

async def main_async():
    parser = argparse.ArgumentParser(description='Verify OSS-Fuzz project builds and reproduction.')
    parser.add_argument('project', help='OSS-Fuzz project name')
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without making changes')
    parser.add_argument('--no-rebuild', action='store_true', help='Skip rebuilding if build directory exists')
    parser.add_argument('--no-cleanup', action='store_true', help='Do not cleanup temporary build directories')
    parser.add_argument('--run-id', help='Optional run ID for isolated builds')
    args = parser.parse_args()
    
    # Setup persistent log file for results only
    temp_base_dir_root = '/usr/local/google/home/matheushunsche/projects/oss-fuzz-temp'
    results_dir = os.path.join(temp_base_dir_root, 'results')
    os.makedirs(results_dir, exist_ok=True)
    run_id = args.run_id
    if run_id is None:
        run_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_filename = f"{args.project}_{run_id}_{timestamp}.log"
    log_filepath = os.path.join(results_dir, log_filename)
    
    safe_print(f"Starting main... Full output on console, results will be saved to {log_filepath}")
    safe_print(f"Args: {args}")
    results = {}
    temp_oss_fuzz_dir = None
    all_temp_dirs = [] # Initialize all_temp_dirs here
    
    try:
        engines, sanitizers = get_project_config(args.project)
        safe_print(f"Found engines: {engines}")
        safe_print(f"Found sanitizers: {sanitizers}")
        
        # Run ID already generated above
        safe_print(f"Run ID: {run_id}")
        
        safe_print("Starting parallel execution...")
        
        # Define tasks
        task_gcb = asyncio.create_task(get_gcb_builds(args.project))
        task_remote = asyncio.create_task(run_reproduction(args.project, local_build_path=None, os_version='legacy', dry_run=False))
        # Legacy builds now handle their own isolation with run_id
        task_legacy = asyncio.create_task(run_full_suite(args.project, run_id, engines, sanitizers, 'legacy', args.no_rebuild, build_project_name=args.project, oss_fuzz_dir=OSS_FUZZ_DIR))
        # 24.04 builds now handle their own isolation and modification with run_id
        # For Ubuntu 24.04, we need a modified OSS-Fuzz dir, but we can reuse the main one for now if we are careful,
        # or create a temporary one. Given we want isolated builds, we will create a temporary OSS-Fuzz dir for 24.04
        # to avoid modifying the main one's base images if possible, though build_local_combo handles Dockerfile changes.
        # To be safe and allow parallel 24.04 builds, we'll use a temp OSS-Fuzz dir.
        
        # Create a temporary OSS-Fuzz directory for Ubuntu 24.04 modifications
        temp_oss_fuzz_dir = tempfile.mkdtemp(prefix=f'oss-fuzz-2404-{args.project}-')
        # Symlink everything from main OSS-Fuzz dir
        for item in os.listdir(OSS_FUZZ_DIR):
            s = os.path.join(OSS_FUZZ_DIR, item)
            d = os.path.join(temp_oss_fuzz_dir, item)
            if os.path.islink(s):
                # Handle symlinks by recreating them in the temp dir
                target = os.readlink(s)
                os.symlink(target, d)
            elif os.path.isdir(s):
                os.symlink(s, d)
            else:
                os.symlink(s, d)
        
        # Modify files for 24.04 in the temp dir
        await modify_files_for_2404(args.project, oss_fuzz_dir=temp_oss_fuzz_dir, dry_run=args.dry_run)
        
        task_2404 = asyncio.create_task(run_full_suite(args.project, run_id, engines, sanitizers, 'ubuntu-24-04', args.no_rebuild, build_project_name=args.project, oss_fuzz_dir=temp_oss_fuzz_dir))
        
        # Wait for all tasks
        results_list = await asyncio.gather(task_gcb, task_remote, task_legacy, task_2404, return_exceptions=True)
        
        # Give a moment for all subprocess output to flush
        await asyncio.sleep(1)
        
        results = {
            'gcb_status': results_list[0] if not isinstance(results_list[0], Exception) else [],
            'remote_legacy': results_list[1] if not isinstance(results_list[1], Exception) else (0, 0, []),
            'local_legacy': (results_list[2][0], results_list[2][1]) if not isinstance(results_list[2], Exception) else (0, 0),
            'local_2404': (results_list[3][0], results_list[3][1]) if not isinstance(results_list[3], Exception) else (0, 0)
        }
        
        # Collect failures
        all_failures = []
        if not isinstance(results_list[1], Exception):
            all_failures.extend(results_list[1][2])
        if not isinstance(results_list[2], Exception):
            all_failures.extend(results_list[2][3])
        if not isinstance(results_list[3], Exception):
            all_failures.extend(results_list[3][3])
        
        # Collect temp dirs for cleanup
        all_temp_dirs = []
        if not isinstance(results_list[2], Exception):
            all_temp_dirs.extend(results_list[2][2])
        if not isinstance(results_list[3], Exception):
            all_temp_dirs.extend(results_list[3][2])
        
        if not args.no_cleanup:
            safe_print("\n--- Cleaning up temporary build directories ---")
            for d in all_temp_dirs:
                if os.path.exists(d):
                    safe_print(f"Removing {d}")
                    shutil.rmtree(d)
        else:
            safe_print("\n--- Cleanup skipped per --no-cleanup flag ---")
            for d in all_temp_dirs:
                safe_print(f"Kept: {d}")
        
        # Open results log file for writing summary and failures
        with open(log_filepath, 'w') as results_log:
            def dual_print(message):
                logger.info(message)
                results_log.write(message + '\n')

            if all_failures:
                dual_print("\nFAILED TEST CASES")
                dual_print("-" * 80)
                dual_print(f"{'TC ID':<16} | {'OS':<12} | {'Engine':<10} | {'Sanitizer':<10} | Log Path")
                dual_print("-" * 80)
                for f in all_failures:
                    dual_print(f"{f['tc_id']:<16} | {f['os_version']:<12} | {f['engine']:<10} | {f['sanitizer']:<10} | {f['log_path']}")
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
            
            if success_remote == success_local_legacy == success_local_2404 and success_local_2404 > 0:
                dual_print("\n✅ Success: Remote, Local Legacy, and Local 24.04 results match and are non-zero.")
                dual_print("Proceeding with PR preparation...")
                # Note: prepare_pr_branch still uses safe_print, which is fine as it's not part of the results log
                await prepare_pr_branch(args.project, results, dry_run=args.dry_run)
            else:
                dual_print("\n❌ Failure: Results do not match or are zero.")
                dual_print(f"Remote: {success_remote}, Local Legacy: {success_local_legacy}, Local 24.04: {success_local_2404}")
                dual_print("Skipping PR preparation.")
            dual_print("="*40)
            dual_print(f"\nResults saved to: {log_filepath}")

    except Exception as e:
        safe_print(f"An error occurred: {e}")
    finally:
        # Fallback cleanup in case of exceptions before normal cleanup
        if not args.no_cleanup and 'all_temp_dirs' in locals():
            for d in all_temp_dirs:
                if os.path.exists(d):
                    shutil.rmtree(d)

if __name__ == "__main__":
    asyncio.run(main_async())
