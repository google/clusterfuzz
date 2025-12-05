#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import datetime
from typing import List, Dict, Optional, Tuple

# Configuration
OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'
CONCURRENCY_LIMIT = 20  # Number of concurrent gcloud calls

async def run_command(cmd: List[str], cwd: str = None) -> Tuple[int, str, str]:
    """Runs a command asynchronously and returns (returncode, stdout, stderr)."""
    process = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace')

async def get_project_builds(project: str, semaphore: asyncio.Semaphore) -> Optional[Dict]:
    """
    Fetches recent builds for a project.
    Returns a dict with metadata if the project meets criteria (last 3 failed), else None.
    """
    async with semaphore:
        # Try us-central1 first (matching oss-migration.py logic)
        cmd_region = [
            'gcloud', 'builds', 'list',
            f'--project=oss-fuzz',
            f'--region=us-central1',
            f'--filter=tags="{project}" AND tags="fuzzing"',
            '--limit=20',
            '--format=json',
            '--sort-by=~createTime'
        ]
        
        rc, stdout, stderr = await run_command(cmd_region)
        builds = []
        if rc == 0:
            try:
                builds = json.loads(stdout)
            except json.JSONDecodeError:
                pass
        
        # If no builds in us-central1, try global
        if not builds:
            cmd_global = [
                'gcloud', 'builds', 'list',
                f'--project=oss-fuzz',
                f'--filter=tags="{project}" AND tags="fuzzing"',
                '--limit=20',
                '--format=json',
                '--sort-by=~createTime'
            ]
            rc, stdout, stderr = await run_command(cmd_global)
            if rc == 0:
                try:
                    builds = json.loads(stdout)
                except json.JSONDecodeError:
                    pass

        if not builds or len(builds) < 3:
            return None

        # Ensure strict sorting by createTime just in case gcloud didn't respect it perfectly (it should, but safety first)
        # GCB timestamps are ISO 8601 strings, so string comparison works for YYYY-MM-DDTHH:MM:SS...
        builds.sort(key=lambda x: x.get('createTime', ''), reverse=True)

        # Check last 3 builds (most recent 3)
        last_3 = builds[:3]
        all_failed = all(b.get('status') != 'SUCCESS' for b in last_3)

        if not all_failed:
            return None

        # Find last success
        last_success = None
        for b in builds:
            if b.get('status') == 'SUCCESS':
                last_success = b
                break
        
        return {
            'project': project,
            'last_success': last_success,
            'recent_failures': last_3
        }

def modify_project_files(project: str) -> bool:
    """Modifies project.yaml and Dockerfile for Ubuntu 24.04 migration."""
    project_dir = os.path.join(OSS_FUZZ_DIR, 'projects', project)
    project_yaml = os.path.join(project_dir, 'project.yaml')
    dockerfile = os.path.join(project_dir, 'Dockerfile')

    if not os.path.exists(project_yaml) or not os.path.exists(dockerfile):
        return False

    modified = False

    # Modify project.yaml
    try:
        with open(project_yaml, 'r') as f:
            content = f.read()
        
        if 'base_os_version: ubuntu-24-04' not in content:
            if 'base_os_version:' in content:
                 # Replace existing
                new_content = re.sub(r'base_os_version:.*', 'base_os_version: ubuntu-24-04', content)
            else:
                # Prepend
                new_content = 'base_os_version: ubuntu-24-04\n' + content
            
            if new_content != content:
                with open(project_yaml, 'w') as f:
                    f.write(new_content)
                modified = True
    except Exception as e:
        print(f"Failed to modify project.yaml for {project}: {e}")
        return False

    # Modify Dockerfile
    try:
        with open(dockerfile, 'r') as f:
            content = f.read()
        
        if 'ubuntu-24-04' not in content:
            # Replace base image
            new_content = re.sub(
                r'FROM\s+(gcr\.io/oss-fuzz-base/base-builder(?:-[a-z0-9]+)?)(?::\w+)?',
                r'FROM \1:ubuntu-24-04',
                content
            )
            if new_content != content:
                with open(dockerfile, 'w') as f:
                    f.write(new_content)
                modified = True
    except Exception as e:
        print(f"Failed to modify Dockerfile for {project}: {e}")
        return False

    return modified

async def main():
    parser = argparse.ArgumentParser(description='Batch migrate failing OSS-Fuzz projects.')
    parser.add_argument('--dry-run', action='store_true', help='Do not make changes, just list projects.')
    parser.add_argument('--preview-pr', action='store_true', help='Close existing PRs and preview new PR description without creating it.')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of projects to process.')
    parser.add_argument('--project', help='Specific project to process.')
    args = parser.parse_args()

    print(f"Scanning projects in {OSS_FUZZ_DIR}...")
    projects_dir = os.path.join(OSS_FUZZ_DIR, 'projects')
    
    if args.project:
        all_projects = [args.project]
    else:
        all_projects = [d for d in os.listdir(projects_dir) if os.path.isdir(os.path.join(projects_dir, d))]
    
    if args.limit:
        all_projects = all_projects[:args.limit]

    print(f"Found {len(all_projects)} projects. Checking GCB status...")

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [get_project_builds(p, semaphore) for p in all_projects]
    
    results = []
    # Use tqdm if available, else simple print
    try:
        from tqdm import tqdm
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks)):
            res = await f
            if res:
                results.append(res)
    except ImportError:
        done_count = 0
        for f in asyncio.as_completed(tasks):
            res = await f
            if res:
                results.append(res)
            done_count += 1
            if done_count % 10 == 0:
                print(f"Checked {done_count}/{len(all_projects)} projects...", end='\r')
        print()

    print(f"Found {len(results)} projects failing last 3 builds.")

    # Sort by last success time (descending - most recent success first)
    def get_success_time(item):
        ls = item['last_success']
        if ls:
            return ls.get('createTime', '')
        return ''

    results.sort(key=get_success_time, reverse=True)

    if not results:
        print("No projects found matching criteria.")
        return

    # Create PR Description
    pr_body = "### Batch Migration to Ubuntu 24.04\n\n"
    pr_body += "This Pull Request performs a batch migration of OSS-Fuzz projects that are currently **consistently failing** in the legacy build environment.\n\n"
    pr_body += "#### Rationale\n"
    pr_body += "The projects listed below have failed their last 3 consecutive builds on Google Cloud Build (GCB). As they are currently not producing any fuzzing results, migrating them to **Ubuntu 24.04** offers several advantages:\n"
    pr_body += "1. **Modern Environment**: Access to a newer toolchain and updated system dependencies.\n"
    pr_body += "2. **Potential Fixes**: The new environment may resolve issues related to deprecated or missing packages in the legacy environment.\n"
    pr_body += "3. **No Regression Risk**: Since these projects are already in a broken state, this migration does not introduce new regressions but rather provides a path forward for recovery.\n\n"
    
    pr_body += "#### Automated Selection Criteria\n"
    pr_body += "Projects were automatically selected based on the following strict criteria:\n"
    pr_body += "- **3/3 Recent Failures**: The last 3 builds tagged with `fuzzing` have a status of `FAILURE`, `TIMEOUT`, or `INTERNAL_ERROR`.\n"
    pr_body += "- **Legacy Environment**: The failures occurred in the legacy environment (prior to this migration).\n\n"

    pr_body += "#### Migrated Projects\n"
    pr_body += "The table below details the migration candidates, sorted by their last successful build date (most recent success first).\n\n"
    
    pr_body += "| # | Project | Last Successful Build | Failed Build 1 (Latest) | Failed Build 2 | Failed Build 3 |\n"
    pr_body += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
    
    for idx, item in enumerate(results, 1):
        p = item['project']
        ls = item['last_success']
        failures = item['recent_failures'] # List of 3 failed builds
        
        # Format Last Success
        if ls:
            ts = ls.get('createTime', 'N/A').split('T')[0] # Just date
            link = ls.get('logUrl') or f"https://console.cloud.google.com/cloud-build/builds/{ls['id']}?project=oss-fuzz"
            success_cell = f"[{ts}]({link})"
        else:
            success_cell = "N/A"

        # Format Failures
        fail_cells = []
        for b in failures:
            ts = b.get('createTime', 'N/A').split('T')[0]
            link = b.get('logUrl') or f"https://console.cloud.google.com/cloud-build/builds/{b['id']}?project=oss-fuzz"
            fail_cells.append(f"[{ts}]({link})")
        
        # Pad if fewer than 3 failures (though logic ensures 3)
        while len(fail_cells) < 3:
            fail_cells.append("-")

        pr_body += f"| {idx} | {p} | {success_cell} | {fail_cells[0]} | {fail_cells[1]} | {fail_cells[2]} |\n"

    if args.dry_run:
        print("\n--- DRY RUN: PR Description Preview ---")
        print(pr_body)
        print("---------------------------------------")
        print("Dry run completed. No changes made.")
        return

    if args.preview_pr:
        print("\n--- PREVIEW: PR Description ---")
        print(pr_body)
        print("-------------------------------")
        
        # Close existing PRs if any (logic to close PRs with 'batch-ubuntu-migration' in title or branch)
        # We can search for PRs created by us or with specific title pattern
        print("Checking for existing batch migration PRs to close...")
        try:
            # Find PRs with "Batch Migration" in title
            cmd = ['gh', 'pr', 'list', '--search', 'Batch Migration to Ubuntu 24.04', '--json', 'number', '--jq', '.[].number']
            rc, stdout, stderr = await run_command(cmd, cwd=OSS_FUZZ_DIR)
            if rc == 0 and stdout.strip():
                pr_nums = stdout.strip().split()
                for pr_num in pr_nums:
                    print(f"Closing existing PR #{pr_num}...")
                    await run_command(['gh', 'pr', 'close', pr_num, '--delete-branch'], cwd=OSS_FUZZ_DIR)
            else:
                print("No existing PRs found to close.")
        except Exception as e:
            print(f"Error closing PRs: {e}")
            
        print("Preview mode: PR closed (if any), new PR not created.")
        return

    # Create Branch
    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    branch_name = f"batch-ubuntu-migration-{timestamp}"
    print(f"\nCreating branch {branch_name}...")
    subprocess.check_call(['git', 'checkout', 'master'], cwd=OSS_FUZZ_DIR)
    subprocess.check_call(['git', 'pull', 'origin', 'master'], cwd=OSS_FUZZ_DIR)
    subprocess.check_call(['git', 'checkout', '-b', branch_name], cwd=OSS_FUZZ_DIR)

    migrated_count = 0
    for item in results:
        p = item['project']
        if modify_project_files(p):
            print(f"Migrated {p}")
            migrated_count += 1
        else:
            print(f"Skipped {p} (files not found or failed)")

    if migrated_count == 0:
        print("No projects migrated.")
        return

    # Commit
    print("Committing changes...")
    subprocess.check_call(['git', 'add', 'projects/'], cwd=OSS_FUZZ_DIR)
    subprocess.check_call(['git', 'commit', '-m', f'Batch migrate {migrated_count} failing projects to Ubuntu 24.04'], cwd=OSS_FUZZ_DIR)

    # Push
    print("Pushing branch...")
    subprocess.check_call(['git', 'push', 'origin', branch_name], cwd=OSS_FUZZ_DIR)

    pr_file = f"/tmp/pr_body_{timestamp}.md"
    with open(pr_file, 'w') as f:
        f.write(pr_body)

    # Open PR
    print("Creating Pull Request...")
    try:
        cmd = [
            'gh', 'pr', 'create',
            '--title', f'Batch Migration: {migrated_count} failing projects to Ubuntu 24.04',
            '--body-file', pr_file,
            '--base', 'master',
            '--head', branch_name
        ]
        subprocess.check_call(cmd, cwd=OSS_FUZZ_DIR)
        print("PR created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create PR: {e}")

if __name__ == '__main__':
    asyncio.run(main())
