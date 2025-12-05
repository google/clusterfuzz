#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import datetime
import time
from typing import List, Set

# Configuration
OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'
BATCH_SIZE = 100

def run_command(cmd: List[str], cwd: str = None, check: bool = True) -> str:
    """Runs a command and returns stdout."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {' '.join(cmd)}")
        print(f"Stderr: {e.stderr}")
        if check:
            raise
        return ""

def get_project_contacts(project: str) -> Set[str]:
    """Extracts contacts from project.yaml."""
    project_yaml = os.path.join(OSS_FUZZ_DIR, 'projects', project, 'project.yaml')
    contacts = set()
    if os.path.exists(project_yaml):
        try:
            with open(project_yaml, 'r') as f:
                content = f.read()
            
            # Primary contact
            pc_match = re.search(r'primary_contact:\s+"?([^"\n]+)"?', content)
            if pc_match:
                contacts.add(pc_match.group(1))
            
            # Auto CCs
            cc_match = re.search(r'auto_ccs:\n((?:\s+-\s+"?[^"\n]+"?\n)+)', content)
            if cc_match:
                for line in cc_match.group(1).splitlines():
                    email = line.strip().replace('- ', '').replace('"', '')
                    if email:
                        contacts.add(email)
        except Exception as e:
            print(f"Warning: Failed to parse contacts for {project}: {e}")
    return contacts

def is_migrated(project: str) -> bool:
    """Checks if a project is already migrated to Ubuntu 24.04."""
    project_dir = os.path.join(OSS_FUZZ_DIR, 'projects', project)
    project_yaml = os.path.join(project_dir, 'project.yaml')
    dockerfile = os.path.join(project_dir, 'Dockerfile')

    if not os.path.exists(project_yaml) or not os.path.exists(dockerfile):
        return True # Skip invalid projects

    # Check project.yaml
    try:
        with open(project_yaml, 'r') as f:
            yaml_content = f.read()
        if 'base_os_version: ubuntu-24-04' not in yaml_content:
            return False
    except:
        return False

    # Check Dockerfile
    try:
        with open(dockerfile, 'r') as f:
            docker_content = f.read()
        if 'ubuntu-24-04' not in docker_content:
            return False
    except:
        return False

    return True

def modify_project_files(project: str) -> bool:
    """Modifies project.yaml and Dockerfile for Ubuntu 24.04 migration."""
    project_dir = os.path.join(OSS_FUZZ_DIR, 'projects', project)
    project_yaml = os.path.join(project_dir, 'project.yaml')
    dockerfile = os.path.join(project_dir, 'Dockerfile')

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

def generate_pr_body(projects: List[str], all_contacts: Set[str]) -> str:
    """Generates the PR description."""
    body = "### Mass Migration to Ubuntu 24.04\n\n"
    body += "This Pull Request migrates a batch of OSS-Fuzz projects to Ubuntu 24.04.\n\n"
    
    body += "#### Rationale\n"
    body += "Support for Ubuntu 20.04 is ending. To ensure continued security updates and access to modern toolchains, we are migrating all OSS-Fuzz projects to Ubuntu 24.04. "
    body += "We have extensively tested this migration with large projects and do not anticipate significant issues.\n\n"
    
    body += "#### Rollback Instructions\n"
    body += "If you encounter any issues, rolling back is simple:\n"
    body += "1.  Remove the `base_os_version: ubuntu-24-04` line from `project.yaml`.\n"
    body += "2.  Revert the `Dockerfile` base image tag to its previous state (e.g., remove `:ubuntu-24-04`).\n\n"
    body += "We will maintain the Ubuntu 20.04 build pool for a few weeks to allow time for any necessary fixes or rollbacks.\n\n"
    
    body += "#### Support\n"
    body += "We are available to support you during this transition. Please comment on this PR or reach out if you have questions.\n\n"
    
    body += "#### Migrated Projects\n"
    body += "| # | Project |\n"
    body += "| :--- | :--- |\n"
    for idx, p in enumerate(projects, 1):
        body += f"| {idx} | {p} |\n"
    
    body += "\n"
    if all_contacts:
        body += "CC: " + ", ".join(sorted(list(all_contacts)))
    
    return body

def main():
    parser = argparse.ArgumentParser(description='Mass migrate remaining OSS-Fuzz projects to Ubuntu 24.04.')
    parser.add_argument('--dry-run', action='store_true', help='Do not make changes, just list projects.')
    parser.add_argument('--preview-pr', action='store_true', help='Preview PR description for the first batch.')
    parser.add_argument('--limit', type=int, default=None, help='Limit total number of projects to process.')
    args = parser.parse_args()

    print(f"Scanning projects in {OSS_FUZZ_DIR}...")
    projects_dir = os.path.join(OSS_FUZZ_DIR, 'projects')
    all_projects = sorted([d for d in os.listdir(projects_dir) if os.path.isdir(os.path.join(projects_dir, d))])
    
    to_migrate = []
    print("Identifying projects needing migration...")
    for p in all_projects:
        if not is_migrated(p):
            to_migrate.append(p)
    
    print(f"Found {len(to_migrate)} projects needing migration.")
    
    if args.limit:
        to_migrate = to_migrate[:args.limit]
        print(f"Limiting to {args.limit} projects.")

    # Batching
    batches = [to_migrate[i:i + BATCH_SIZE] for i in range(0, len(to_migrate), BATCH_SIZE)]
    print(f"Split into {len(batches)} batches of up to {BATCH_SIZE} projects.")

    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')

    for i, batch in enumerate(batches, 1):
        print(f"\n--- Processing Batch {i}/{len(batches)} ({len(batch)} projects) ---")
        
        branch_name = f"migration-ubuntu-24-04-batch-{i}-{timestamp}"
        
        # Collect contacts
        batch_contacts = set()
        for p in batch:
            batch_contacts.update(get_project_contacts(p))
        
        pr_body = generate_pr_body(batch, batch_contacts)
        
        if args.dry_run:
            print(f"Would create branch: {branch_name}")
            print(f"Would migrate {len(batch)} projects: {', '.join(batch[:5])}...")
            continue

        if args.preview_pr:
            print(f"Preview for Batch {i}:")
            print(pr_body)
            if i == 1: # Only preview first batch then exit
                break
            continue

        # Create Branch
        print(f"Creating branch {branch_name}...")
        run_command(['git', 'checkout', 'master'], cwd=OSS_FUZZ_DIR)
        run_command(['git', 'pull', 'origin', 'master'], cwd=OSS_FUZZ_DIR)
        run_command(['git', 'checkout', '-b', branch_name], cwd=OSS_FUZZ_DIR)

        # Modify Files
        migrated_count = 0
        for p in batch:
            if modify_project_files(p):
                migrated_count += 1
            else:
                print(f"Failed to migrate {p}")
        
        if migrated_count == 0:
            print("No projects migrated in this batch. Skipping PR.")
            continue

        # Commit
        print("Committing changes...")
        run_command(['git', 'add', 'projects/'], cwd=OSS_FUZZ_DIR)
        run_command(['git', 'commit', '-m', f'Mass migrate batch {i}: {migrated_count} projects to Ubuntu 24.04'], cwd=OSS_FUZZ_DIR)

        # Push
        print("Pushing branch...")
        run_command(['git', 'push', 'origin', branch_name], cwd=OSS_FUZZ_DIR)

        # Create PR
        pr_file = f"/tmp/pr_body_batch_{i}_{timestamp}.md"
        with open(pr_file, 'w') as f:
            f.write(pr_body)
        
        print("Creating Pull Request...")
        try:
            # Default reviewers
            reviewers = ['DavidKorczynski', 'decoNR', 'ViniciustCosta', 'jonathanmetzman']
            reviewer_args = []
            for r in reviewers:
                reviewer_args.extend(['--reviewer', r])
            
            cmd = [
                'gh', 'pr', 'create',
                '--title', f'Mass Migration: Batch {i} to Ubuntu 24.04',
                '--body-file', pr_file,
                '--base', 'master',
                '--head', branch_name
            ] + reviewer_args
            
            run_command(cmd, cwd=OSS_FUZZ_DIR)
            print("PR created successfully.")
        except Exception as e:
            print(f"Failed to create PR: {e}")
        
        # Sleep slightly to be nice to API
        time.sleep(2)

if __name__ == '__main__':
    main()
