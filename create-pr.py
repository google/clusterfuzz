#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'

def run_command(cmd, cwd=None):
    print(f"Running: {cmd} in {cwd or os.getcwd()}")
    subprocess.check_call(cmd, shell=True, cwd=cwd)

def get_project_contacts(project, oss_fuzz_dir):
    project_yaml = os.path.join(oss_fuzz_dir, 'projects', project, 'project.yaml')
    contacts = [] # Start empty, or add default if needed. User's example had @OliverChang but it's better to pull from yaml
    if os.path.exists(project_yaml):
        with open(project_yaml, 'r') as f:
            content = f.read()
            import re
            pc_match = re.search(r'primary_contact:\s+"?([^"\n]+)"?', content)
            if pc_match:
                contacts.append(pc_match.group(1))
            cc_match = re.search(r'auto_ccs:\n((?:\s+-\s+"?[^"\n]+"?\n)+)', content)
            if cc_match:
                for line in cc_match.group(1).splitlines():
                    email = line.strip().replace('- ', '').replace('"', '')
                    if email and email not in contacts:
                        contacts.append(email)
    return contacts

def main():
    parser = argparse.ArgumentParser(description='Create PR for OSS-Fuzz migration')
    parser.add_argument('project', help='OSS-Fuzz project name')
    parser.add_argument('--recreate', action='store_true', help='Recreate branch and PR if they already exist')
    args = parser.parse_args()
    
    project = args.project
    branch_name = f"ubuntu-migration-{project}"
    
    print(f"--- Creating PR for {project} ---")
    
    # 0. Check if summary.log exists and indicates success
    migration_results_dir = f'/usr/local/google/home/matheushunsche/projects/oss-migration/{project}/results'
    summary_log = os.path.join(migration_results_dir, 'summary.log')
    if not os.path.exists(summary_log):
        print(f"Error: Summary log not found at {summary_log}")
        print("Please run oss-migration.py first.")
        sys.exit(1)
    
    with open(summary_log, 'r') as f:
        content = f.read()
        if "✅ Success: Results meet criteria for PR." not in content:
            print(f"Error: Summary log indicates failure or criteria not met.")
            print("Please check the summary log and resolve issues before creating PR.")
            sys.exit(1)
    print("Verified: Summary log indicates success.")

    # 1. Check out master and pull latest
    run_command("git checkout master", cwd=OSS_FUZZ_DIR)
    run_command("git pull origin master", cwd=OSS_FUZZ_DIR)
    
    # 2. Handle existing branch/PR if --recreate is set
    if args.recreate:
        print("Recreate flag set. Cleaning up existing branch and PR...")
        # Close PR if exists
        try:
            existing_prs = subprocess.check_output(f"gh pr list --head {branch_name} --json number --jq '.[].number'", shell=True, cwd=OSS_FUZZ_DIR).decode('utf-8').strip()
            if existing_prs:
                for pr_num in existing_prs.split():
                    print(f"Closing PR #{pr_num}...")
                    subprocess.run(f"gh pr close {pr_num} --delete-branch", shell=True, cwd=OSS_FUZZ_DIR)
        except subprocess.CalledProcessError:
            pass

        # Delete local branch
        try:
            subprocess.run(f"git branch -D {branch_name}", shell=True, cwd=OSS_FUZZ_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Deleted local branch {branch_name}")
        except subprocess.CalledProcessError:
            pass

        # Delete remote branch
        try:
            subprocess.run(f"git push origin --delete {branch_name}", shell=True, cwd=OSS_FUZZ_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Deleted remote branch {branch_name}")
        except subprocess.CalledProcessError:
            pass
    else:
        # Normal checks
        # Check local
        try:
            subprocess.check_call(f"git rev-parse --verify {branch_name}", shell=True, cwd=OSS_FUZZ_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Error: Branch {branch_name} already exists locally. Use --recreate to overwrite.")
            sys.exit(1)
        except subprocess.CalledProcessError:
            pass # Branch does not exist locally, good

        try:
            # Check remote
            subprocess.check_call(f"git fetch origin {branch_name}", shell=True, cwd=OSS_FUZZ_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Error: Branch {branch_name} already exists on remote. Use --recreate to overwrite.")
            sys.exit(1)
        except subprocess.CalledProcessError:
            pass # Branch does not exist on remote, good

    # Create new branch
    run_command(f"git checkout -b {branch_name}", cwd=OSS_FUZZ_DIR)
    
    # 3. Modify files
    project_dir = os.path.join(OSS_FUZZ_DIR, 'projects', project)
    project_yaml = os.path.join(project_dir, 'project.yaml')
    dockerfile = os.path.join(project_dir, 'Dockerfile')
    
    if not os.path.exists(project_yaml) or not os.path.exists(dockerfile):
        print(f"Error: Project files not found in {project_dir}")
        sys.exit(1)
    
    # Get contacts before modifying project.yaml (though it shouldn't matter much)
    contacts = get_project_contacts(project, OSS_FUZZ_DIR)
    cc_list = ", ".join(contacts)
    
    # Modify project.yaml
    with open(project_yaml, 'r') as f:
        content = f.read()
    if 'base_os_version: ubuntu-24-04' not in content:
        # Insert at the beginning
        new_content = 'base_os_version: ubuntu-24-04\n' + content
        with open(project_yaml, 'w') as f:
            f.write(new_content)
        print(f"Updated {project_yaml} (added to beginning)")
    else:
        print(f"{project_yaml} already updated")
    
    # Modify Dockerfile
    with open(dockerfile, 'r') as f:
        content = f.read()
    if 'ubuntu-24-04' not in content:
        # Robust replacement using regex to handle base images like base-builder-go
        # Matches 'FROM gcr.io/oss-fuzz-base/base-builder' optionally followed by '-lang' and optionally a tag
        import re
        new_content = re.sub(
            r'FROM\s+(gcr\.io/oss-fuzz-base/base-builder(?:-[a-z0-9]+)?)(?::\w+)?',
            r'FROM \1:ubuntu-24-04',
            content
        )
        with open(dockerfile, 'w') as f:
            f.write(new_content)
        print(f"Updated {dockerfile}")
    else:
        print(f"{dockerfile} already updated")
    
    # 4. Commit changes
    run_command(f"git add projects/{project}/", cwd=OSS_FUZZ_DIR)
    commit_msg = f"Migrate {project} to Ubuntu 24.04"
    try:
        run_command(f"git commit -m '{commit_msg}'", cwd=OSS_FUZZ_DIR)
    except subprocess.CalledProcessError:
        print("Nothing to commit (changes might already be committed)")
    
    # 5. Push and create PR
    # Check if PR already exists before pushing
    pr_title = f"Migrate {project} to Ubuntu 24.04"
    pr_body = f"""### Summary

This pull request migrates the `{project}` project to use the new `ubuntu-24-04` base image for fuzzing.

### Changes in this PR

1.  **`projects/{project}/project.yaml`**: Sets the `base_os_version` property to `ubuntu-24-04`.
2.  **`projects/{project}/Dockerfile`**: Updates the `FROM` instruction.

CC: {cc_list}
"""
    
    if not args.recreate:
        # Check for existing PR with same title or branch
        try:
            existing_prs = subprocess.check_output(f"gh pr list --head {branch_name} --json number --jq '.[].number'", shell=True, cwd=OSS_FUZZ_DIR).decode('utf-8').strip()
            if existing_prs:
                print(f"Error: PR already exists for branch {branch_name} (PR #{existing_prs})")
                sys.exit(1)
        except subprocess.CalledProcessError:
            pass # No existing PR or error checking, proceed

    run_command(f"git push origin {branch_name}", cwd=OSS_FUZZ_DIR)
    
    # Create PR with body from file to handle multiline safely
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as tmp:
        tmp.write(pr_body)
        tmp_path = tmp.name
    
    try:
        # Default reviewers that we know are valid
        default_reviewers = ['DavidKorczynski', 'decoNR', 'ViniciustCosta', 'jonathanmetzman']
        reviewer_args = [f'--reviewer "{c}"' for c in default_reviewers]
        reviewer_cmd = " ".join(reviewer_args)
        
        try:
            print(f"Attempting to create PR with default reviewers: {', '.join(default_reviewers)}")
            output = subprocess.check_output(f"gh pr create --title '{pr_title}' --body-file '{tmp_path}' {reviewer_cmd}", shell=True, cwd=OSS_FUZZ_DIR).decode('utf-8').strip()
        except subprocess.CalledProcessError:
            print("Warning: Failed to create PR with default reviewers. Retrying without reviewers...")
            output = subprocess.check_output(f"gh pr create --title '{pr_title}' --body-file '{tmp_path}'", shell=True, cwd=OSS_FUZZ_DIR).decode('utf-8').strip()
        
        print(f"PR created: {output}")
        
        # Try to find PR URL in output
        pr_url = None
        for line in output.splitlines():
            if 'github.com' in line and '/pull/' in line:
                pr_url = line.strip()
                break
        if not pr_url:
            pr_url = output.splitlines()[-1] # Fallback
        
        # Project contacts are already in CC list in description, no need to add as reviewers
        print(f"Project contacts added to CC list in description.")
    finally:
        os.remove(tmp_path)

if __name__ == "__main__":
    main()
