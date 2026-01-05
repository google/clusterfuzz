import os
import json
import sys

OSS_FUZZ_DIR = '/usr/local/google/home/matheushunsche/projects/oss-fuzz'

def is_migrated(project):
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

def main():
    projects_dir = os.path.join(OSS_FUZZ_DIR, 'projects')
    all_projects = sorted([d for d in os.listdir(projects_dir) if os.path.isdir(os.path.join(projects_dir, d))])
    
    to_migrate = []
    print("Identifying projects needing migration...")
    for p in all_projects:
        if not is_migrated(p):
            to_migrate.append(p)
    
    print(f"Found {len(to_migrate)} projects needing migration.")
    
    output_file = 'all_remaining_projects.json'
    with open(output_file, 'w') as f:
        json.dump(to_migrate, f, indent=2)
    print(f"Saved list to {output_file}")

if __name__ == '__main__':
    main()
