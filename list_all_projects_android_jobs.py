import os
import sys
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.config import local_config

def main():
    # Setup paths
    base_dir = '/usr/local/google/home/matheushunsche/projects/clusterfuzz'
    config_dir = '/usr/local/google/home/matheushunsche/projects/clusterfuzz-config'
    
    # Use the google config directory directly
    config_path = os.path.join(config_dir, 'configs', 'google')
    if not os.path.isdir(config_path):
        print(f"Error: Config path not found: {config_path}")
        return

    os.environ['CONFIG_DIR_OVERRIDE'] = config_path
    
    try:
        local_config.ProjectConfig().set_environment()
    except Exception as e:
        print(f"Warning setting environment: {e}")

    print("Connecting to Datastore to check all projects...")
    with ndb_init.context():
        query = data_types.Job.query()
        all_jobs = list(ndb_utils.get_all_from_query(query))
        
        projects = set(j.project for j in all_jobs if j.project)
        print(f"Found jobs in {len(projects)} projects.")
        
        for project in sorted(projects):
            project_jobs = [j for j in all_jobs if j.project == project]
            android_jobs = [j for j in project_jobs if 'ANDROID' in (j.platform or '')]
            if android_jobs:
                print(f"\nProject: {project}")
                print(f"  Total jobs: {len(project_jobs)}")
                print(f"  Android jobs: {len(android_jobs)}")
                for j in android_jobs:
                    print(f"    - {j.name} ({j.platform})")

if __name__ == '__main__':
    main()
