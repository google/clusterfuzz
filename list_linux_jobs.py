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
    project_name = 'google'
    
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

    print(f"Connecting to Datastore for project: {project_name}...")
    with ndb_init.context():
        query = data_types.Job.query()
        all_jobs = list(ndb_utils.get_all_from_query(query))
        project_jobs = [j for j in all_jobs if project_name in j.name]
        
        linux_jobs = [j for j in project_jobs if j.platform == 'LINUX']
        non_linux_jobs = [j for j in project_jobs if j.platform != 'LINUX']
        
        print(f"\nFound {len(linux_jobs)} Linux jobs.")
        print(f"Found {len(non_linux_jobs)} non-Linux jobs.")
        
        if linux_jobs:
            print("\nLinux Jobs (first 100):")
            for j in linux_jobs[:100]:
                print(f"- {j.name}")
            if len(linux_jobs) > 100:
                print(f"... and {len(linux_jobs) - 100} more.")
        
        if non_linux_jobs:
            print("\nNon-Linux Jobs:")
            for j in non_linux_jobs:
                print(f"- {j.name} ({j.platform})")

if __name__ == '__main__':
    main()
