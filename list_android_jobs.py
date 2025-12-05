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
        
        android_jobs = [j for j in project_jobs if 'ANDROID' in (j.platform or '')]
        
        print(f"\nFound {len(android_jobs)} Android jobs.")
        
        if android_jobs:
            print("\nAndroid Jobs:")
            for j in android_jobs:
                print(f"- {j.name} ({j.platform})")
        else:
            print("No Android jobs found for this project.")

if __name__ == '__main__':
    main()
