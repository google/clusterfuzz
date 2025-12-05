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

    jobs_to_check = [
        'libfuzzer_qemu_asan',
        'libfuzzer_asan_message_center_test',
        'honggfuzz_asan_simplejson_test'
    ]

    print(f"Connecting to Datastore to check jobs: {jobs_to_check}...")
    with ndb_init.context():
        for job_name in jobs_to_check:
            job = data_types.Job.query(data_types.Job.name == job_name).get()
            if job:
                print(f"\nJob: {job_name}")
                print(f"Platform: {job.platform}")
                print(f"Environment String:\n{job.get_environment_string()}")
            else:
                print(f"\nJob: {job_name} not found.")

if __name__ == '__main__':
    main()
