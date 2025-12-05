import os
import sys
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.config import local_config
import collections

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
        print("Fetching all open testcases for project...")
        # Query all open testcases for the project
        query = data_types.Testcase.query(
            data_types.Testcase.project_name == project_name,
            ndb_utils.is_true(data_types.Testcase.open)
        )
        all_testcases = list(ndb_utils.get_all_from_query(query))
        print(f"Found {len(all_testcases)} open testcases.")
        
        job_counts = collections.defaultdict(int)
        
        for t in all_testcases:
            is_unreproducible = t.status and t.status.startswith('Unreproducible')
            is_one_time = t.one_time_crasher_flag
            is_timeout = t.crash_type == 'Timeout'
            is_flaky_stack = t.flaky_stack
            is_pending_status = t.status == 'Pending'
            
            if not (is_unreproducible or is_one_time or is_timeout or is_flaky_stack or is_pending_status):
                job_counts[t.job_type] += 1
        
        print(f"Found {len(job_counts)} jobs with valid open testcases.")
        
        # Sort by count descending
        sorted_jobs = sorted(job_counts.items(), key=lambda x: x[1], reverse=True)
        
        print(f"\n{'Job Name':<70} | {'Valid Open Testcases':<20}")
        print("-" * 93)
        
        for name, count in sorted_jobs[:100]:
            print(f"{name:<70} | {count:<20}")
        
        total_valid_testcases = sum(job_counts.values())
        print("-" * 93)
        print(f"{'Total':<70} | {total_valid_testcases:<20}")

if __name__ == '__main__':
    main()
