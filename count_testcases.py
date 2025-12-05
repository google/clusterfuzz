import os
import sys
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_init
from clusterfuzz._internal.datastore import ndb_utils
from clusterfuzz._internal.config import local_config
import concurrent.futures

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
    # We need to set up the environment so local_config works
    # This might require setting up PYTHONPATH which we will do in the run command
    
    try:
        local_config.ProjectConfig().set_environment()
    except Exception as e:
        print(f"Warning setting environment: {e}")

    print(f"Connecting to Datastore for project: {project_name}...")
    with ndb_init.context():
        # 1. Get all jobs
        query = data_types.Job.query()
        all_jobs = list(ndb_utils.get_all_from_query(query))
        project_jobs = [j for j in all_jobs if project_name in j.name]
        
        print(f"Found {len(project_jobs)} potential jobs for project {project_name}")
        print("Fetching testcase counts (this may take a while)...")
        
        results = []
        
        def process_job(job):
            with ndb_init.context():
                tc_query = data_types.Testcase.query(
                    data_types.Testcase.project_name == project_name,
                    data_types.Testcase.job_type == job.name,
                    ndb_utils.is_true(data_types.Testcase.open)
                )
                testcases = list(ndb_utils.get_all_from_query(tc_query))
                
                valid_count = 0
                for t in testcases:
                    is_unreproducible = t.status and t.status.startswith('Unreproducible')
                    is_one_time = t.one_time_crasher_flag
                    is_timeout = t.crash_type == 'Timeout'
                    is_flaky_stack = t.flaky_stack
                    is_pending_status = t.status == 'Pending'
                    
                    if not (is_unreproducible or is_one_time or is_timeout or is_flaky_stack or is_pending_status):
                        valid_count += 1
                return job.name, valid_count

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_job = {executor.submit(process_job, job): job for job in project_jobs}
            for i, future in enumerate(concurrent.futures.as_completed(future_to_job)):
                try:
                    name, count = future.result()
                    if count > 0:
                        results.append((name, count))
                except Exception as e:
                    print(f"Error processing job: {e}")
                
                if i % 100 == 0:
                    print(f"Processed {i}/{len(project_jobs)} jobs...", end='\r')

        print("\nSorting results...")
        results.sort(key=lambda x: x[1], reverse=True)
        
        print(f"\n{'Job Name':<70} | {'Valid Open Testcases':<20}")
        print("-" * 93)
        
        for name, count in results[:100]:
            print(f"{name:<70} | {count:<20}")
        
        total_valid_testcases = sum(c for n, c in results)
        print("-" * 93)
        print(f"{'Total (All Jobs)':<70} | {total_valid_testcases:<20}")

if __name__ == '__main__':
    main()
