from clusterfuzz._internal.datastore import data_types

def execute(args):
    job_name = 'android_content_shell_native_job'
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
        print(f"Job {job_name} not found! Run setup_content_shell_job_remote first.")
    else:
        print(f"Job {job_name} exists.")
        
    fuzzer_name = 'android_chrome_native_fuzzer'
    fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
    if not fuzzer:
        print(f"Fuzzer {fuzzer_name} not found!")
    else:
        print(f"Fuzzer {fuzzer_name} exists.")
        if job_name not in fuzzer.jobs:
            fuzzer.jobs.append(job_name)
            if args.non_dry_run:
                fuzzer.put()
            print(f"Added {job_name} to {fuzzer_name}.jobs")
        else:
            print(f"{job_name} already in {fuzzer_name}.jobs")
