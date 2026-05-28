from clusterfuzz._internal.datastore import data_types

def execute(args):
    job_name = 'android_content_shell_native_job'
    job = data_types.Job.query(data_types.Job.name == job_name).get()
    if not job:
        print(f"Job {job_name} not found in Datastore!")
    else:
        print(f"Job {job_name} found!")
        print(f"Platform: {job.platform}")
        print(f"Environment: {job.environment_string}")
        
    fuzzer_name = 'android_chrome_native_fuzzer'
    fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
    if not fuzzer:
        print(f"Fuzzer {fuzzer_name} not found!")
    else:
        print(f"Fuzzer {fuzzer_name} found!")
        print(f"Jobs: {fuzzer.jobs}")
