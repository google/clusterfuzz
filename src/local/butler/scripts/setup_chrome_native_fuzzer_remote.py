import os
import uuid
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage

def execute(args):
    job_name = 'android_chrome_native_job'
    fuzzer_name = 'android_chrome_native_fuzzer'
    fuzzer_archive_path = 'android_chrome_native_fuzzer.zip'
    blobs_bucket = storage.blobs_bucket()

    # 1. Upload Fuzzer Archive
    blob_name = str(uuid.uuid4()).lower()
    fuzzer_gcs_path = f'/{blobs_bucket}/{blob_name}'
    
    print(f'Uploading fuzzer archive to {fuzzer_gcs_path}...')
    if args.non_dry_run:
        with open(fuzzer_archive_path, 'rb') as f:
            storage.write_data(f, fuzzer_gcs_path)

    # 2. Create or Update Fuzzer
    file_size = os.path.getsize(fuzzer_archive_path)
    
    print(f'Creating/Updating fuzzer: {fuzzer_name}...')
    if args.non_dry_run:
        fuzzer = data_types.Fuzzer.query(data_types.Fuzzer.name == fuzzer_name).get()
        if not fuzzer:
            fuzzer = data_types.Fuzzer(name=fuzzer_name)

        fuzzer.revision = 1  # Fix for the %d format TypeError
        fuzzer.executable_path = 'run.sh'
        fuzzer.timeout = 120
        fuzzer.jobs = [job_name]
        fuzzer.blobstore_key = blob_name
        fuzzer.filename = fuzzer_archive_path
        fuzzer.file_size = f'{file_size} B'
        fuzzer.builtin = False
        fuzzer.put()

    print('Setup complete!')