import os
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import storage

def execute(args):
    job_name = 'android_content_shell_native_job'
    dummy_build_path = 'android_content_shell_native_dummy-1.zip'
    build_bucket = 'deployment.clusterfuzz-development.appspot.com'

    # 1. Upload Dummy Build
    build_gcs_path = f'/{build_bucket}/{dummy_build_path}'
    
    print(f'Uploading dummy build to {build_gcs_path}...')
    if args.non_dry_run:
        with open(dummy_build_path, 'rb') as f:
            storage.write_data(f, build_gcs_path)

    # 2. Create or Update Job Configuration
    environment_string = (
        f'RELEASE_BUILD_BUCKET_PATH = gs://{build_bucket}/android_content_shell_native_dummy-([0-9]+).zip\n'
        'APP_NAME = ContentShell.apk\n'
        'PKG_NAME = org.chromium.content_shell_apk\n'
        'CHILD_PROCESS_TERMINATION_PATTERN = org.chromium.content_shell_apk:sandboxed_process\n'
        'APP_LAUNCH_COMMAND = shell am start -a android.intent.action.VIEW -n %PKG_NAME%/.ContentShellActivity -d \'%TESTCASE_FILE_URL%\'\n'
        'APP_ARGS = --enable-logging=stderr --v=1 --disable-gpu-watchdog --enable-test-intents --disable-fre --no-restore-state --allow-file-access-from-files --disable-gesture-requirement-for-media-playback --disable-click-to-play --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --new-window --js-flags="--expose-gc" --no-default-browser-check --no-first-run --no-process-singleton-dialog --use-fake-device-for-media-stream --use-fake-ui-for-media-stream --force-renderer-accessibility --disable-crash-reporter --no-experiments %TESTCASE_FILE_URL%\n'
        'REQUIRED_APP_ARGS = --disable-gpu-watchdog --enable-test-intents --disable-fre --no-restore-state --disable-crash-reporter\n'
        'COMMAND_LINE_PATH = /data/local/tmp/chrome-command-line\n'
        'OS_OVERRIDE = ANDROID\n'
        'REQUIRES_GPU = True\n'
        'IS_SWARMING_JOB = True\n'
        'IS_K8S_ENV = True\n'
    )
    
    print(f'Creating/Updating job: {job_name}...')
    if args.non_dry_run:
        job = data_types.Job.query(data_types.Job.name == job_name).get()
        if not job:
            job = data_types.Job(name=job_name)
            
        job.platform = 'ANDROID'
        job.environment_string = environment_string
        job.put()

    print('Job setup complete!')