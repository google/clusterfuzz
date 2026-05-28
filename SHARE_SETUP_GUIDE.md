# Android Swarming Setup Guide

This guide explains how to set up your local ClusterFuzz instance for native Android HTML fuzzing on LUCI Swarming.

## Prerequisites

1.  Make sure you have pulled the `android-swarming-setup-scripts` branch in your `clusterfuzz` repository. This branch contains the necessary `butler.py` automation scripts.
    ```bash
    cd ../clusterfuzz
    git fetch origin
    git checkout android-swarming-setup-scripts
    ```
2.  Make sure you have downloaded the `ContentShell.apk` dummy build and placed it in your deployment bucket. (We are using the `AndroidDesktop_x64` build to match the Swarming emulator architecture).

## Running the Setup

Simply run the provided bash script from the root of the `clusterfuzz-config` repository:

```bash
./setup_android_swarming.sh
```

### What the script does:

1.  **Deploys the Job:** It creates `android_content_shell_native_job` in Datastore. This job is configured to dynamically download the x64 Content Shell dummy build, automatically install it via `adb`, and launch the `ContentShellActivity` intent.
2.  **Deploys the Fuzzer:** It packages and uploads `android_chrome_native_fuzzer` to the Blobstore. This includes a `run.sh` script that generates HTML payloads and pushes them to the emulator.
3.  **Links Entities:** It securely links the fuzzer to the job so they can be run together.
4.  **Verifies:** It queries Datastore to ensure everything was created successfully.

## Uploading a Testcase

Once the setup is complete, you can reproduce Android crashes flawlessly!

1.  Open the ClusterFuzz UI.
2.  Navigate to **"Upload Testcase"**.
3.  Select Job: `android_content_shell_native_job`
4.  Select Fuzzer: `android_chrome_native_fuzzer`
5.  Upload your HTML file.

ClusterFuzz will schedule an `analyze` task on Swarming, boot the headless Android 36 (x86_64) emulator, install Content Shell, launch your HTML file, and package the logs without any Datastore permission crashes!