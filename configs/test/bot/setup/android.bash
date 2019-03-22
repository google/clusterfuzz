#!/bin/bash -e
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ -z "$CLOUD_PROJECT_ID" ]; then
  echo "\$CLOUD_PROJECT_ID is not set."
  exit 1
fi

if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  echo "\$GOOGLE_APPLICATION_CREDENTIALS is not set."
  exit 1
fi

if [ -z "$ANDROID_SERIAL" ]; then
  echo "\$ANDROID_SERIAL is not set."
  exit 1
fi

NFS_ROOT=  # Fill in NFS information if available.
APPENGINE=google_appengine
APPENGINE_FILE=google_appengine_1.9.75.zip
GOOGLE_CLOUD_SDK=google-cloud-sdk
GOOGLE_CLOUD_SDK_ARCHIVE=google-cloud-sdk-232.0.0-linux-x86_64.tar.gz
INSTALL_DIRECTORY=${INSTALL_DIRECTORY:-${HOME}}
APPENGINE_DIR="$INSTALL_DIRECTORY/$APPENGINE"
DEPLOYMENT_BUCKET="deployment.$CLOUD_PROJECT_ID.appspot.com"
GSUTIL_PATH="$INSTALL_DIRECTORY/$GOOGLE_CLOUD_SDK/bin"
ROOT_DIR="$INSTALL_DIRECTORY/clusterfuzz"
PYTHONPATH="$PYTHONPATH:$APPENGINE_DIR:$ROOT_DIR/src"
ADB_PATH="$INSTALL_DIRECTORY/platform-tools"
PATH="$PATH:$ADB_PATH"

echo "Creating directory $INSTALL_DIRECTORY."
if [ ! -d "$INSTALL_DIRECTORY" ]; then
  mkdir -p "$INSTALL_DIRECTORY"
fi

cd $INSTALL_DIRECTORY

echo "Fetching Google Cloud SDK."
if [ ! -d "$INSTALL_DIRECTORY/$GOOGLE_CLOUD_SDK" ]; then
  curl -O "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/$GOOGLE_CLOUD_SDK_ARCHIVE"
  tar -xzf $GOOGLE_CLOUD_SDK_ARCHIVE
  rm $GOOGLE_CLOUD_SDK_ARCHIVE
fi

echo "Fetching Android platform tools for ADB."
if [ ! -d "$ADB_PATH" ]; then
  wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
  unzip $INSTALL_DIRECTORY/platform-tools-latest-linux.zip
  rm $INSTALL_DIRECTORY/platform-tools-latest-linux.zip
fi

echo "Fetching Google App Engine SDK."
if [ ! -d "$INSTALL_DIRECTORY/$APPENGINE" ]; then
  curl -O "https://commondatastorage.googleapis.com/clusterfuzz-data/$APPENGINE_FILE"
  unzip -q $APPENGINE_FILE
  rm $APPENGINE_FILE
fi

echo "Installing ClusterFuzz package dependencies."
pip install crcmod==1.7 psutil==5.4.7 pyOpenSSL==19.0.0

echo "Ensuring device is connected."
if ! $ADB_PATH/adb -s $ANDROID_SERIAL get-state | grep -q "device"; then
  echo "Device $ANDROID_SERIAL is not connected."
  exit 1
fi

echo "Activating credentials with the Google Cloud SDK."
$GSUTIL_PATH/gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS

# Otherwise, gsutil will error out due to multiple types of configured
# credentials. For more information about this, see
# https://cloud.google.com/storage/docs/gsutil/commands/config#configuration-file-selection-procedure
echo "Specifying the proper Boto configuration file."
BOTO_CONFIG_PATH=$($GSUTIL_PATH/gsutil -D 2>&1 | grep "config_file_list" | egrep -o "/[^']+gserviceaccount\.com/\.boto") || true
if [ -f $BOTO_CONFIG_PATH ]; then
  export BOTO_CONFIG="$BOTO_CONFIG_PATH"
else
  echo "WARNING: failed to identify the Boto configuration file and specify BOTO_CONFIG env."
fi

echo "Downloading ClusterFuzz source code."
rm -rf clusterfuzz
$GSUTIL_PATH/gsutil cp gs://$DEPLOYMENT_BUCKET/linux.zip clusterfuzz-source.zip
unzip -q clusterfuzz-source.zip

echo "Running ClusterFuzz."
OS_OVERRIDE="ANDROID" ANDROID_SERIAL="$ANDROID_SERIAL" PATH="$PATH" NFS_ROOT="$NFS_ROOT" GOOGLE_APPLICATION_CREDENTIALS="$GOOGLE_APPLICATION_CREDENTIALS" ROOT_DIR="$ROOT_DIR" PYTHONPATH="$PYTHONPATH" GSUTIL_PATH="$GSUTIL_PATH" python $ROOT_DIR/src/python/bot/startup/run.py &

echo "Success!"
