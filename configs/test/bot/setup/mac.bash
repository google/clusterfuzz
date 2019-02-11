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

NFS_ROOT=  # Fill in NFS information if available.
APPENGINE=google_appengine
APPENGINE_FILE=google_appengine_1.9.75.zip
GOOGLE_CLOUD_SDK=google-cloud-sdk
GOOGLE_CLOUD_SDK_ARCHIVE=google-cloud-sdk-232.0.0-darwin-x86_64.tar.gz
INSTALL_DIRECTORY=${INSTALL_DIRECTORY:-${HOME}}
APPENGINE_DIR="$INSTALL_DIRECTORY/$APPENGINE"
DEPLOYMENT_BUCKET="deployment.$CLOUD_PROJECT_ID.appspot.com"
GSUTIL_PATH="$INSTALL_DIRECTORY/$GOOGLE_CLOUD_SDK/bin"
ROOT_DIR="$INSTALL_DIRECTORY/clusterfuzz"
PYTHONPATH="$PYTHONPATH:$APPENGINE_DIR:$ROOT_DIR/src"

echo "Disabling macOS crash reporting (requires sudo)."
sudo -u $USER bash -c "launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist"
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

echo "Disabling kernel message logging (requires sudo)."
sudo sysctl -w vm.shared_region_unnest_logging=0

echo "Increasing default file limit (requires sudo)."
sudo launchctl limit maxfiles 2048 unlimited
sudo ulimit -n 4096

echo "Installing ClusterFuzz package dependencies (requires sudo)."

# pip may fail on some macOS versions if run without "--ignore-installed".
# For more context, see https://github.com/pypa/pip/issues/3165.
sudo pip install --ignore-installed crcmod==1.7 psutil==5.4.7

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

echo "Activating credentials with the Google Cloud SDK."
$GSUTIL_PATH/gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS

echo "Specifying the proper Boto configuration file."

# Otherwise, gsutil will error out due to multiple types of configured
# credentials. For more information about this, see
# https://cloud.google.com/storage/docs/gsutil/commands/config#configuration-file-selection-procedure
BOTO_CONFIG_PATH=$($GSUTIL_PATH/gsutil -D 2>&1 | grep "config_file_list" | egrep -o "/[^']+gserviceaccount\.com/\.boto")

if [ -f $BOTO_CONFIG_PATH ]; then
  export BOTO_CONFIG="$BOTO_CONFIG_PATH"
else
  echo "WARNING: failed to identify the Boto configuration file and specify BOTO_CONFIG env."
fi

echo "Fetching Google App Engine SDK."
if [ ! -d "$INSTALL_DIRECTORY/$APPENGINE" ]; then
  curl -O "https://commondatastorage.googleapis.com/clusterfuzz-data/$APPENGINE_FILE"
  unzip -q $APPENGINE_FILE
  rm $APPENGINE_FILE
fi

echo "Downloading ClusterFuzz source code."
$GSUTIL_PATH/gsutil cp gs://$DEPLOYMENT_BUCKET/macos.zip clusterfuzz-source.zip
unzip -q clusterfuzz-source.zip

echo "Running ClusterFuzz."
NFS_ROOT="$NFS_ROOT" GOOGLE_APPLICATION_CREDENTIALS="$GOOGLE_APPLICATION_CREDENTIALS" ROOT_DIR="$ROOT_DIR" PYTHONPATH="$PYTHONPATH" GSUTIL_PATH="$GSUTIL_PATH" python $ROOT_DIR/src/python/bot/startup/run.py &

echo "Success!"
