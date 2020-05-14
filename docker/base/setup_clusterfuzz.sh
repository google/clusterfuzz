#!/bin/bash -ex
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

if [ -z "$DEPLOYMENT_BUCKET" ]; then
  # Get deployment bucket from project metadata.
  export DEPLOYMENT_BUCKET=$(curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/deployment-bucket)
fi

# When $LOCAL_SRC is set, use source zip on mounted volume for local testing.
if [[ -z "$LOCAL_SRC" ]]; then
  # Set up ClusterFuzz
  if [[ -d clusterfuzz ]]; then
    rm -rf clusterfuzz
  fi

  gsutil cp gs://$DEPLOYMENT_BUCKET/$DEPLOYMENT_ZIP .
  unzip -o $DEPLOYMENT_ZIP
fi

# Some configurations (e.g. hosts) run many instances of ClusterFuzz. Don't
# set up mounts in this case.
if [[ -z "$DISABLE_MOUNTS" ]]; then
  # Setup Tmpfs dirs for frequently accessed files to save disk I/O.
  mount -t tmpfs -o size=250M,mode=777 tmpfs $INSTALL_DIRECTORY/clusterfuzz/bot/inputs/fuzzer-testcases/
  mount -t tmpfs -o size=10M,mode=777 tmpfs $INSTALL_DIRECTORY/clusterfuzz/bot/logs/
  mount -t tmpfs -o size=90M,mode=777 tmpfs $BOT_TMPDIR

  # Setup mount to limit disk space for fuzzer-testcases-disk directory.
  FUZZER_TESTCASES_DISK_FILE=$INSTALL_DIRECTORY/fuzzer-testcases.mnt
  fallocate -l 8GiB $FUZZER_TESTCASES_DISK_FILE
  mkfs.ext4 -F $FUZZER_TESTCASES_DISK_FILE

  # mkfs.ext4 seems to remove the previous allocation, so do it again.
  fallocate -l 8GiB $FUZZER_TESTCASES_DISK_FILE
  mount -o loop $FUZZER_TESTCASES_DISK_FILE $INSTALL_DIRECTORY/clusterfuzz/bot/inputs/fuzzer-testcases-disk
fi

chown -R $USER:$USER $INSTALL_DIRECTORY
