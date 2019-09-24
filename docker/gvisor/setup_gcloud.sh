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

if [ -z "$CLOUD_PROJECT_ID" ]; then
  echo "FATAL: no CLOUD_PROJECT_ID set"
  exit 1
fi

gcloud config set project "$CLOUD_PROJECT_ID"
gcloud auth activate-service-account --key-file=/credentials.json

BOTO_CONFIG_PATH=$(/usr/bin/gsutil -D 2>&1 | grep "config_file_list" | egrep -o "/[^']+gserviceaccount\.com/\.boto") || true
if [[ -f "$BOTO_CONFIG_PATH" ]]; then
  export BOTO_CONFIG="$BOTO_CONFIG_PATH"
else
  echo "WARNING: failed to identify the Boto configuration file and specify BOTO_CONFIG env."
fi

