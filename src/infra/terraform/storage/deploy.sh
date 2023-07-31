#!/bin/bash
# Copyright 2023 Google LLC
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

# Checks if the user has provided at least two arguments
if [ $# -lt 2 ]; then
  echo "Usage: $0 PROJECT_ID BUCKET_NAME [BUCKET_LOCATION]"
  exit 1
fi

export TF_VAR_project_id=$1
export TF_VAR_bucket_name=$2
# Gets the bucket location, if provided. Default: us-east1
export TF_VAR_bucket_location=${3:-us-central1}

terraform init
terraform plan
terraform apply