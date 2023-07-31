#!/bin/bash -ex
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

# Checks if the user has provided necessary arguments.
if [ $# -lt 2 ]; then
  echo "Usage: $0 PROJECT_ID BUCKET_NAME [REGION] [subnet_name] [network_name] [ip_cidr_range]"
  exit 1
fi

terraform init \
  -backend-config="bucket=$2" \
  -backend-config="prefix=terraform/state"

project_id=$1
bucket_name=$2
region=${3:-us-central1}
subnet_name=${4:-us-central1}
network_name=${5:-main}

export TF_VAR_project_id=$project_id
export TF_VAR_bucket_name=$bucket_name
export TF_VAR_region=$region
export TF_VAR_subnet_name=$subnet_name
export TF_VAR_network_name=$network_name
export TF_VAR_ip_cidr_range=${6:-'10.128.0.0/16'}

# Checks if the subnet exists
if ! terraform state show google_compute_subnetwork.subnet; then
  terraform import google_compute_subnetwork.subnet $project_id/$region/$subnet_name
fi

# Checks if the network exists
if ! terraform state show google_compute_network.vpc; then
  terraform import google_compute_network.vpc $network_name
fi
terraform plan
terraform apply