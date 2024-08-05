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

DEPLOYMENT_ZIP="linux-3.zip"
if [[ $CLUSTERFUZZ_RELEASE == "candidate" ]]; then
    DEPLOYMENT_ZIP="linux-3-candidate.zip"
fi
export DEPLOYMENT_ZIP

source /data/setup_common.sh
source /data/setup_depot_tools.sh
source /data/setup_gerrit.sh
source /data/setup_clusterfuzz.sh

bash -ex /data/start_clusterfuzz.sh
