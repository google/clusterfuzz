#!/bin/bash -e
#
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

echo "Running metadata server..."

set +x
docker_ip=$(ip -4 addr show docker0 | grep -P inet | head -1 | awk '{print $2}' | cut -d/ -f1)
root_dir=$(dirname $(dirname "$(readlink -f "$0")"))

go run emulators/metadata.go -ip=$docker_ip "$@"
