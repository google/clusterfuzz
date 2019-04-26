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

# Set up mock metadata server.
if [[ -n "$LOCAL_METADATA_SERVER" ]]; then
  ip addr add 169.254.169.254/32 dev lo
  socat TCP-LISTEN:80,fork,reuseaddr TCP:$LOCAL_METADATA_SERVER:$LOCAL_METADATA_PORT &
  echo "127.0.0.1 metadata metadata.google.internal" >> /etc/hosts
fi

