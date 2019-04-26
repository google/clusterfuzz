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

docker_ip=$(ip -4 addr show docker0 | grep -P inet | head -1 | awk '{print $2}' | cut -d/ -f1)

docker run -ti --rm --privileged \
  -e LOCAL_METADATA_SERVER=$docker_ip -e LOCAL_METADATA_PORT=8080 \
  -e TEST_BLOBS_BUCKET=clusterfuzz-ci-blobs \
  -e TEST_BUCKET=clusterfuzz-ci-test \
  -e TEST_CORPUS_BUCKET=clusterfuzz-ci-corpus \
  -e TEST_QUARANTINE_BUCKET=clusterfuzz-ci-quarantine \
  -e TEST_BACKUP_BUCKET=clusterfuzz-ci-backup \
  -e TEST_COVERAGE_BUCKET=clusterfuzz-ci-coverage \
  -v $(pwd)/..:/workspace \
  gcr.io/clusterfuzz-images/ci /bin/bash
