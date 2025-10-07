#!/bin/bash -ex
# Copyright 2025 Google LLC
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

IMAGES=(
  gcr.io/clusterfuzz-images/chromium/base/immutable
  gcr.io/clusterfuzz-images/chromium/base/immutable/dev
  gcr.io/clusterfuzz-images/base/immutable
)

if [ -n "$1" ]; then
  cd /workspace/clusterfuzz
fi

for image_name in "${IMAGES[@]}"; do
  echo $PWD
  CURRENT_CLUSTERFUZZ_REVISION="$(cat /workspace/revision.txt)"
  image_dir=docker/${image_name#gcr.io/clusterfuzz-images/}
  docker build --build-arg CLUSTERFUZZ_SOURCE_DIR=. -t "$image_name":${CURRENT_CLUSTERFUZZ_REVISION} -f "$image_dir/Dockerfile" .
  if [ "$2" == "true" ]; then
    docker push "$image_name":${CURRENT_CLUSTERFUZZ_REVISION}
  fi
done
