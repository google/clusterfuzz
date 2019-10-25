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

IMAGES=(
  gcr.io/clusterfuzz-images/base
  gcr.io/clusterfuzz-images/high-end
  gcr.io/clusterfuzz-images/ml-with-gpu
  gcr.io/clusterfuzz-images/chromium/base
  gcr.io/clusterfuzz-images/chromium/builder
  gcr.io/clusterfuzz-images/chromium/high-end
  gcr.io/clusterfuzz-images/chromium/ml-with-gpu
  gcr.io/clusterfuzz-images/chromium/python-profiler
  gcr.io/clusterfuzz-images/chromium/tests-syncer
  gcr.io/clusterfuzz-images/oss-fuzz/base
  gcr.io/clusterfuzz-images/oss-fuzz/host
  gcr.io/clusterfuzz-images/oss-fuzz/host-high-end
  gcr.io/clusterfuzz-images/oss-fuzz/worker
  gcr.io/clusterfuzz-images/ci
  gcr.io/clusterfuzz-images/fuchsia
)

GIT_HASH=$1
stamp=$GIT_HASH-$(date -u +%Y%m%d%H%M)
for image in "${IMAGES[@]}"; do
  docker build -t $image ${image#gcr.io/clusterfuzz-images/}
  docker tag $image $image:$stamp
  docker push $image
  docker push $image:$stamp
done

echo Built and pushed images successfully with stamp $stamp
