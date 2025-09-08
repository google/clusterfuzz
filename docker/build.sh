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
  gcr.io/clusterfuzz-images/base
  gcr.io/clusterfuzz-images/high-end
  gcr.io/clusterfuzz-images/chromium/base
  gcr.io/clusterfuzz-images/chromium/builder
  gcr.io/clusterfuzz-images/chromium/high-end
  gcr.io/clusterfuzz-images/chromium/tester
  gcr.io/clusterfuzz-images/chromium/tests-syncer
  gcr.io/clusterfuzz-images/oss-fuzz/base
  gcr.io/clusterfuzz-images/oss-fuzz/host
  gcr.io/clusterfuzz-images/oss-fuzz/host-high-end
  gcr.io/clusterfuzz-images/oss-fuzz/worker
  gcr.io/clusterfuzz-images/ci
  gcr.io/clusterfuzz-images/utask-main-scheduler
  gcr.io/clusterfuzz-images/tworker
  gcr.io/clusterfuzz-images/fuchsia
)

# The first argument is the version tag, e.g., 'latest', 'ubuntu-20-04'.
VERSION_TAG=${1:-latest}
# The second argument is the git hash.
GIT_HASH_ARG=${2}

function docker_push {
  docker push "$image_with_version_tag"
  docker push "$image_with_stamp"
}

if [ -z "$GIT_HASH_ARG" ]; then
  GIT_HASH=$(git rev-parse HEAD | head -c7)
else
  GIT_HASH=$GIT_HASH_ARG
fi

DATE_STAMP=$(date -u +%Y%m%d%H%M)
if [ "$VERSION_TAG" == "latest" ]; then
  stamp="$GIT_HASH-$DATE_STAMP"
else
  stamp="$VERSION_TAG-$GIT_HASH-$DATE_STAMP"
fi

for image_name in "${IMAGES[@]}"; do
  image_dir=${image_name#gcr.io/clusterfuzz-images/}
  
  if [ "$VERSION_TAG" == "latest" ]; then
    dockerfile="$image_dir/Dockerfile"
  else
    dockerfile="$image_dir/$VERSION_TAG.Dockerfile"
  fi

  if [ ! -f "$dockerfile" ]; then
    echo "Skipping $dockerfile since it does not exist."
    continue
  fi
  
  image_with_version_tag="$image_name:$VERSION_TAG"
  image_with_stamp="$image_name:$stamp"

  docker build -t "$image_with_version_tag" -f "$dockerfile" "$image_dir"
  docker tag "$image_with_version_tag" "$image_with_stamp"
  docker_push
done

echo "Built and pushed images successfully for version $VERSION_TAG with stamp $stamp"
