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

# Default values
VERSION_TAG="latest"
GIT_HASH_ARG=""
PUSH="true"
NEEDS_ROOT_PIPFILE=false

# Set up a trap to clean up Pipfiles on exit.
function cleanup() {
  if [[ "$NEEDS_ROOT_PIPFILE" == "true" ]]; then
    rm -f base/Pipfile base/Pipfile.lock
  fi
}
trap cleanup EXIT

# Parse command-line arguments
# The first two arguments are positional for backwards compatibility.
if [ -n "$1" ] && ! [[ "$1" =~ ^-- ]]; then
    VERSION_TAG="$1"
    shift
fi
if [ -n "$1" ] && ! [[ "$1" =~ ^-- ]]; then
    GIT_HASH_ARG="$1"
    shift
fi

# Parse optional flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --no-push) PUSH="false";;
        "") ;; # Ignore empty arguments, which can be passed by Cloud Build.
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

function docker_push {
  if [ "$PUSH" == "true" ]; then
    docker push "$image_with_version_tag"
    docker push "$image_with_stamp"
  else
    echo "Skipping push for $image_with_version_tag."
  fi
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
    dockerfile="$image_dir/${VERSION_TAG}Dockerfile"
  fi

  if [ ! -f "$dockerfile" ]; then
    echo "Skipping $dockerfile since it does not exist."
    continue
  fi
  
  image_with_version_tag="$image_name:$VERSION_TAG"
  image_with_stamp="$image_name:$stamp"

  # Copy Pipfile to base for the ubuntu-24.04 build, as it's
  # needed but not in the build context.
  if [[ "$image_dir" == "base" && "$dockerfile" == *"ubuntu-24-04"* ]]; then
    NEEDS_ROOT_PIPFILE=true
    cp ../Pipfile ../Pipfile.lock base/
  fi

  docker build -t "$image_with_version_tag" -f "$dockerfile" "$image_dir"

  # Clean up the copied files.
  if [[ "$NEEDS_ROOT_PIPFILE" == "true" ]]; then
    rm base/Pipfile base/Pipfile.lock
    NEEDS_ROOT_PIPFILE=false
  fi

  docker tag "$image_with_version_tag" "$image_with_stamp"
  docker_push
done

if [ "$PUSH" == "true" ]; then
  echo "Built and pushed images successfully for version $VERSION_TAG with stamp $stamp"
else
  echo "Built images successfully (without push) for version $VERSION_TAG with stamp $stamp"
fi
