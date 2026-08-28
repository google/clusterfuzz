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
  gcr.io/clusterfuzz-images/chromium/tests-syncer
  gcr.io/clusterfuzz-images/oss-fuzz/base
  gcr.io/clusterfuzz-images/oss-fuzz/host-high-end
  gcr.io/clusterfuzz-images/ci
  gcr.io/clusterfuzz-images/utask-main-scheduler
  gcr.io/clusterfuzz-images/tworker
  gcr.io/clusterfuzz-images/fuchsia
)

# Default values
VERSION_TAG="latest"
GIT_HASH_ARG=""
PUSH="true"
SKIP_LATEST_TAG="false"
TARGET_IMAGE=""
REGISTRY_PREFIX=${REGISTRY_PREFIX:-"gcr.io/clusterfuzz-images"}
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
        --skip-latest-tag) SKIP_LATEST_TAG="true";;
        --image) TARGET_IMAGE="$2"; shift;;
        --image=*) TARGET_IMAGE="${1#*=}";;
        --registry-prefix) REGISTRY_PREFIX="$2"; shift;;
        --registry-prefix=*) REGISTRY_PREFIX="${1#*=}";;
        --project) REGISTRY_PREFIX="gcr.io/$2"; shift;;
        --project=*) REGISTRY_PREFIX="gcr.io/${1#*=}";;
        "") ;; # Ignore empty arguments, which can be passed by Cloud Build.
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -n "$TARGET_IMAGE" ]; then
  FILTERED_IMAGES=()
  for img in "${IMAGES[@]}"; do
    if [[ "$img" == *"$TARGET_IMAGE"* ]]; then
      FILTERED_IMAGES+=("$img")
    fi
  done
  if [ ${#FILTERED_IMAGES[@]} -eq 0 ]; then
    echo "No images matching target '$TARGET_IMAGE'"
    exit 1
  fi
  IMAGES=("${FILTERED_IMAGES[@]}")
fi

function docker_push {
  if [ "$PUSH" == "true" ]; then
    if [ "$SKIP_LATEST_TAG" != "true" ]; then
      docker push "$image_with_version_tag"
    fi
    docker push "$image_with_stamp"
  else
    echo "Skipping push for $image_with_stamp."
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

for image_path in "${IMAGES[@]}"; do
  image_dir=${image_path#gcr.io/clusterfuzz-images/}
  image_name="$REGISTRY_PREFIX/$image_dir"
  
  if [ "$VERSION_TAG" == "latest" ]; then
    dockerfile="$image_dir/Dockerfile"
  else
    dockerfile="$image_dir/${VERSION_TAG}.Dockerfile"
  fi

  if [ ! -f "$dockerfile" ]; then
    echo "Skipping $dockerfile since it does not exist."
    continue
  fi
  
  image_with_version_tag="$image_name:$VERSION_TAG"
  image_with_stamp="$image_name:$stamp"

  # Copy Pipfile to base as it's needed but not in the base build context.
  if [[ "$image_dir" == "base" ]]; then
    NEEDS_ROOT_PIPFILE=true
    cp ../Pipfile ../Pipfile.lock base/
  fi

  if [ "$SKIP_LATEST_TAG" == "true" ]; then
    docker build -t "$image_with_stamp" -f "$dockerfile" "$image_dir"
  else
    docker build -t "$image_with_version_tag" -f "$dockerfile" "$image_dir"
    docker tag "$image_with_version_tag" "$image_with_stamp"
  fi

  # Clean up the copied files.
  if [[ "$NEEDS_ROOT_PIPFILE" == "true" ]]; then
    rm base/Pipfile base/Pipfile.lock
    NEEDS_ROOT_PIPFILE=false
  fi

  docker_push
done

if [ "$PUSH" == "true" ]; then
  echo "Built and pushed images successfully for version $VERSION_TAG with stamp $stamp"
else
  echo "Built images successfully (without push) for version $VERSION_TAG with stamp $stamp"
fi
