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

# This script builds immutable Docker images for ClusterFuzz.
# It iterates through a predefined list of images, builds them using the
# Dockerfiles found in subdirectories, and optionally pushes them to a container
# registry.

# An array of Docker image names to be built.
IMAGES=(
  gcr.io/clusterfuzz-images/chromium/base/immutable
  gcr.io/clusterfuzz-images/base/immutable
)

# If an argument is provided, change the current directory to
# /workspace/clusterfuzz. This is typically used in CI/CD environments where the
# script is executed from a different context.
if [ -n "$1" ]; then
  cd /workspace/clusterfuzz
fi

# Loop through each image name in the IMAGES array.
for image_name in "${IMAGES[@]}"; do
  # Read the ClusterFuzz revision from the revision.txt file. This is used to
  # tag the Docker images.
  CURRENT_CLUSTERFUZZ_REVISION="$(cat /workspace/revision.txt)"

  # Determine the directory containing the Dockerfile and related build context.
  project_dir=docker/${image_name#gcr.io/clusterfuzz-images/}

  # Loop through each subdirectory in the project directory. This allows for
  # building multiple image variants from the same base project directory.
  for image_dir in ${project_dir}/*; do
    # Build the Docker image.
    # --build-arg CLUSTERFUZZ_SOURCE_DIR=.: Passes the location of the
    #   ClusterFuzz source directory as a build argument.
    # -t "$image_name":${CURRENT_CLUSTERFUZZ_REVISION}: Tags the image with its
    #   name and the current ClusterFuzz revision.
    # -f "$image_dir/Dockerfile": Specifies the path to the Dockerfile.
    # .: Sets the build context to the current directory.
    docker build --build-arg CLUSTERFUZZ_SOURCE_DIR=. -t "$image_name":${CURRENT_CLUSTERFUZZ_REVISION} -f "$image_dir/Dockerfile" .

    # If the second argument to the script is "true", push the newly built
    # image to the container registry.
    if [ "$2" == "true" ]; then
      docker push "$image_name":${CURRENT_CLUSTERFUZZ_REVISION}
    fi
  done
done
