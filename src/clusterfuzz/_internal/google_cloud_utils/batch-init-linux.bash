#!/usr/bin/env bash
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
set -euox pipefail

# Performance tweaks.
SWAP="/var/swap"
fallocate -l 1G $SWAP
chmod 600 $SWAP
mkswap $SWAP

swapon -a
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
echo core   > /proc/sys/kernel/core_pattern  # For AFL.
sysctl -w vm.disk_based_swap=1
sysctl -w vm.swappiness=10
# Disable hung task checking. Otherwise we may incorrectly panic when we use
# up CPU/disk from fuzzing or downloading large builds.
sysctl -w kernel.hung_task_timeout_secs=0

# More config.
useradd --system --home-dir /home/root --uid 1337 clusterfuzz
mkdir -p /home/root /var/scratch0
chown clusterfuzz:clusterfuzz /var/scratch0 /home/root
docker-credential-gcr configure-docker

docker run --rm --net=host \
  -v /var/scratch0:/mnt/scratch0 \
  --privileged --cap-add=ALL \
  --name=clusterfuzz \
  --memory-swappiness=40 --shm-size=1.9g --rm --net=host \
  -e HOST_UID=1337 -P --privileged --cap-add=all \
  -e CLUSTERFUZZ_RELEASE -e UNTRUSTED_WORKER=False -e UWORKER=True \
  -e UWORKER_INPUT_DOWNLOAD_URL \
  $IMAGE