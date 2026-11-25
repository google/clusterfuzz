#!/bin/bash
# Copyright 2026 Google LLC
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

# Verifies open file soft limits inside Ubuntu 24.04 ClusterFuzz images.
# Base image builds require /etc/security/limits.d/99-clusterfuzz-nofile.conf,
# while immutable image PR builds pull the pre-merge GCR base image and verify
# PAM limits whenever the base image already includes that file.

MIN_EXPECTED_NOFILE_SOFT_LIMIT=65535
INITIAL_LOW_NOFILE_SOFT_LIMIT=1024

function verify_ubuntu24_base_open_file_limit {
  local image_ref="$1"
  docker run --rm \
    --ulimit "nofile=${MIN_EXPECTED_NOFILE_SOFT_LIMIT}:${MIN_EXPECTED_NOFILE_SOFT_LIMIT}" \
    --entrypoint bash "$image_ref" -c '
      set -euo pipefail
      min_limit="$1"
      low_limit="$2"
      test -f /data/start_clusterfuzz.sh
      test -f /etc/security/limits.d/99-clusterfuzz-nofile.conf
      id -u clusterfuzz >/dev/null 2>&1 || useradd -mU -G nopwsudo clusterfuzz
      sudo_limit=$(sudo -E -H -u clusterfuzz bash -c "ulimit -Sn")
      test "$sudo_limit" -ge "$min_limit"
      root_sudo_limit=$(sudo -E -H -u root bash -c "ulimit -Sn")
      test "$root_sudo_limit" -ge "$min_limit"
      rm -f /etc/security/limits.d/99-clusterfuzz-nofile.conf
      ulimit -Sn "$low_limit"
      startup_limit=$(USER=clusterfuzz RUN_CMD="ulimit -Sn" bash /data/start_clusterfuzz.sh)
      test "$startup_limit" -ge "$min_limit"
    ' _ "$MIN_EXPECTED_NOFILE_SOFT_LIMIT" "$INITIAL_LOW_NOFILE_SOFT_LIMIT"
}

function verify_ubuntu24_immutable_open_file_limit {
  local image_ref="$1"
  docker run --rm \
    --ulimit "nofile=${MIN_EXPECTED_NOFILE_SOFT_LIMIT}:${MIN_EXPECTED_NOFILE_SOFT_LIMIT}" \
    --entrypoint bash "$image_ref" -c '
      set -euo pipefail
      min_limit="$1"
      low_limit="$2"
      test -f /data/start_clusterfuzz.sh
      id -u clusterfuzz >/dev/null 2>&1 || useradd -mU -G nopwsudo clusterfuzz
      if [[ -f /etc/security/limits.d/99-clusterfuzz-nofile.conf ]]; then
        sudo_limit=$(sudo -E -H -u clusterfuzz bash -c "ulimit -Sn")
        test "$sudo_limit" -ge "$min_limit"
        root_sudo_limit=$(sudo -E -H -u root bash -c "ulimit -Sn")
        test "$root_sudo_limit" -ge "$min_limit"
        rm -f /etc/security/limits.d/99-clusterfuzz-nofile.conf
      fi
      ulimit -Sn "$low_limit"
      startup_limit=$(USER=clusterfuzz RUN_CMD="ulimit -Sn" bash /data/start_clusterfuzz.sh)
      test "$startup_limit" -ge "$min_limit"
    ' _ "$MIN_EXPECTED_NOFILE_SOFT_LIMIT" "$INITIAL_LOW_NOFILE_SOFT_LIMIT"
}
