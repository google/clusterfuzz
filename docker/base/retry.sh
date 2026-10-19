#!/bin/sh
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

# Usage: retry <command> [args...]
# Runs the command up to RETRY_ATTEMPTS times (default 5), waiting 10s, 20s,
# ... between attempts. Meant for flaky network commands during image builds.

attempts="${RETRY_ATTEMPTS:-5}"
i=1
while true; do
  "$@" && exit 0
  if [ "$i" -ge "$attempts" ]; then
    echo "retry: '$*' failed after $attempts attempts" >&2
    exit 1
  fi
  echo "retry: '$*' failed (attempt $i/$attempts), retrying in $((i * 10))s" >&2
  sleep $((i * 10))
  i=$((i + 1))
done
