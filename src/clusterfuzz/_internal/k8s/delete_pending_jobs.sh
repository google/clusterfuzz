#!/bin/bash
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
#
# Script to delete pending Kubernetes jobs in batches.

BATCH_SIZE=1000
NAMESPACE="default"

echo "Listing pending jobs in namespace '${NAMESPACE}'..."

# Get list of pending jobs (completions usually 0/1)
# We assume pending jobs have '0/1' in the COMPLETIONS column (2nd column usually).
# Adjust awk if your kubectl output differs.
# Safer: check json output. But for a quick script:
# kubectl get jobs -o wide
# NAME   COMPLETIONS   DURATION   AGE   CONTAINERS   IMAGES   SELECTOR
# job1   0/1           10s        10s   ...          ...      ...

# Using -o custom-columns to be sure about the column content
# We select jobs where status.succeeded is not equal to status.completions (or null)
# But filtering logic in bash is easier with just listing names of incomplete jobs.
# Pending jobs have .status.succeeded != 1 (assuming parallelism 1).

# Let's get all jobs and filter those with 0 completions.
JOBS=$(kubectl get jobs -n "${NAMESPACE}" -o jsonpath='{range .items[?(@.status.succeeded!=1)]}{.metadata.name}{"\n"}{end}')

if [ -z "$JOBS" ]; then
  echo "No pending jobs found."
  exit 0
fi

JOB_COUNT=$(echo "$JOBS" | wc -l)
echo "Found ${JOB_COUNT} pending jobs."

# Process in batches
echo "$JOBS" | xargs -n "${BATCH_SIZE}" sh -c '
  echo "Deleting batch of jobs..."
  kubectl delete jobs -n "'""${NAMESPACE}""'" --propagation=Background "$@"
' --

echo "Finished deleting pending jobs."
