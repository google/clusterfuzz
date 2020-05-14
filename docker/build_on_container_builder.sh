#!/bin/bash
#
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

# Change to this directory (docker), so as to use the correct cloudbuild.yaml.
cd "$(dirname "${0}")"

git fetch
git_diff=$(git diff origin/master --stat)
if [[ -n "$git_diff" ]]; then
  echo "You are not on origin/master."
  exit 1
fi

cp ../Pipfile* base/
gcloud builds submit . --project=clusterfuzz-images --substitutions=_GIT_HASH=$(git rev-parse HEAD | head -c7)
