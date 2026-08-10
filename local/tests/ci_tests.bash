#!/bin/bash -ex
#
# Copyright 2020 Google LLC
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

IMAGE=gcr.io/clusterfuzz-images/ci:bc696af-202407021946

SETUP_UV="pip install pipx==1.10.0 && pipx install uv==0.12.3 && export PATH=\$HOME/.local/bin:\$PATH"

docker run -i --rm \
  -e IS_GITHUB_ACTIONS=true \
  -v $(pwd):/workspace \
  $IMAGE \
  bash -c "$SETUP_UV && uv sync"
docker run -i --rm \
  -e IS_GITHUB_ACTIONS=true \
  -v $(pwd):/workspace \
  $IMAGE \
  bash -c "$SETUP_UV && uv run butler.py bootstrap"
docker run -i --rm \
  -e IS_GITHUB_ACTIONS=true \
  -v $(pwd):/workspace \
  $IMAGE \
  bash -c "$SETUP_UV && uv run butler.py lint"
docker run -i --rm --privileged --cap-add=all \
  -e IS_GITHUB_ACTIONS=true \
  -v $(pwd):/workspace \
  $IMAGE \
  bash -c "$SETUP_UV && uv run local/tests/run_tests"
