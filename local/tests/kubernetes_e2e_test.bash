#!/bin/bash -ex
#
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

# This script is for running the Kubernetes end-to-end test in CI.

# Install kind.
mkdir -p "$HOME/.local/bin"
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
mv ./kind "$HOME/.local/bin/kind"
export PATH=$PATH:$HOME/.local/bin

# Install pipenv.
pip install pipenv

# Install dependencies.
pipenv install --dev

# Run the test.
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
pipenv run python3 src/clusterfuzz/_internal/tests/core/platforms/kubernetes/service_e2e_test.py
