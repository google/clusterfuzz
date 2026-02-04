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

pip install pipenv

# Install dependencies.
pipenv --python 3.11
pipenv install

./local/install_deps.bash

# Run the test.
export K8S_E2E=1
pipenv run python butler.py py_unittest -t core -p k8s_service_e2e_test.py
