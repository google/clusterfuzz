#!/bin/bash -ex
#
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

if [ "$(uname)" != "Linux" ]; then
  echo "install_deps_test_linux.bash is supported on Linux only."
  exit 0
fi

# Store repository root directory before cloning.
REPO_DIR=$(git rev-parse --show-toplevel)

TEMP_DIR=$(mktemp -d -t clusterfuzz-fresh-install-XXXXXX)
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Clone a clean copy of the repo to test installation in an isolated fresh checkout.
git clone "$REPO_DIR" "$TEMP_DIR/clusterfuzz"
cd "$TEMP_DIR/clusterfuzz"

# Verify initial clean state (no venv or vendored directories).
if [ -d .venv ]; then
  echo "ERROR: .venv should not exist in fresh checkout."
  exit 1
fi
if [ -d src/third_party ]; then
  echo "ERROR: src/third_party should not exist in fresh checkout."
  exit 1
fi
if [ -d src/appengine/third_party ]; then
  echo "ERROR: src/appengine/third_party should not exist in fresh checkout."
  exit 1
fi
if [ -f src/appengine/requirements.txt ]; then
  echo "ERROR: src/appengine/requirements.txt should not exist in fresh checkout."
  exit 1
fi

# Run installation script for fresh setup.
./local/install_deps.bash

# Verify virtual environment and python installation.
if [ ! -f .venv/bin/python ]; then
  echo "ERROR: .venv/bin/python was not created."
  exit 1
fi

# Verify vendored core third_party packages.
if [ ! -d src/third_party/google/cloud/monitoring_v3 ]; then
  echo "ERROR: src/third_party/google/cloud/monitoring_v3 missing."
  exit 1
fi

# Verify vendored appengine third_party packages.
if [ ! -d src/appengine/third_party/flask ]; then
  echo "ERROR: src/appengine/third_party/flask missing."
  exit 1
fi

# Verify generated appengine requirements.txt for deployment.
if [ ! -f src/appengine/requirements.txt ]; then
  echo "ERROR: src/appengine/requirements.txt missing."
  exit 1
fi

# Verify bower frontend components.
if [ ! -d src/appengine/private/bower_components ]; then
  echo "ERROR: src/appengine/private/bower_components missing."
  exit 1
fi

# Verify linting passes in fresh environment.
uv run butler.py lint

# Verify running core and appengine unit tests passes in fresh environment.
uv run butler.py py_unittest -t core -p deploy_test.py
uv run butler.py py_unittest -t appengine -p home_test.py

echo "SUCCESS: Fresh checkout setup using local/install_deps.bash verified!"
