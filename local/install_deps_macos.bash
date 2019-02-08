#!/bin/bash -ex
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

if ! which brew > /dev/null 2>&1; then
  echo 'Please install homebrew (https://brew.sh).'
  exit 1
fi

bazel_tap="bazelbuild/tap"

if ! brew tap | grep $bazel_tap > /dev/null 2>&1; then
  brew tap $bazel_tap
fi

if ! brew tap --list-pinned | grep $bazel_tap > /dev/null 2>&1; then
  brew tap-pin $bazel_tap
fi

brew install \
    bazel \
    golang \
    node \
    nodeenv \
    npm \
    pkill \
    python@2 \
    xz

pip install virtualenv

# Setup virtualenv.
rm -rf ENV
virtualenv ENV
source ENV/bin/activate

# Install needed python packages.
pip install --upgrade pip
pip install --upgrade -r docker/ci/requirements.txt
pip install --upgrade -r src/local/requirements.txt

# Install other dependencies (e.g. bower).
nodeenv -p --prebuilt
npm install -g bower polymer-bundler
bower install

gcloud components install --quiet \
    app-engine-go \
    app-engine-python \
    app-engine-python-extras \
    beta \
    cloud-datastore-emulator \
    pubsub-emulator

# Bootstrap code structure.
python butler.py bootstrap

set +x
echo "

Installation succeeded!
Please load virtualenv environment by running 'source ENV/bin/activate'.

"
