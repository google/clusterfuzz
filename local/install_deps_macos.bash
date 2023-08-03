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

if ! which gcloud > /dev/null 2>&1; then
  echo 'Please install the google cloud SDK (https://cloud.google.com/sdk/install)'
  exit 1
fi

if ! which brew > /dev/null 2>&1; then
  echo 'Please install homebrew (https://brew.sh).'
  exit 1
fi

brew bundle --file=$(dirname "$0")/Brewfile

pipenv --python 3.7
pipenv sync --dev
source "$(pipenv --venv)/bin/activate"

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
Please load environment by running 'pipenv shell'.

"
