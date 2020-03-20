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

export IMAGE=gcr.io/clusterfuzz-images/ci

docker run -ti --rm \
  -e PIPENV_VENV_IN_PROJECT=1 \
  -v $TRAVIS_BUILD_DIR:/workspace \
  $IMAGE \
  pipenv sync --dev
docker run -ti --rm \
  -e PIPENV_VENV_IN_PROJECT=1 \
  -v $TRAVIS_BUILD_DIR:/workspace \
  $IMAGE \
  pipenv run setup
docker run -ti --rm \
  -e PIPENV_VENV_IN_PROJECT=1 \
  -e TRAVIS_BRANCH=$TRAVIS_BRANCH \
  -v $TRAVIS_BUILD_DIR:/workspace \
  $IMAGE \
  pipenv run python butler.py lint
docker run -ti --rm --privileged --cap-add=all \
  -e PIPENV_VENV_IN_PROJECT=1 \
  -v $TRAVIS_BUILD_DIR:/workspace \
  $IMAGE \
  pipenv run local/tests/run_tests
