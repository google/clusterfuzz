#!/bin/bash -ex

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
