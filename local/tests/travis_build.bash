#!/bin/bash -ex

export IMAGE=gcr.io/clusterfuzz-images/ci

docker run -ti --rm -v $TRAVIS_BUILD_DIR:/workspace $IMAGE setup
docker run -ti --rm -e TRAVIS_BRANCH=$TRAVIS_BRANCH -v $TRAVIS_BUILD_DIR:/workspace $IMAGE python butler.py lint
docker run -ti --rm --privileged --cap-add=all -v $TRAVIS_BUILD_DIR:/workspace $IMAGE local/tests/run_tests
