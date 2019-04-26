#!/bin/bash

docker_ip=$(ip -4 addr show docker0 | grep -P inet | head -1 | awk '{print $2}' | cut -d/ -f1)

docker run -ti --rm --privileged \
  -e LOCAL_METADATA_SERVER=$docker_ip -e LOCAL_METADATA_PORT=8080 \
  -e TEST_BLOBS_BUCKET=clusterfuzz-ci-blobs \
  -e TEST_BUCKET=clusterfuzz-ci-test \
  -e TEST_CORPUS_BUCKET=clusterfuzz-ci-corpus \
  -e TEST_QUARANTINE_BUCKET=clusterfuzz-ci-quarantine \
  -e TEST_BACKUP_BUCKET=clusterfuzz-ci-backup \
  -e TEST_COVERAGE_BUCKET=clusterfuzz-ci-coverage \
  -v $(pwd)/..:/workspace \
  gcr.io/clusterfuzz-images/ci /bin/bash
