# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM gcr.io/clusterfuzz-images/base

ENV RUN_CMD \
    "python3.7 $ROOT_DIR/src/python/other-bots/chromium-tests-syncer/run.py"
ENV DISABLE_MOUNTS True
ENV EXTRA_PATH "/data/depot_tools"
ENV SYNC_INTERVAL 43200
ENV TESTS_ARCHIVE_BUCKET "clusterfuzz-data"
ENV TESTS_ARCHIVE_NAME "web_tests.zip"
ENV TESTS_DIR /home/$USER/tests

# Add git-core/ppa for latest git version. Otherwise, we fail on gclient sync.
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y ppa:git-core/ppa

RUN apt-get update && \
    apt-get install -y \
        git \
        subversion \
        zip

RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git \
    /data/depot_tools

RUN git clone https://gerrit.googlesource.com/gcompute-tools \
    /data/gcompute-tools

COPY start.sh setup_depot_tools.sh setup_gerrit.sh /data/
CMD ["bash", "-ex", "/data/start.sh"]
