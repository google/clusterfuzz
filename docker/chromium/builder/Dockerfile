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
FROM gcr.io/clusterfuzz-images/base@sha256:1110514de5bb678562b75e5cf65130923bd22bb9371dcbc9e99483fd277ac135

ENV RUN_CMD \
   "python3 $ROOT_DIR/src/python/other-bots/chromium-builder/run.py"
ENV BUCKET_PREFIX "chromium-browser-"
ENV BUILD_DIR /home/$USER/builds
ENV DISABLE_MOUNTS True
ENV EXTRA_PATH "/data/depot_tools"
ENV WAIT_TIME 7200

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

# Fix PATH to prefer /usr/local/bin to avoid build failures with using older
# Python 3 in /usr/bin.
ENV PATH /usr/local/bin:$PATH
CMD ["bash", "-ex", "/data/start.sh"]
