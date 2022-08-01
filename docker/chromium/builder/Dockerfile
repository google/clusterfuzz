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
   "python3.7 $ROOT_DIR/src/python/other-bots/chromium-builder/run.py"
ENV BUCKET_PREFIX "chromium-browser-"
ENV BUILD_DIR /home/$USER/builds
ENV DISABLE_MOUNTS True
ENV EXTRA_PATH "/data/depot_tools"
ENV WAIT_TIME 7200

# Add git-core/ppa for latest git version. Otherwise, we fail on gclient sync.
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository -y ppa:git-core/ppa

RUN apt-get update && \
    apt-get install -y \
        git \
        subversion \
        zip

# Note: snapcraft installation seems to always fail.
RUN echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true | debconf-set-selections && \
    curl 'https://chromium.googlesource.com/chromium/src/+/main/build/install-build-deps.sh?format=TEXT' | base64 -d > /tmp/install-build-deps.sh && \
    sed -i s/snapcraft/doesnotexist/ /tmp/install-build-deps.sh && \ 
    chmod u+x /tmp/install-build-deps.sh && \
    /tmp/install-build-deps.sh --backwards-compatible --no-prompt --no-chromeos-fonts --syms

RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git \
    /data/depot_tools

RUN git clone https://gerrit.googlesource.com/gcompute-tools \
    /data/gcompute-tools

COPY start.sh setup_depot_tools.sh setup_gerrit.sh /data/

# Fix PATH to prefer /usr/local/bin to avoid build failures with using older
# Python 3 in /usr/bin.
ENV PATH /usr/local/bin:$PATH
RUN ln -s /usr/local/bin/python3.7 /usr/local/bin/python3
CMD ["bash", "-ex", "/data/start.sh"]
