# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law of or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM gcr.io/clusterfuzz-images/base:ubuntu24-04

ENV UPDATE_WEB_TESTS True

# Note: snapcraft installation seems to always fail.
RUN apt-get update && apt-get install -y file &&     echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true | debconf-set-selections &&     curl 'https://chromium.googlesource.com/chromium/src/+/main/build/install-build-deps.py?format=TEXT' | base64 -d > /tmp/install-build-deps.py &&     sed -i s/snapcraft/doesnotexist/ /tmp/install-build-deps.py &&     sed -i "s/if requires_pinned_linux_libc():/if False:/" /tmp/install-build-deps.py &&     chmod u+x /tmp/install-build-deps.py &&     /tmp/install-build-deps.py --backwards-compatible --no-prompt --no-chromeos-fonts --syms --lib32

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
        autofs \
        dbus-x11 \
        blackbox \
        libdconf-dev \
        libdconf1 \
        libdconf1:i386 \
        libgbm1:i386 \
        libgles2 \
        nfs-common \
        pulseaudio \
        xdotool \
        xvfb

ENV BOT_CONFIG linux_docker

COPY setup.sh setup_x.sh start.sh /data/

CMD ["bash", "-ex", "/data/start.sh"]