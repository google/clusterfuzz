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

ENV UPDATE_WEB_TESTS True
ENV NFS_ROOT /mnt/nfs/cfvolume

# Note: snapcraft installation seems to always fail.
RUN echo ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true | debconf-set-selections && \
    curl 'https://chromium.googlesource.com/chromium/src/+/main/build/install-build-deps.sh?format=TEXT' | base64 -d > /tmp/install-build-deps.sh && \
    sed -i s/snapcraft/doesnotexist/ /tmp/install-build-deps.sh && \ 
    chmod u+x /tmp/install-build-deps.sh && \
    /tmp/install-build-deps.sh --backwards-compatible --no-prompt --no-chromeos-fonts --syms --lib32

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
        autofs \
        dbus-x11 \
        blackbox \
        libdconf-dev \
        libdconf1 \
        libdconf1:i386 \
        libgconf-2-4:i386 \
        libgconf2-dev \
        libgles2-mesa \
        nfs-common \
        nodejs \
        pulseaudio \
        xdotool \
        xvfb

# Needed for older versions of Chrome.
RUN ln -s /usr/lib/x86_64-linux-gnu/libudev.so /usr/lib/x86_64-linux-gnu/libudev.so.0
RUN curl -o /usr/lib/x86_64-linux-gnu/libgcrypt.so.11 https://clusterfuzz-data.storage.googleapis.com/libgcrypt.so.11

# Prepare NFS mount.
ENV NFS_CLUSTER_NAME=10.0.0.2 \
    NFS_DIR=/mnt/nfs \
    NFS_VOLUME_NAME=cfvolume
RUN mkdir $NFS_DIR && \
    sed -i 's/browse_mode = no/browse_mode = yes/' /etc/autofs.conf && \
    echo "$NFS_DIR   /etc/auto.nfs" >> /etc/auto.master

# Get pre-built msan libraries (with and without origin tracking).
RUN mkdir /msan-chained-origins && \
    curl -o /msan-chained-origins/libs.zip https://clusterfuzz-chromium-msan-libs.storage.googleapis.com/16.04/chained-origins/latest-201906130139.zip && \
    unzip /msan-chained-origins/libs.zip -d /msan-chained-origins && \
    rm /msan-chained-origins/libs.zip && \
    mkdir /msan-no-origins && \
    curl -o /msan-no-origins/libs.zip https://clusterfuzz-chromium-msan-libs.storage.googleapis.com/16.04/no-origins/latest-201906130139.zip && \
    unzip /msan-no-origins/libs.zip -d /msan-no-origins && \
    rm /msan-no-origins/libs.zip

ENV INSTRUMENTED_LIBRARIES_PATHS_MSAN_CHAINED /msan-chained-origins/lib/x86_64-linux-gnu:/msan-chained-origins/usr/lib/x86_64-linux-gnu
ENV INSTRUMENTED_LIBRARIES_PATHS_MSAN_NO_ORIGINS /msan-no-origins/lib/x86_64-linux-gnu:/msan-no-origins/usr/lib/x86_64-linux-gnu
ENV BOT_CONFIG linux_docker

COPY setup.sh setup_x.sh start.sh /data/

CMD ["bash", "-ex", "/data/start.sh"]
