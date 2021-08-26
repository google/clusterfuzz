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

# Copy some commonly linked library versions from xenial for backwards
# compatibility with older builds.
FROM ubuntu:16.04 as xenial
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y \
      libcurl3-gnutls \
      libffi6 \
      libnettle6 \
      libssl1.0.0

FROM ubuntu:20.04

RUN mkdir /data
WORKDIR /data

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y && \
    apt-get install -y \
        apt-transport-https \
        build-essential \
        curl \
        gdb \
        iproute2 \
        libbz2-dev \
        libcurl4-openssl-dev \
        libffi-dev \
        libgdbm-dev \
        libidn11 \
        liblzma-dev \
        libncurses5-dev \
        libncursesw5 \
        libnss3-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl-dev \
        libtinfo5 \
        locales \
        lsb-release \
        net-tools \
        psmisc \
        socat \
        sudo \
        unzip \
        util-linux \
        wget \
        zip \
        zlib1g-dev

COPY --from=xenial \
    /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 \
    /lib/x86_64-linux-gnu/libssl.so.1.0.0 \
    /lib/x86_64-linux-gnu/
COPY --from=xenial \
    /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.* \
    /usr/lib/x86_64-linux-gnu/libffi.so.6.* \
    /usr/lib/x86_64-linux-gnu/libnettle.so.* \
    /usr/lib/x86_64-linux-gnu/

# Install patchelf.
RUN curl -sS https://releases.nixos.org/patchelf/patchelf-0.9/patchelf-0.9.tar.bz2 | tar -C /tmp -xj && \
    cd /tmp/patchelf-*/ && \
    ./configure --prefix=/usr && \
    make install

# Install OpenJDK 15 for Jazzer (Java fuzzer).
# Copied from gcr.io/oss-fuzz-base/base-runner.
ENV JAVA_HOME=/usr/lib/jvm/java-15-openjdk-amd64
ENV JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
ENV PATH=$PATH:$JAVA_HOME/bin
RUN wget https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz -O /tmp/openjdk-15.0.2_linux-x64_bin.tar.gz && \
    cd /tmp && \
    mkdir -p $JAVA_HOME && \
    tar -xzv --strip-components=1 -f openjdk-15.0.2_linux-x64_bin.tar.gz --directory $JAVA_HOME && \
    rm -rf openjdk*.tar.gz $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

# Install Python 3.
RUN curl -sS https://www.python.org/ftp/python/3.7.7/Python-3.7.7.tgz | tar -C /tmp -xzv && \
    cd /tmp/Python-3.7.7 && \
    ./configure --enable-optimizations --enable-loadable-sqlite-extensions && make altinstall && \
    rm -rf /tmp/Python-3.7.7
RUN pip3.7 install pipenv

RUN echo "deb https://packages.cloud.google.com/apt cloud-sdk main" \
    | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | apt-key add - && \
    apt-get update -y && \
    apt-get install -y google-cloud-sdk

# Set up google-fluentd
# We ignore errors in install-logging-agent.sh as it always fails to start
# after installation without a metadata server.
RUN curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh && \
    bash install-logging-agent.sh || true && \
    sed -i 's/flush_interval 5s/flush_interval 60s/' /etc/google-fluentd/google-fluentd.conf
COPY clusterfuzz-fluentd.conf /etc/google-fluentd/config.d/clusterfuzz.conf

# Common environment variables.
ENV USER=clusterfuzz
ENV INSTALL_DIRECTORY /mnt/scratch0
ENV BOT_TMPDIR $INSTALL_DIRECTORY/tmp
ENV ROOT_DIR $INSTALL_DIRECTORY/clusterfuzz
ENV UPDATE_WEB_TESTS True
ENV PYTHONPATH $INSTALL_DIRECTORY/clusterfuzz/src
ENV RUN_CMD "python3.7 $ROOT_DIR/src/python/bot/startup/run.py"
ENV DEPLOYMENT_ZIP "linux-3.zip"

# Passwordless sudo (needed for AFL launcher).
RUN groupadd nopwsudo && \
    echo "%nopwsudo ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/mysudoers

# Make sure GSUtil uses the GCE service account.
RUN echo '[GoogleCompute]\nservice_account = default' > /etc/boto.cfg

VOLUME $INSTALL_DIRECTORY
WORKDIR $INSTALL_DIRECTORY

RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV PYTHONIOENCODING UTF-8

COPY setup_common.sh setup_clusterfuzz.sh setup_nfs.sh start_clusterfuzz.sh setup_mock_metadata.sh start.sh Pipfile Pipfile.lock /data/
RUN cd /data && \
    # Make pip3.7 the default so that pipenv install --system works.
    mv /usr/local/bin/pip3.7 /usr/local/bin/pip && \
    pipenv install --deploy --system && \
    # Install tensorflow here as it's not included in the Pipfile due to
    # strict python version requirements.
    pip install tensorflow==2.3.0
CMD ["bash", "-ex", "/data/start.sh"]

