# Copyright 2025 Google LLC
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

FROM ubuntu:24.04

# Prevent interactive prompts during package installation. This seems to work
# better than `ENV DEBIAN_FRONTEND=noninteractive` for some reason.
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN mkdir /data
WORKDIR /data

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y && \
    apt-get install -y \
        apt-transport-https \
        build-essential \
        curl \
        file \
        gdb \
        iproute2 \
        libbz2-dev \
        libcurl4-openssl-dev \
        libffi-dev \
        libgdbm-dev \
        libidn12 \
        liblzma-dev \
        libncurses-dev \
        libncursesw6 \
        libnss3-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl-dev \
        libtinfo6 \
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

# Install patchelf.
RUN curl -sS https://releases.nixos.org/patchelf/patchelf-0.9/patchelf-0.9.tar.bz2 | tar -C /tmp -xj && \
    cd /tmp/patchelf-*/ && \
    ./configure --prefix=/usr && \
    make install && \
    rm -rf /tmp/patchelf-*

# Install Ruby, for Ruby fuzzing.
RUN apt-get update && apt-get install -y binutils xz-utils libyaml-dev libffi-dev zlib1g-dev && \
    RUBY_VERSION=3.3.13 && \
    curl -O https://cache.ruby-lang.org/pub/ruby/3.3/ruby-$RUBY_VERSION.tar.gz && \
    tar -xvf ruby-$RUBY_VERSION.tar.gz && \
    cd ruby-$RUBY_VERSION && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    cd - && \
    rm -rf ruby-$RUBY_VERSION ruby-$RUBY_VERSION.tar.gz && \
    # Ruby 3.3 bundles net-imap 0.4.x; replace it with the 0.5 line.
    gem install --no-document net-imap -v 0.5.15 && \
    gem cleanup net-imap

# Install OpenJDK 17 for Jazzer (Java fuzzer).
# Copied from gcr.io/oss-fuzz-base/base-runner.
ENV JAVA_HOME /usr/lib/jvm/java-17-openjdk-amd64
ENV JAVA_15_HOME /usr/lib/jvm/java-15-openjdk-amd64
ENV JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
ENV PATH=$PATH:$JAVA_HOME/bin

RUN cd /tmp && \
    curl --silent -L -O https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz && \
    mkdir -p $JAVA_HOME && \
    tar -xzv --strip-components=1 -f openjdk-17.0.2_linux-x64_bin.tar.gz --directory $JAVA_HOME && \
    rm -rf openjdk*.tar.gz $JAVA_HOME/jmods $JAVA_HOME/lib/src.zip

 # Install OpenJDK 15 and trim its size by removing unused components. Some projects only run with Java 15.
RUN cd /tmp && \
    curl --silent -L -O https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz && \
    mkdir -p $JAVA_15_HOME && \
    tar -xz --strip-components=1 -f openjdk-15.0.2_linux-x64_bin.tar.gz --directory $JAVA_15_HOME && \
    rm -rf openjdk*.tar.gz $JAVA_15_HOME/lib/src.zip

# Install Python 3.11
RUN curl -sS https://www.python.org/ftp/python/3.11.18/Python-3.11.18.tgz | tar -C /tmp -xzv && \
    cd /tmp/Python-3.11.18 && \
    ./configure --enable-optimizations --enable-loadable-sqlite-extensions && make altinstall && \
    rm -rf /tmp/Python-3.11.18 /tmp/Python-3.11.18.tar.xz && \
    cd / && \
    # Upgrade the pip and setuptools that ensurepip installed, and drop its
    # bundled wheels: nothing in the image uses ensurepip.
    # setuptools stays on 81: 82 dropped pkg_resources, which pipenv 2022.8.5
    # still imports.
    pip3.11 --no-cache-dir install --upgrade pip==26.2.2 setuptools==81.0.0 && \
    rm -f /usr/local/lib/python3.11/ensurepip/_bundled/*.whl
# virtualenv also embeds pip and setuptools wheels for Python 3.9 environments.
# Only the Python 3.11 ones are used here.
RUN pip3.11 --no-cache-dir install pipenv==2022.8.5 virtualenv==21.15.1 && \
    cd /usr/local/lib/python3.11/site-packages/virtualenv/seed/wheels/embed && \
    rm pip-26.0.1-py3-none-any.whl setuptools-82.0.1-py3-none-any.whl
RUN ln -s /usr/local/bin/python3.11 /usr/bin/python3.11 && \
    ln -s /usr/bin/python3.11 /usr/bin/python3

# Install Node.js 22.x from binary to maintain version consistency
RUN cd /tmp && \
    curl -sSL https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz -o node.tar.xz && \
    tar -xJf node.tar.xz && \
    mv node-v22.23.4-linux-x64 /usr/local/node && \
    rm node.tar.xz && \
    # Upgrade the npm that comes with Node 22.
    PATH="/usr/local/node/bin:${PATH}" npm install -g npm@12.2.2 && \
    rm -rf /root/.npm
ENV PATH="/usr/local/node/bin:${PATH}"

# Support i386.
RUN dpkg --add-architecture i386
RUN apt update && apt install libc6:i386 -y

ENV CLOUDSDK_PYTHON=python3.11

RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | tee /usr/share/keyrings/cloud.google.asc >/dev/null && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.asc] https://packages.cloud.google.com/apt cloud-sdk main" \
    | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update -y && \
    apt-get install -y google-cloud-cli

# Common environment variables.
ENV USER=clusterfuzz
ENV INSTALL_DIRECTORY /mnt/scratch0
ENV BOT_TMPDIR $INSTALL_DIRECTORY/tmp
ENV ROOT_DIR $INSTALL_DIRECTORY/clusterfuzz
ENV UPDATE_WEB_TESTS True
ENV PYTHONPATH $INSTALL_DIRECTORY/clusterfuzz/src
ENV RUN_CMD "python3.11 $ROOT_DIR/src/python/bot/startup/run.py"

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
ENV BASE_OS_VERSION=ubuntu-24-04


COPY Pipfile Pipfile.lock setup_common.sh setup_clusterfuzz.sh start_clusterfuzz.sh setup_mock_metadata.sh start.sh /data/
RUN cd /data && \
    # Make pip3.11 the default so that pipenv install --system works.
    mv /usr/local/bin/pip3.11 /usr/local/bin/pip && \
    python3.11 -m pipenv install --deploy --system && \
    rm -rf /root/.cache/pipenv

CMD ["bash", "-ex", "/data/start.sh"]
