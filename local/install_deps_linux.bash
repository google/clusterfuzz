#!/bin/bash -ex
#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Check for lsb_release command in $PATH
if ! which lsb_release > /dev/null; then
  echo "ERROR: lsb_release not found in \$PATH" >&2
  exit 1;
fi

# Check if the distro is supported.
distro_codename=$(lsb_release --codename --short)
distro_id=$(lsb_release --id --short)
supported_codenames="(trusty|xenial|artful|bionic|cosmic)"
supported_ids="(Debian)"
if [[ ! $distro_codename =~ $supported_codenames &&
      ! $distro_id =~ $supported_ids ]]; then
  echo -e "ERROR: The only supported distros are\n" \
    "\tUbuntu 14.04 LTS (trusty)\n" \
    "\tUbuntu 16.04 LTS (xenial)\n" \
    "\tUbuntu 17.10 (artful)\n" \
    "\tUbuntu 18.04 LTS (bionic)\n" \
    "\tUbuntu 18.10 LTS (cosmic)\n" \
    "\tDebian 8 (jessie) or later" >&2
  exit 1
fi

# Check if the architecture is supported.
if ! uname -m | egrep -q "i686|x86_64"; then
  echo "Only x86 architectures are currently supported" >&2
  exit
fi

# Prerequisite for add-apt-repository.
sudo apt-get install -y apt-transport-https software-properties-common

# Add needed apt-get repos. Not needed on Goobuntu (rodete).
if [ "$distro_codename" != "rodete" ]; then
  curl -fsSL https://download.docker.com/linux/${distro_id,,}/gpg | \
     sudo apt-key add -
  sudo add-apt-repository -y \
     "deb [arch=amd64] https://download.docker.com/linux/${distro_id,,} \
     $(lsb_release -cs) \
     stable"

  echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" \
      | sudo tee /etc/apt/sources.list.d/bazel.list
  curl https://bazel.build/bazel-release.pub.gpg | sudo apt-key add -

  export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
  echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | \
      sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
      sudo apt-key add -

fi

# Set java_package so we know which to install.
if [ "$distro_codename" == "trusty" ]; then
  sudo add-apt-repository -y ppa:webupd8team/java
  java_package=oracle-java8-installer
else
  java_package=openjdk-8-jdk
fi

# Install apt-get packages.
sudo apt-get update
sudo apt-get install -y \
    bazel \
    docker-ce \
    google-cloud-sdk \
    $java_package    \
    liblzma-dev \
    python-dev \
    python-pip \
    python-virtualenv \
    unzip \
    xvfb

# Install patchelf - latest version not available on some older distros so we
# compile from source.
# Needed for MemorySanitizer to patch instrumented system libraries into the
# target binary (using RPATH).
unsupported_codenames="(trusty|xenial|jessie)"
if [[ $distro_codename =~ $unsupported_codenames ]]; then
    (cd /tmp && \
        curl -sS https://nixos.org/releases/patchelf/patchelf-0.9/patchelf-0.9.tar.bz2 \
        | tar -C /tmp -xj && \
        cd /tmp/patchelf-*/ && \
        ./configure && \
        sudo make install && \
        sudo rm -rf /tmp/patchelf-*)
else
    sudo apt-get install -y patchelf
fi

# Setup virtualenv.
rm -rf ENV
virtualenv ENV
source ENV/bin/activate

# Install needed python packages.
pip install --upgrade pip
pip install --upgrade -r docker/ci/requirements.txt
pip install --upgrade -r src/local/requirements.txt

# Install other dependencies (e.g. bower).
nodeenv -p --prebuilt
npm install -g bower polymer-bundler
bower install

# Install gcloud dependencies.
if gcloud components install --quiet beta; then
  gcloud components install --quiet \
      app-engine-go \
      app-engine-python \
      app-engine-python-extras \
      beta \
      cloud-datastore-emulator \
      pubsub-emulator
else
  # Either Cloud SDK component manager is disabled (default on GCE), or google-cloud-sdk package is
  # installed via apt-get.
  sudo apt-get install -y \
      google-cloud-sdk-app-engine-go \
      google-cloud-sdk-app-engine-python \
      google-cloud-sdk-app-engine-python-extras \
      google-cloud-sdk \
      google-cloud-sdk-datastore-emulator \
      google-cloud-sdk-pubsub-emulator
fi

# Bootstrap code structure.
python butler.py bootstrap

set +x
echo "

Installation succeeded!
Please load virtualenv environment by running 'source ENV/bin/activate'.

"
