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

# Process command line arguments.
while [ "$1" != "" ]; do
  case $1 in
    --install-android-emulator)
      install_android_emulator=1
      ;;
  esac
  shift
done

if [ -z "$PYTHON" ]; then
   if which python3.11 > /dev/null; then
    export PYTHON='python3.11'
  elif which python3.10 > /dev/null; then
    export PYTHON='python3.10'
  elif which python3.9 > /dev/null; then
    export PYTHON='python3.9'
  else
    export PYTHON='python3'
  fi
fi

if ! which "$PYTHON" > /dev/null; then
  echo "python $PYTHON not found"
  exit 1
fi

version=$($PYTHON --version 2>&1 | cut -f2 -d' ')

# Check for lsb_release command in $PATH.
if ! which lsb_release > /dev/null; then
  echo "ERROR: lsb_release not found in \$PATH" >&2
  exit 1;
fi

# Check if the distro is supported.
distro_codename=$(lsb_release --codename --short)
distro_id=$(lsb_release --id --short)
supported_codenames="(xenial|artful|bionic|cosmic|focal)"
supported_ids="(Debian)"
if [[ ! $distro_codename =~ $supported_codenames &&
      ! $distro_id =~ $supported_ids ]]; then
  echo -e "ERROR: The only supported distros are\n" \
    "\tUbuntu 16.04 LTS (xenial)\n" \
    "\tUbuntu 17.10 (artful)\n" \
    "\tUbuntu 18.04 LTS (bionic)\n" \
    "\tUbuntu 18.10 LTS (cosmic)\n" \
    "\tUbuntu 20.04 LTS (focal)\n" \
    "\tDebian 8 (jessie) or later" >&2
  exit 1
fi

# Check if the architecture is supported.
if ! uname -m | egrep -q "i686|x86_64"; then
  echo "Only x86 architectures are currently supported" >&2
  exit
fi

# Install packages that we depend on.
sudo apt-get update
sudo apt-get install -y \
    blackbox \
    curl \
    libpython3-all-dev \
    python3-pip \
    unzip \
    xvfb

# Prerequisite for add-apt-repository.
sudo apt-get install -y apt-transport-https software-properties-common

if [ "$distro_codename" == "rodete" ]; then
  glogin
  sudo glinux-add-repo docker-ce-"$distro_codename"
else
  curl -fsSL https://download.docker.com/linux/${distro_id,,}/gpg | \
      sudo apt-key add -
  sudo add-apt-repository -y \
      "deb [arch=amd64] https://download.docker.com/linux/${distro_id,,} \
      $distro_codename \
      stable"

  export CLOUD_SDK_REPO="cloud-sdk"
  export APT_FILE=/etc/apt/sources.list.d/google-cloud-sdk.list
  export APT_LINE="deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main"
  sudo bash -c "grep -x \"$APT_LINE\" $APT_FILE || (echo $APT_LINE | tee -a $APT_FILE)"

  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
      sudo apt-key add -

fi

# Install apt-get packages.
sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    google-cloud-sdk \
    openjdk-11-jdk \
    liblzma-dev \
    pipenv

# Install patchelf - latest version not available on some older distros so we
# compile from source.
# Needed for MemorySanitizer to patch instrumented system libraries into the
# target binary (using RPATH).
unsupported_codenames="(xenial|jessie)"
if [[ $distro_codename =~ $unsupported_codenames ]]; then
    (cd /tmp && \
        curl -sS https://releases.nixos.org/patchelf/patchelf-0.9/patchelf-0.9.tar.bz2 \
        | tar -C /tmp -xj && \
        cd /tmp/patchelf-*/ && \
        ./configure && \
        sudo make install && \
        sudo rm -rf /tmp/patchelf-*)
else
    sudo apt-get install -y patchelf
fi

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

dir=$(dirname "$0")
"$dir"/install_python_deps_linux.bash $*
