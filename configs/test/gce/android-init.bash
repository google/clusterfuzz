#!/bin/bash -e
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

# Fill NFS server information if available.
NFS_CLUSTER_NAME=  # E.g. 10.0.0.2 is default for Cloud filestore.
NFS_VOLUME_NAME=   # Fill this based on NFS config.
NFS_DIR=/mnt/nfs

# Create clusterfuzz user (uid=1337).
USER=clusterfuzz
HOME=/home/$USER
useradd -mU -u 1337 $USER
usermod -aG kvm $USER
usermod -aG cvdnetwork $USER
echo "$USER ALL=NOPASSWD: ALL" >> /etc/sudoers

# Setup helper variables.
ANDROID_SERIAL=127.0.0.1:6520
CVD_DIR=$HOME  # To avoid custom params in launch_cvd for various image type locations.
DEPLOYMENT_BUCKET=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/deployment-bucket)
DEVICE_BRANCH=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/device-branch)
DEVICE_TARGET=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/device-target)
DEVICE_MEMORY_MB=$(curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/device-memory-mb)
GSUTIL_PATH="/usr/bin"
INSTALL_DIRECTORY=$HOME
ROOT_DIR="$INSTALL_DIRECTORY/clusterfuzz"
PYTHONPATH="$PYTHONPATH:$ROOT_DIR/src"

# Use nodesource nodejs packages.
curl -sL https://deb.nodesource.com/setup_11.x | sudo -E bash -

echo "Installing dependencies."
apt-get update && apt-get install -y \
  autofs \
  apt-transport-https \
  build-essential \
  curl \
  gdb \
  libcurl4-openssl-dev \
  libffi-dev \
  libssl-dev \
  locales \
  lsb-release \
  net-tools \
  nfs-common \
  nodejs \
  python \
  python-dbg \
  python-dev \
  python-pip \
  socat \
  sudo \
  unzip \
  util-linux \
  wget \
  zip

echo "Increasing default file limit."
ulimit -n 65536

echo "Fixing hugepages bug."
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

echo "Disabling hung task checking."
sysctl kernel.hung_task_timeout_secs=0

echo "Adding workaround to prevent /dev/random hangs."
rm /dev/random
ln -s /dev/urandom /dev/random

echo "Setting up google-fluentd."
curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
sudo bash install-logging-agent.sh
echo "
<source>
  type tcp
  format json
  port 5170
  bind 127.0.0.1
  tag bot
</source>
" > /etc/google-fluentd/config.d/clusterfuzz.conf
sed -i 's/flush_interval 5s/flush_interval 60s/' \
  /etc/google-fluentd/google-fluentd.conf
sudo service google-fluentd restart

echo "Installing ClusterFuzz package dependencies."
pip install crcmod==1.7 psutil==5.6.6 pyOpenSSL==19.0.0

if [ -z "$NFS_CLUSTER_NAME" ]; then
  NFS_ROOT=
else
  NFS_ROOT=$NFS_DIR/$NFS_VOLUME_NAME

  echo "Setting up NFS."
  mkdir -p $NFS_DIR
  sed -i "s/browse_mode = no/browse_mode = yes/" /etc/autofs.conf
  echo "$NFS_DIR   /etc/auto.nfs" >> /etc/auto.master
  service autofs stop
  echo "$NFS_VOLUME_NAME -intr,hard,rsize=65536,wsize=65536,mountproto=tcp,vers=3,noacl,noatime,nodiratime $NFS_CLUSTER_NAME:/$NFS_VOLUME_NAME" > /etc/auto.nfs
  service autofs start

  set +e  # Ignore errors in this block since NFS server can be flaky.
  ls $NFS_ROOT
  chown $USER:$USER $NFS_ROOT
  set -e
fi

echo "Changing user shell to clusterfuzz."
exec sudo -i -u clusterfuzz bash - << eof

echo "Creating directory $INSTALL_DIRECTORY."
mkdir -p "$INSTALL_DIRECTORY"
cd $INSTALL_DIRECTORY

echo "Downloading ClusterFuzz source code."
rm -rf $ROOT_DIR
$GSUTIL_PATH/gsutil cp gs://$DEPLOYMENT_BUCKET/linux.zip clusterfuzz-source.zip
unzip -q clusterfuzz-source.zip

echo "Setting up android."
mkdir -p $CVD_DIR
cd $CVD_DIR
fetch_artifacts.py -branch $DEVICE_BRANCH -build_target $DEVICE_TARGET
mkdir -p backup
cp *.img backup/
./bin/launch_cvd -daemon -memory_mb $DEVICE_MEMORY_MB

echo "Bringing up device in adb."
$ROOT_DIR/resources/platform/android/adb devices

echo "Running ClusterFuzz."
OS_OVERRIDE="ANDROID" \
  QUEUE_OVERRIDE="ANDROID_X86" \
  ANDROID_SERIAL="$ANDROID_SERIAL" \
  ROOT_DIR="$ROOT_DIR" \
  PYTHONPATH="$PYTHONPATH" \
  CVD_DIR="$CVD_DIR" \
  GSUTIL_PATH="$GSUTIL_PATH" \
  NFS_ROOT="$NFS_ROOT" \
  DEVICE_MEMORY_MB="$DEVICE_MEMORY_MB" \
  python $ROOT_DIR/src/python/bot/startup/run.py &

echo "Success!"
eof
