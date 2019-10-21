#!/bin/bash -ex
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

source /data/setup_mock_metadata.sh

# Create user with matching UID as host
if [[ "$USER" != "root" ]]
then
  export HOST_UID=${HOST_UID:-1337}
  useradd -mU -G nopwsudo -u $HOST_UID $USER
fi

mkdir -p $BOT_TMPDIR
chmod 777 $BOT_TMPDIR

export HOSTNAME=${HOSTNAME:-$(curl --header "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/hostname)}

# Setup PREEMPTIBLE flag based on hostname.
if [[ $HOSTNAME =~ "-pre-" ]]
then
  export PREEMPTIBLE=True
fi

# Make sure mounted volume doesn't have noexec,nosuid,nodev
mount /mnt/scratch0 -o remount,exec,suid,dev

# Prevent /dev/random hangs.
if [[ -z "$DISABLE_DEV_RANDOM_RENAME" ]] 
then
  rm /dev/random
  ln -s /dev/urandom /dev/random
fi

# Running without credentials will cause this to fail.
if [[ -z "$LOCAL_SRC" ]]; then
  /etc/init.d/google-fluentd restart
fi

# Prevent anything from being written to downloads directory.
mkdir -p /home/$USER/Downloads
chmod 111 /home/$USER/Downloads

ulimit -n 65535
