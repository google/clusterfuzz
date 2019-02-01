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

# Set up mock metadata server.
if [[ -n "$LOCAL_METADATA_SERVER" ]]; then
  ip addr add 169.254.169.254/32 dev lo
  socat TCP-LISTEN:80,fork,reuseaddr TCP:$LOCAL_METADATA_SERVER:$LOCAL_METADATA_PORT &
  echo "127.0.0.1 metadata metadata.google.internal" >> /etc/hosts
fi

# Create user with matching UID as host
export HOST_UID=${HOST_UID:-1337}
useradd -mU -G nopwsudo -u $HOST_UID $USER

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
rm /dev/random && ln -s /dev/urandom /dev/random

# Running without credentials will cause this to fail.
if [[ -z "$LOCAL_SRC" ]]; then
  service google-fluentd restart
fi

# Prevent anything from being written to downloads directory.
mkdir -p /home/$USER/Downloads
chmod 111 /home/$USER/Downloads

ulimit -n 65535
