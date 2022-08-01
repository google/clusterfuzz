#!/bin/bash -e
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

if [ $# -eq 0 ]; then
    echo "No arguments provided. Usage: <image path> [optional arguments to 'docker run']"
fi

IMAGE=$1
shift

echo "Running docker image $IMAGE..."

set +x
docker_ip=$(ip -4 addr show docker0 | grep -P inet | head -1 | awk '{print $2}' | cut -d/ -f1)

if [[ -z $LOCAL_SRC ]]; then
  MOUNT_ARGS=""
  CONFIG_DIR_OVERRIDE=""
else
  if [[ -z $CONFIG_DIR_OVERRIDE ]]; then
    echo "CONFIG_DIR_OVERRIDE must be set."
    exit 1
  fi

  SRC_LOCATION=$(dirname $(dirname $(realpath ${BASH_SOURCE[0]})))
  MOUNT_ARGS="-v $SRC_LOCATION:/mnt/scratch0/clusterfuzz -v $(readlink -f $CONFIG_DIR_OVERRIDE):/config "
  CONFIG_DIR_OVERRIDE="/config"
fi

sudo docker run -e COMMAND_OVERRIDE="$COMMAND_OVERRIDE" -e SETUP_NFS= -e HOST_UID=$UID \
              -e LOCAL_METADATA_SERVER=$docker_ip -e LOCAL_METADATA_PORT=8080 \
              -e USE_LOCAL_DIR_FOR_NFS=1 $MOUNT_ARGS \
              -e LOCAL_SRC=$LOCAL_SRC \
              -e CONFIG_DIR_OVERRIDE=$CONFIG_DIR_OVERRIDE \
              --hostname test-bot-$USER \
              -p 7123:7123 \
              -ti --privileged --cap-add=all $IMAGE "$@"
