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

if [[ -z "$USE_LOCAL_DIR_FOR_NFS" ]]; then
  # rpcbind is necessary for NFS mount.
  mkdir -p /run/sendsigs.omit.d
  service rpcbind start

  service autofs stop
  echo "$NFS_VOLUME_NAME -intr,hard,rsize=65536,wsize=65536,mountproto=tcp,vers=3,noacl,noatime,nodiratime $NFS_CLUSTER_NAME:/$NFS_VOLUME_NAME" > /etc/auto.nfs
  service autofs start

  # Change ownership of mount from root to $USER.
  ls $NFS_DIR/$NFS_VOLUME_NAME
  chown $USER:$USER $NFS_DIR/$NFS_VOLUME_NAME
else
  mkdir -p $NFS_DIR/$NFS_VOLUME_NAME
  chown -R $USER:$USER $NFS_DIR/$NFS_VOLUME_NAME
fi

# For backwards compatibility with old testcases.
ln -s $NFS_DIR /mnt/glusterfs
