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

source /data/setup_gcloud.sh
source /data/setup_common.sh
source /data/setup_clusterfuzz.sh

export DISPLAY=:1
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export PATH="$EXTRA_PATH:$PATH"
export TZ='America/Los_Angeles'

touch $INSTALL_DIRECTORY/clusterfuzz/bot/logs/bot.log
tail -f $INSTALL_DIRECTORY/clusterfuzz/bot/logs/bot.log &

$RUN_CMD
