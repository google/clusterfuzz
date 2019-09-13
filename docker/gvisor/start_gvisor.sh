#!/bin/bash -ex

gcloud auth activate-service-account --key-file=/credentials.json
gcloud config set project "$CLOUD_PROJECT_ID"

BOTO_CONFIG_PATH=$(/usr/bin/gsutil -D 2>&1 | grep "config_file_list" | egrep -o "/[^']+gserviceaccount\.com/\.boto") || true
if [[ -f "$BOTO_CONFIG_PATH" ]]; then
  export BOTO_CONFIG="$BOTO_CONFIG_PATH"
else
  echo "WARNING: failed to identify the Boto configuration file and specify BOTO_CONFIG env."

source /data/setup_common.sh
source /data/setup_clusterfuzz.sh

export DISPLAY=:1
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export PATH="$EXTRA_PATH:$PATH"
export TZ='America/Los_Angeles'

touch /mnt/scratch0/clusterfuzz/bot/logs/bot.log
tail -f /mnt/scratch0/clusterfuzz/bot/logs/bot.log &

$RUN_CMD
