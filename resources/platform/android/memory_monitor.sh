#!/system/bin/sh
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

PROCESS_LIST=( /system/bin/mediaserver )
LOG_FILE=/data/local/tmp/kill_process.log
MEMORY_THRESHOLD=400000
SLEEP_INTERVAL=5

while true
do
  for i in "${PROCESS_LIST[@]}"
  do
    output=$(ps | /system/bin/grep $i)
    [ -z "$output" ] && continue
    array=($output)
    rss=${array[4]}
    if [ $rss -gt $MEMORY_THRESHOLD ]
    then
      kill -9 ${array[1]}
      echo "$(date) $i is using $rss KB memory. killing it." >> $LOG_FILE
    fi
  done
  sleep $SLEEP_INTERVAL
done

