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

CLUSTERFUZZ_CONFIG_DIR=~/.config/clusterfuzz
ROOT_DIRECTORY=$(dirname $(readlink -f "$0"))

# Process command line arguments.
original_args="$*"
while [ "$1" != "" ]; do
  case $1 in
    -e)
      emulator_install_flag=--install-android-emulator
      ;;
    --emulator)
      emulator_install_flag=--install-android-emulator
      ;;
  esac
  shift
done

mkdir -p $CLUSTERFUZZ_CONFIG_DIR
if [ ! -d $ROOT_DIRECTORY/ENV ] || ([ $emulator_install_flag ] && [ ! -d $ROOT_DIRECTORY/local/bin/android-sdk ]); then
  echo "Running first time setup. This may take a while, but is only required once."
  echo "You may see several password prompts to install required packages."
  sleep 5
  $ROOT_DIRECTORY/local/install_deps.bash --only-reproduce $emulator_install_flag || { rm -rf $ROOT_DIRECTORY/ENV && exit 1; }
fi

source ENV/bin/activate
python $ROOT_DIRECTORY/butler.py reproduce $original_args
