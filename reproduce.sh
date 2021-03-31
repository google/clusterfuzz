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

# If we're using the emulator, make sure we install the Android SDK.
original_args="$*"
while [ "$1" != "" ]; do
  case $1 in
    -e)
      additional_deps_args=--install-android-emulator
      ;;
    --emulator)
      additional_deps_args=--install-android-emulator
      ;;
  esac
  shift
done

# Later checks will set this to false if dependencies are missing.
dependencies_installed="true"

# Create the config directory if needed and check the ClusterFuzz version.
mkdir -p $CLUSTERFUZZ_CONFIG_DIR
current_version=4
version_file=$CLUSTERFUZZ_CONFIG_DIR/version
if [ ! -e $version_file ] || [ "$(cat $version_file)" != "$current_version" ]; then
  dependencies_installed="false"
fi

# Check if we have a valid pipenv.
if ! which pipenv > /dev/null || ! pipenv graph 2>&1 > /dev/null; then
  dependencies_installed="false"
fi

# Check to see if we need to install the android emulator.
if [ $additional_deps_args ] && [ ! -d $ROOT_DIRECTORY/local/bin/android-sdk ]; then
  dependencies_installed="false"
fi

if [ "$dependencies_installed" != "true" ]; then
  echo "Running first time setup. This may take a while, but is only required once."
  echo "You may see several password prompts to install required packages."
  sleep 5
  $ROOT_DIRECTORY/local/install_deps.bash --only-reproduce $additional_deps_args || { exit 1; }
  echo -n $current_version > $version_file
fi

# Need to get python to use pipenv.
if [ -z "$PYTHON" ]; then
  if which python3.8 > /dev/null; then
    PYTHON='python3.8'
  elif which python3.7 > /dev/null; then
    PYTHON='python3.7'
  else
    PYTHON='python3'
  fi
fi

if ! which "$PYTHON" > /dev/null; then
  echo "python $PYTHON not found"
  exit 1
fi

version=$($PYTHON --version 2>&1 | cut -f2 -d' ')
if [[ "$version" < "3.7" || ! "$version" < "3.9" ]]; then
  echo "You need Python 3.8 or 3.7. Try \`export PYTHON=python3.8\` (or 3.7)."
  exit 1
fi

# Only sync if necessary.
pip_sync_file=$CLUSTERFUZZ_CONFIG_DIR/pip_sync
if [ ! -e $pip_sync_file ] || [ $ROOT_DIRECTORY/Pipfile.lock -nt $pip_sync_file ]; then
  $PYTHON -m pipenv sync --dev
  echo 1 > $pip_sync_file
fi

source "$($PYTHON -m pipenv --venv)/bin/activate"
python $ROOT_DIRECTORY/butler.py reproduce $original_args
