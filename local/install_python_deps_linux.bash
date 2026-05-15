#!/bin/bash -ex
#
# Copyright 2023 Google LLC
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

# Setup pipenv and install python dependencies.
echo If this fails, you may need to build older Python from source
if $PYTHON -m pipenv --venv > /dev/null 2>&1; then
  # Remove existing pipenv virtual environment.
  $PYTHON -m pipenv --rm
fi

$PYTHON -m pipenv --python $PYTHON
$PYTHON -m pipenv sync --dev
source "$(${PYTHON} -m pipenv --venv)/bin/activate"

if [ $install_android_emulator ]; then
  ANDROID_SDK_INSTALL_DIR=local/bin/android-sdk
  ANDROID_SDK_REVISION=11076708
  ANDROID_VERSION=34
  ANDROID_TOOLS_BIN=$ANDROID_SDK_INSTALL_DIR/cmdline-tools/latest/bin/

  # Install the Android emulator and its dependencies. Used in tests and as an
  # option during Android test case reproduction.
  rm -rf $ANDROID_SDK_INSTALL_DIR
  mkdir -p $ANDROID_SDK_INSTALL_DIR
  curl https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_SDK_REVISION}_latest.zip \
      --output $ANDROID_SDK_INSTALL_DIR/cmdline-tools.zip
  unzip -d $ANDROID_SDK_INSTALL_DIR $ANDROID_SDK_INSTALL_DIR/cmdline-tools.zip
  
  # The new cmdline-tools expects to be in a directory named 'latest' or 'version'
  # to find its own root.
  mv $ANDROID_SDK_INSTALL_DIR/cmdline-tools $ANDROID_SDK_INSTALL_DIR/temp
  mkdir -p $ANDROID_SDK_INSTALL_DIR/cmdline-tools/latest
  mv $ANDROID_SDK_INSTALL_DIR/temp/* $ANDROID_SDK_INSTALL_DIR/cmdline-tools/latest/
  rm -rf $ANDROID_SDK_INSTALL_DIR/temp

  yes | $ANDROID_TOOLS_BIN/sdkmanager --licenses
  $ANDROID_TOOLS_BIN/sdkmanager "emulator"
  $ANDROID_TOOLS_BIN/sdkmanager "platform-tools" "platforms;android-$ANDROID_VERSION" "build-tools;$ANDROID_VERSION.0.0"
  $ANDROID_TOOLS_BIN/sdkmanager "system-images;android-$ANDROID_VERSION;google_apis;x86_64"
  $ANDROID_TOOLS_BIN/avdmanager create avd --force -n TestImage -k "system-images;android-$ANDROID_VERSION;google_apis;x86_64"
fi

# Install other dependencies (e.g. bower).
nodeenv -p --prebuilt
# Unsafe perm flag allows bower and polymer-bundler install for root users as well.
npm install --unsafe-perm -g bower polymer-bundler
bower --allow-root install

# Run the full bootstrap script to prepare for ClusterFuzz development.
python butler.py bootstrap

set +x
echo "

Installation succeeded!
Please load environment by running "$PYTHON -m pipenv shell".

"
