#!/bin/bash -ex
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

dir=$(dirname "$0")

# Delete third_party to prevent import issues while doing `python butler.py
# bootstrap`.
rm -rf "$dir"/../src/third_party

if [ "$(uname)" == "Darwin" ]; then
  "$dir"/install_deps_macos.bash $*
else
  "$dir"/install_deps_linux.bash $*
fi
