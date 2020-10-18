#!/bin/bash
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

# Delete existing symlinks.
find clusterfuzz/ -type l | xargs rm

# Symlink dependencies.
ln -s $(pwd)/../base clusterfuzz/
ln -s $(pwd)/../bot clusterfuzz/
ln -s $(pwd)/../build_managerment clusterfuzz/
ln -s $(pwd)/../config clusterfuzz/
ln -s $(pwd)/../crash_analysis clusterfuzz/
ln -s $(pwd)/../datastore clusterfuzz/
ln -s $(pwd)/../fuzzer_utils clusterfuzz/
ln -s $(pwd)/../fuzzing clusterfuzz/
ln -s $(pwd)/../google_cloud_utils clusterfuzz/
ln -s $(pwd)/../lib clusterfuzz/
ln -s $(pwd)/../metrics clusterfuzz/
ln -s $(pwd)/../platforms clusterfuzz/
ln -s $(pwd)/../system clusterfuzz/
ln -s $(pwd)/../../protos clusterfuzz/

python setup.py sdist bdist_wheel
