#! /bin/bash
# Copyright 2019 Google Inc.
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
#
################################################################################

set -e
CC=${CC:-clang}
CXX=${CXX:-clang++}

# Make sure we don't clobber anything in the current directory.
rm -rf afl-build
git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus afl-build
cd afl-build

make source-only
ar ru FuzzingEngine.a afl-compiler-rt.o utils/aflpp_driver/aflpp_driver.o

cp -f FuzzingEngine.a afl-fuzz afl-showmap ../
echo "Success: link fuzz target against FuzzingEngine.a!"
