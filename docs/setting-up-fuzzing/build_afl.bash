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
mkdir -p afl-build
cd afl-build

# Download AFL from Github Google/AFL repo
declare -a afl_sources=(
  "afl-fuzz.c"
  "afl-showmap.c"
  "android-ashmem.h"
  "config.h"
  "types.h"
  "debug.h"
  "alloc-inl.h"
  "hash.h"
  "Makefile"
)
for source_file in "${afl_sources[@]}"
do
  curl -O "https://raw.githubusercontent.com/google/AFL/master/$source_file"
done
make afl-fuzz afl-showmap

# Build AFL runtime sources needed to link against the fuzz target.
mkdir -p llvm_mode
curl "https://raw.githubusercontent.com/google/AFL/master/llvm_mode/afl-llvm-rt.o.c" > "llvm_mode/afl-llvm-rt.o.c"
$CC -c llvm_mode/afl-llvm-rt.o.c -Wno-pointer-sign -O3
curl -O "https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/lib/fuzzer/afl/afl_driver.cpp"
$CXX -c afl_driver.cpp -fsanitize=address -O3
ar r FuzzingEngine.a afl-llvm-rt.o.o afl_driver.o

mv FuzzingEngine.a afl-fuzz afl-showmap ../
echo "Success: link fuzz target against FuzzingEngine.a!"
