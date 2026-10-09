#!/bin/bash -eu
# Copyright 2026 Google LLC
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
# Builds a coverage-guided fuzz target using silkeh/clang:18-bullseye.
#
# Usage:
#   ARCH=x86_64|arm64 ./build.sh <fuzzer_file>
#   Example: ./build.sh clean_fuzzer.cc

if [ "$#" -ne 1 ]; then
  echo "Usage: ARCH=x86_64|arm64 $0 <fuzzer_file>" >&2
  exit 1
fi

SRC_FILE="$(basename "$1")"
BINARY_NAME="${SRC_FILE%.*}"
FUZZER_DIR="${BINARY_NAME%_fuzzer}"
ARCH=${ARCH:-x86_64}
case "$ARCH" in
  x86_64) PLATFORM=linux/amd64 ;;
  arm64) PLATFORM=linux/arm64 ;;
  *) echo "Unknown ARCH=$ARCH, expected x86_64 or arm64." >&2; exit 1 ;;
esac

CLUSTERFUZZ_DIR="$(cd "$(dirname "$0")/../../../.." && pwd)"
FUZZER_REL_DIR="test_suites/data/fuzzer/coverage_guided/$FUZZER_DIR"

if [ ! -f "$CLUSTERFUZZ_DIR/$FUZZER_REL_DIR/$SRC_FILE" ]; then
  echo "Source file not found: $CLUSTERFUZZ_DIR/$FUZZER_REL_DIR/$SRC_FILE" >&2
  exit 1
fi

mkdir -p "$CLUSTERFUZZ_DIR/$FUZZER_REL_DIR/$ARCH"

# Why we use silkeh/clang:18-bullseye:
# - bullseye (Debian 11): Ships glibc 2.31, which matches ClusterFuzz's bot
#   environment (ubuntu:20.04, glibc 2.31). Building on a newer OS would link
#   against a newer glibc version and fail to run on ClusterFuzz bots.
# - clang:18: Older Clang versions (such as the default clang-10 on glibc 2.31
#   distros) have an AddressSanitizer bug that crashes on startup on newer
#   Linux hosts (glibc >= 2.34). Clang 18 fixes this so the compiled fuzzer
#   runs on both ClusterFuzz's glibc 2.31 bots and modern workstations.
docker run --rm --platform "$PLATFORM" \
  -u "$(id -u):$(id -g)" \
  -v "$CLUSTERFUZZ_DIR:/clusterfuzz" \
  -w "/clusterfuzz/$FUZZER_REL_DIR" \
  silkeh/clang:18-bullseye \
  clang++ -g -O1 -fno-omit-frame-pointer -fno-optimize-sibling-calls \
    -fsanitize=fuzzer,address "$SRC_FILE" -o "$ARCH/$BINARY_NAME"

echo "Built $FUZZER_REL_DIR/$ARCH/$BINARY_NAME"
