#!/bin/bash
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

# Remove ClusterFuzz imports from PYTHONPATH to avoid conflicting
# dependencies.
unset PYTHONPATH

# Environment variables needed during building.
export NO_BREAKPAD=1
export G_SLICE=always-malloc
export NSS_DISABLE_ARENA_FREE_LIST=1
export NSS_DISABLE_UNLOAD=1
export ASAN_OPTIONS=alloc_dealloc_mismatch=0:detect_leaks=0:handle_segv=0:strict_memcmp=0:use_sigaltstack=0
export TSAN_OPTIONS=report_thread_leaks=0

# Parse arguments.
if [ "$#" -ne 3 ]; then
  echo "Usage: ./build_helper.sh <gn_args> <build_version> <build_name>"
  exit 1
fi
gn_args=$1
build_version=$2
build_name=$3

src_dir=$BUILD_DIR/chromium
build_subdir=out/$build_name
build_dir=$src_dir/src/$build_subdir
build_file=$BUILD_DIR/$build_name.zip
cpus=$((`getconf _NPROCESSORS_ONLN` / 2 + 1))

# Clear build files.
rm -rf $build_file $build_dir

# Create source directory if there is no src/ subfolder.
if [ ! -d "$src_dir/src" ]; then
  rm -rf $src_dir
  mkdir -p $src_dir

  # Fetch source.
  cd $src_dir
  fetch --nohooks chromium
fi

# Cleanup checkout state.
cd $src_dir/src
git checkout origin/master
git branch -D release
gclient revert -j$cpus
git clean -df

# Update to latest source.
git rebase-update
gclient sync --with_branch_heads --force -j$cpus
git fetch

# Get code for the release branch.
git fetch --tags
git checkout -b release $build_version
gclient sync --with_branch_heads --force -j$cpus

# Run runhooks and update clang.
python ./tools/clang/scripts/update.py
gclient runhooks --force

# Trigger the build.
gn gen $build_subdir "--args=$gn_args"
autoninja -C $build_subdir chromium_builder_asan

# Clear unneeded files from build directory.
unneeded_dirnames=( ".deps" ".landmines" ".ninja_deps" ".ninja_log"
                    ".sconsign.dblite" "appcache" "gen" "glue" "lib.host"
                    "mksnapshot" "obj" "obj.host" "obj.target" "src"
                    "thinlto-cache" )
for unneeded_dirname in ${unneeded_dirnames[@]}
do
  rm -rf $build_dir/$unneeded_dirname
done

# Store the build.
if [ -f $build_dir/chrome ]; then
  cd $build_dir/..
  zip -r $build_file $(basename $build_dir)
else
  # Don't do cleanup to save bad state.
  exit 1
fi

# Cleanup.
rm -rf $build_dir
rm -rf /tmp/*
