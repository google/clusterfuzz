# Copyright 2020 Google LLC
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
"""Common constants for LKL."""

import re

LINUX_KERNEL_MODULE_STACK_TRACE = 'Linux Kernel Library Stack Trace:'

#hid-fuzzer: lib/posix-host.c:401: void panic(void): Assertion `0' failed.
LINUX_KERNEL_LIBRARY_ASSERT_REGEX = re.compile(
    r'([^:]+): lib/posix-host\.c:\d+: void panic\(void\): Assertion .*')

# Linux version 5.4.58+-ab6926695 where 6926695 is the build id.
# Unlike in a normal linux version string, we do not know the build hash.
LINUX_VERSION_REGEX_LKL = re.compile(r'Linux version .+-(ab([0-9a-f]+)\s)')

# This is the prefix in the repo.prop for the kernel for all
# lkl fuzzers.
LKL_REPO_KERNEL_PREFIX = 'kernel/private/lkl'
LKL_BUILD_TARGET = 'kernel_kasan.lkl_fuzzers'
