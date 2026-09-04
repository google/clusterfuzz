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
"""Common constants."""

from enum import IntEnum
import re

DEVICE_DOWNLOAD_DIR = '/sdcard/Download'

DEVICE_TESTCASES_DIR = '/sdcard/fuzzer-testcases'

DEVICE_TMP_DIR = '/data/local/tmp'

# Directory to keep fuzzing artifacts for grey-box fuzzers e.g. corpus.
DEVICE_FUZZING_DIR = '/data/fuzz'

DEVICE_MTE_DIR = '/system/lib64'
DEVICE_SANITIZER_DIR = '/system/lib64'

MTE_STACKTRACE_BEGIN = 'Build fingerprint:'
MTE_STACKTRACE_END = 'mte-reports'

TRUSTY_STACKTRACE_BEGIN = 'panic notifier - trusty version'
TRUSTY_STACKTRACE_END = 'Built:'

# The format of logcat when lowmemorykiller kills a process. See:
# https://android.googlesource.com/platform/system/core/+/master/lmkd/lmkd.c#586
LOW_MEMORY_REGEX = re.compile(
    r'Low on memory:|'
    r'lowmemorykiller: Killing|'
    r'to\s+free.*because\s+cache.*is\s+below\s+limit.*for\s+oom_', re.DOTALL)

# Various persistent cached values.
BUILD_PROP_MD5_KEY = 'android_build_prop_md5'
LAST_TEST_ACCOUNT_CHECK_KEY = 'android_last_test_account_check'
LAST_FLASH_BUILD_KEY = 'android_last_flash'
LAST_FLASH_TIME_KEY = 'android_last_flash_time'

PRODUCT_TO_KERNEL = {
    'blueline': 'bluecross',
    'crosshatch': 'bluecross',
    'flame': 'floral',
    'coral': 'floral',
    'walleye': 'wahoo',
    'muskie': 'wahoo',
    'taimen': 'wahoo',
}

RELEASE_CONFIGURATION = 'next'

AUTOMOTIVE_RELEASE_CONFIGURATION = 'trunk_staging'

AUTOMOTIVE_TARGET_LIST = ['seahawk_hwasan']

NO_RELEASE_CONFIGURATION_TARGET_LIST = [
    'shiba_fullmte', 'husky_fullmte', 'komodo_fullmte'
]

DEPRECATED_DEVICE_LIST = [
    'sailfish',  # Pixel
    'marlin',  # Pixel XL
    'walleye',  # Pixel 2
    'taimen',  # Pixel 2 XL
    'blueline',  # Pixel 3
    'crosshatch',  # Pixel 3 XL
    'sargo',  # Pixel 3a
    'bonito',  # Pixel 3a XL
    'flame',  # Pixel 4
    'coral',  # Pixel 4 XL
    'sunfish',  # Pixel 4a
    'bramble',  # Pixel 4a 5G
    'redfin',  # Pixel 5
    'barbet',  # Pixel 5a
]

# Restrict pixel6 from picking up generic Android jobs to avoid
# Binary Mismatch: Hence, 'ANDROID:PIXEL6' is added to the list.
DEVICES_WITH_NO_FALLBACK_QUEUE_LIST = ['ANDROID:PIXEL6']


class ExitReason(IntEnum):
  """Android process exit reasons from ApplicationExitInfo. Taken from
  https://developer.android.com/reference/android/app/ApplicationExitInfo
  """

  EXIT_SELF = 1
  SIGNALED = 2
  LOW_MEMORY = 3
  CRASH = 4
  CRASH_NATIVE = 5
  ANR = 6
  INITIALIZATION_FAILURE = 7
  PERMISSION_CHANGE = 8
  EXCESSIVE_RESOURCE_USAGE = 9
  USER_REQUESTED = 10
  USER_STOPPED = 11
  DEPENDENCY_DIED = 12
  OTHER_KILLS_BY_SYSTEM = 13
  FREEZER = 14
  PACKAGE_STATE_CHANGE = 15
  PACKAGE_UPDATED = 16
  REASON_MEMORY_LIMITER = 17
  REASON_ANOMALY = 18


class ExitStatus(IntEnum):
  """Process exit signal statuses. Taken from:
  https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/core/java/android/os/Process.java?q=content:SIGNAL_KILL
  """

  SIGILL = 4
  SIGABRT = 6
  SIGKILL = 9
  SIGSEGV = 11
