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

import re

DEVICE_DOWNLOAD_DIR: str = '/sdcard/Download'

DEVICE_TESTCASES_DIR: str = '/sdcard/fuzzer-testcases'

DEVICE_TMP_DIR: str = '/data/local/tmp'

# Directory to keep fuzzing artifacts for grey-box fuzzers e.g. corpus.
DEVICE_FUZZING_DIR: str = '/data/fuzz'

DEVICE_MTE_DIR: str = '/system/lib64'
DEVICE_SANITIZER_DIR: str = '/system/lib64'

MTE_STACKTRACE_BEGIN: str = 'Build fingerprint:'
MTE_STACKTRACE_END: str = 'mte-reports'

TRUSTY_STACKTRACE_BEGIN: str = 'panic notifier - trusty version'
TRUSTY_STACKTRACE_END: str = 'Built:'

# The format of logcat when lowmemorykiller kills a process. See:
# https://android.googlesource.com/platform/system/core/+/master/lmkd/lmkd.c#586
LOW_MEMORY_REGEX: re.Pattern[str] = re.compile(
    r'Low on memory:|'
    r'lowmemorykiller: Killing|'
    r'to\s+free.*because\s+cache.*is\s+below\s+limit.*for\s+oom_', re.DOTALL)

# Various persistent cached values.
BUILD_PROP_MD5_KEY: str = 'android_build_prop_md5'
LAST_TEST_ACCOUNT_CHECK_KEY: str = 'android_last_test_account_check'
LAST_FLASH_BUILD_KEY: str = 'android_last_flash'
LAST_FLASH_TIME_KEY: str = 'android_last_flash_time'

PRODUCT_TO_KERNEL: dict[str, str] = {
    'blueline': 'bluecross',
    'crosshatch': 'bluecross',
    'flame': 'floral',
    'coral': 'floral',
    'walleye': 'wahoo',
    'muskie': 'wahoo',
    'taimen': 'wahoo',
}

RELEASE_CONFIGURATION: str = 'next'

AUTOMOTIVE_RELEASE_CONFIGURATION: str = 'trunk_staging'

AUTOMOTIVE_TARGET_LIST: list[str] = ['seahawk_hwasan']

NO_RELEASE_CONFIGURATION_TARGET_LIST: list[str] = [
    'shiba_fullmte', 'husky_fullmte', 'komodo_fullmte'
]

DEPRECATED_DEVICE_LIST: list[str] = [
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
DEVICES_WITH_NO_FALLBACK_QUEUE_LIST: list[str] = ['ANDROID:PIXEL6']
