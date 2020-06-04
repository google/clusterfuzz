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

CRASH_DUMPS_DIR = '/sdcard/crash-reports'

DEVICE_DOWNLOAD_DIR = '/sdcard/Download'

DEVICE_TESTCASES_DIR = '/sdcard/fuzzer-testcases'

DEVICE_TMP_DIR = '/data/local/tmp'

# Directory to keep fuzzing artifacts for grey-box fuzzers e.g. corpus.
DEVICE_FUZZING_DIR = '/data/fuzz'

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
