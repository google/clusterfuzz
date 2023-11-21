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
"""Constants that are meaningful to libFuzzer.
Should not have any dependencies.
Note that libFuzzers arguments take the form -flag=value. Thus any variables
defined in this function that end with the suffix "_FLAG" should contain
"-flag=". Any variable that ends with the suffix "_ARGUMENT" should contain
"-flag=value".
"""

# libFuzzer flags.
ARTIFACT_PREFIX_FLAG = '-artifact_prefix='
ARTIFACT_PREFIX_FLAGNAME = 'artifact_prefix'

DATA_FLOW_TRACE_FLAGNAME = 'data_flow_trace'

DICT_FLAGNAME = 'dict'

FOCUS_FUNCTION_FLAGNAME = 'focus_function'

FORK_FLAGNAME = 'fork'

MAX_LEN_FLAGNAME = 'max_len'

MAX_TOTAL_TIME_FLAGNAME = 'max_total_time'

RSS_LIMIT_FLAGNAME = 'rss_limit_mb'

RUNS_FLAGNAME = 'runs'

TIMEOUT_FLAGNAME = 'timeout'

EXACT_ARTIFACT_PATH_FLAGNAME = 'exact_artifact_path'

CLEANSE_CRASH_FLAGNAME = 'cleanse_crash'

MERGE_FLAGNAME = 'merge'

MERGE_CONTROL_FILE_FLAGNAME = 'merge_control_file'

MINIMIZE_CRASH_FLAGNAME = 'minimize_crash'

PRINT_FINAL_STATS_FLAGNAME = 'print_final_stats'

DETECT_LEAKS_FLAGNAME = 'detect_leaks'

TMP_ARTIFACT_PREFIX_ARGUMENT = '/tmp/'

VALUE_PROFILE_FLAGNAME = 'use_value_profile'

# Default value for rss_limit_mb flag to catch OOM.s
DEFAULT_RSS_LIMIT_MB = 2560

# Memory overhead we want to keep to ensure we're not going OOM.s
MEMORY_OVERHEAD = 1024  # 1 GB

# Default value for timeout flag to catch timeouts.
DEFAULT_TIMEOUT_LIMIT = 25

# Buffer for processing crash reports.
REPORT_PROCESSING_TIME = 5

# libFuzzer's exit code if a bug occurred in libFuzzer.
LIBFUZZER_ERROR_EXITCODE = 1

# Defines value of runs argument when loading a testcase.
RUNS_TO_REPRODUCE = 100

# libFuzzer's exit code if a bug was found in the target code.
TARGET_ERROR_EXITCODE = 77

NONCRASH_RETURN_CODES = {
    # Code when LibFuzzer exits due to SIGTERM cancellation (timeout exceeded).
    -15,
    0,
    # pylint: disable=line-too-long
    # Code when we interrupt libFuzzer (https://github.com/llvm/llvm-project/blob/1f161919065fbfa2b39b8f373553a64b89f826f8/compiler-rt/lib/fuzzer/FuzzerOptions.h#L25)
    72,
}
