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
ARTIFACT_PREFIX_FLAG: str = '-artifact_prefix='
ARTIFACT_PREFIX_FLAGNAME: str = 'artifact_prefix'

DATA_FLOW_TRACE_FLAGNAME: str = 'data_flow_trace'

DICT_FLAGNAME: str = 'dict'

FOCUS_FUNCTION_FLAGNAME: str = 'focus_function'

FORK_FLAGNAME: str = 'fork'

MAX_LEN_FLAGNAME: str = 'max_len'

MAX_TOTAL_TIME_FLAGNAME: str = 'max_total_time'

RSS_LIMIT_FLAGNAME: str = 'rss_limit_mb'

RUNS_FLAGNAME: str = 'runs'

TIMEOUT_FLAGNAME: str = 'timeout'

EXACT_ARTIFACT_PATH_FLAGNAME: str = 'exact_artifact_path'

CLEANSE_CRASH_FLAGNAME: str = 'cleanse_crash'

MERGE_FLAGNAME: str = 'merge'

MERGE_CONTROL_FILE_FLAGNAME: str = 'merge_control_file'

MINIMIZE_CRASH_FLAGNAME: str = 'minimize_crash'

PRINT_FINAL_STATS_FLAGNAME: str = 'print_final_stats'

DETECT_LEAKS_FLAGNAME: str = 'detect_leaks'

TMP_ARTIFACT_PREFIX_ARGUMENT: str = '/tmp/'

VALUE_PROFILE_FLAGNAME: str = 'use_value_profile'

# Default value for rss_limit_mb flag to catch OOM.s
DEFAULT_RSS_LIMIT_MB: int = 2560

# Memory overhead we want to keep to ensure we're not going OOM.s
MEMORY_OVERHEAD: int = 1024  # 1 GB

# Default value for timeout flag to catch timeouts.
DEFAULT_TIMEOUT_LIMIT: int = 25

# Buffer for processing crash reports.
REPORT_PROCESSING_TIME: int = 5

# libFuzzer's exit code if a bug occurred in libFuzzer.
LIBFUZZER_ERROR_EXITCODE: int = 1

# Defines value of runs argument when loading a testcase.
RUNS_TO_REPRODUCE: int = 100

# libFuzzer's exit code if a bug was found in the target code.
TARGET_ERROR_EXITCODE: int = 77

NONCRASH_RETURN_CODES: set[int] = {
    # Code when LibFuzzer exits due to SIGTERM cancellation (timeout exceeded).
    -15,
    0,
    # pylint: disable=line-too-long
    # Code when we interrupt libFuzzer (https://github.com/llvm/llvm-project/blob/1f161919065fbfa2b39b8f373553a64b89f826f8/compiler-rt/lib/fuzzer/FuzzerOptions.h#L25)
    72,
}
