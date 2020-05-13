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
"""Constants that are meaningful to AFL.
Should not have any dependancies.
"""

# AFL flags.
DICT_FLAG = '-x'

INPUT_FLAG = '-i'

MEMORY_LIMIT_FLAG = '-m'

OUTPUT_FLAG = '-o'

SKIP_DETERMINISTIC_FLAG = '-d'

TIMEOUT_FLAG = '-t'

# AFL environment variables.
SKIP_CPUFREQ_ENV_VAR = 'AFL_SKIP_CPUFREQ'

BENCH_UNTIL_CRASH_ENV_VAR = 'AFL_BENCH_UNTIL_CRASH'

DONT_DEFER_ENV_VAR = 'AFL_DRIVER_DONT_DEFER'

FAST_CAL_ENV_VAR = 'AFL_FAST_CAL'

NO_AFFINITY_ENV_VAR = 'AFL_NO_AFFINITY'

STDERR_FILENAME_ENV_VAR = 'AFL_DRIVER_STDERR_DUPLICATE_FILENAME'

CLOSE_FD_MASK_ENV_VAR = 'AFL_DRIVER_CLOSE_FD_MASK'

MAX_FILE_BYTES = 2**20  # 1 MB

# This should be as high as possible, otherwise AFL will restart the binary too
# often to be competitive with pure libFuzzer. 2147483647 is the maximum signed
# integer. afl_driver accepts one argument which it converts to a signed int
# using atoi hence this is the largest value we can pick.
MAX_PERSISTENT_EXECUTIONS = '2147483647'

# Resume is used by passing -i- to AFL. See https://goo.gl/rZi455
RESUME_INPUT = '-'

# Don't let afl set a memory limit. Otherwise we will not be able to use
# sanitizers.
MAX_MEMORY_LIMIT = 'none'

CORE_PATTERN_FILE_PATH = '/proc/sys/kernel/core_pattern'
