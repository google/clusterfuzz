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

TIMEOUT_FLAG = '-t'

INSTANCE_ID_FLAG = '-S'

MOPT_FLAG = '-L'

CMPLOG_LEVEL_FLAG = '-l'

QUEUE_OLD_STRATEGY_FLAG = '-Z'

SCHEDULER_FLAG = '-p'

CMPLOG_FLAG = '-c'

# AFL CMPLOG suboptions.
CMPLOG_ARITH = 'A'

CMPLOG_TRANS = 'T'

# AFL environment variables.
AFL_MAP_SIZE_ENV_VAR = 'AFL_MAP_SIZE'

IGNORE_UNKNOWN_ENVS_ENV_VAR = 'AFL_IGNORE_UNKNOWN_ENVS'

SKIP_CRASHES_ENV_VAR = 'AFL_SKIP_CRASHES'

SKIP_CPUFREQ_ENV_VAR = 'AFL_SKIP_CPUFREQ'

BENCH_UNTIL_CRASH_ENV_VAR = 'AFL_BENCH_UNTIL_CRASH'

DONT_DEFER_ENV_VAR = 'AFL_DRIVER_DONT_DEFER'

FAST_CAL_ENV_VAR = 'AFL_FAST_CAL'

FORKSRV_INIT_TMOUT_ENV_VAR = 'AFL_FORKSRV_INIT_TMOUT'

NO_AFFINITY_ENV_VAR = 'AFL_NO_AFFINITY'

STDERR_FILENAME_ENV_VAR = 'AFL_DRIVER_STDERR_DUPLICATE_FILENAME'

CLOSE_FD_MASK_ENV_VAR = 'AFL_DRIVER_CLOSE_FD_MASK'

EXPAND_HAVOC_NOW_VAR = 'AFL_EXPAND_HAVOC_NOW'

DEBUG_VAR = 'AFL_DEBUG'

CMPLOG_ONLY_NEW_ENV_VAR = 'AFL_CMPLOG_ONLY_NEW'

DISABLE_TRIM_ENV_VAR = 'AFL_DISABLE_TRIM'

EXPAND_HAVOC_ENV_VAR = 'AFL_EXPAND_HAVOC_NOW'

# Other settings.

MAX_FILE_BYTES = 2**20  # 1 MB

FORKSERVER_TIMEOUT = 60000  # milliseconds

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

DEFAULT_INSTANCE_ID = 'default'
