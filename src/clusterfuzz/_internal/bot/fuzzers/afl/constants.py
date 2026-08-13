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
"""Constants that are meaningful to AFL++.
Should not have any dependancies.
"""

# AFL++ flags.
DICT_FLAG: str = '-x'

INPUT_FLAG: str = '-i'

MEMORY_LIMIT_FLAG: str = '-m'

OUTPUT_FLAG: str = '-o'

TIMEOUT_FLAG: str = '-t'

INSTANCE_ID_FLAG: str = '-S'

MOPT_FLAG: str = '-L'

CMPLOG_LEVEL_FLAG: str = '-l'

QUEUE_OLD_STRATEGY_FLAG: str = '-Z'

SCHEDULER_FLAG: str = '-p'

CMPLOG_FLAG: str = '-c'

FUZZING_TIMEOUT_FLAG: str = '-V'

MUTATION_STATE_FLAG: str = '-P'

INPUT_TYPE_FLAG: str = '-a'

# AFL MUTATION suboptions.
MUTATION_EXPLORE: str = 'explore'

MUTATION_EXPLOIT: str = 'exploit'

# AFL INPUT suboptions.
INPUT_ASCII: str = 'ascii'

INPUT_BINARY: str = 'binary'

# AFL CMPLOG suboptions.
CMPLOG_ARITH: str = 'A'

CMPLOG_TRANS: str = 'T'

CMPLOG_XTREME: str = 'X'

CMPLOG_RAND: str = 'R'

# AFL environment variables.
IGNORE_UNKNOWN_ENVS_ENV_VAR: str = 'AFL_IGNORE_UNKNOWN_ENVS'

SKIP_CRASHES_ENV_VAR: str = 'AFL_SKIP_CRASHES'

SKIP_CPUFREQ_ENV_VAR: str = 'AFL_SKIP_CPUFREQ'

BENCH_UNTIL_CRASH_ENV_VAR: str = 'AFL_BENCH_UNTIL_CRASH'

DONT_DEFER_ENV_VAR: str = 'AFL_DRIVER_DONT_DEFER'

IGNORE_SEED_PROBLEMS: str = 'AFL_IGNORE_SEED_PROBLEMS'

FAST_CAL_ENV_VAR: str = 'AFL_FAST_CAL'

FORKSRV_INIT_TMOUT_ENV_VAR: str = 'AFL_FORKSRV_INIT_TMOUT'

KEEP_TIMEOUTS_ENV_VAR: str = 'AFL_KEEP_TIMEOUTS'

NO_AFFINITY_ENV_VAR: str = 'AFL_NO_AFFINITY'

STDERR_FILENAME_ENV_VAR: str = 'AFL_DRIVER_STDERR_DUPLICATE_FILENAME'

CLOSE_FD_MASK_ENV_VAR: str = 'AFL_DRIVER_CLOSE_FD_MASK'

EXPAND_HAVOC_NOW_VAR: str = 'AFL_EXPAND_HAVOC_NOW'

DEBUG_VAR: str = 'AFL_DEBUG'

CMPLOG_ONLY_NEW_ENV_VAR: str = 'AFL_CMPLOG_ONLY_NEW'

DISABLE_TRIM_ENV_VAR: str = 'AFL_DISABLE_TRIM'

IGNORE_PROBLEMS_ENV_VAR: str = 'AFL_IGNORE_PROBLEMS'

IGNORE_TIMEOUTS_ENV_VAR: str = 'AFL_IGNORE_TIMEOUTS'

# Other settings.

MAX_FILE_BYTES: int = 2**20  # 1 MB

FORKSERVER_TIMEOUT: int = 60000  # milliseconds

# This should be as high as possible, otherwise AFL will restart the binary too
# often to be competitive with pure libFuzzer. 2147483647 is the maximum signed
# integer. afl_driver accepts one argument which it converts to a signed int
# using atoi hence this is the largest value we can pick.
MAX_PERSISTENT_EXECUTIONS: str = '2147483647'

# Resume is used by passing -i- to AFL. See https://goo.gl/rZi455
RESUME_INPUT: str = '-'

# Don't let afl set a memory limit. Otherwise we will not be able to use
# sanitizers.
MAX_MEMORY_LIMIT: str = 'none'

CORE_PATTERN_FILE_PATH: str = '/proc/sys/kernel/core_pattern'

DEFAULT_INSTANCE_ID: str = 'default'
