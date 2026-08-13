# Copyright 2023 Google LLC
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
"""Constants that are meaningful to Centipede.
Should not have any dependencies.
Note that Centipede arguments take the form -flag=value. Thus any variables
defined in this function that end with the suffix "_FLAG" should contain
"-flag=". Any variable that ends with the suffix "_ARGUMENT" should contain
"-flag=value".
"""

FORK_SERVER_FLAGNAME: str = 'fork_server'
FORK_SERVER_DEFAULT: int = 1

RSS_LIMIT_MB_FLAGNAME: str = 'rss_limit_mb'
RSS_LIMIT_MB_DEFAULT: int = 4096

TIMEOUT_PER_INPUT_FLAGNAME: str = 'timeout_per_input'
TIMEOUT_PER_INPUT_DEFAULT: int = 25
TIMEOUT_PER_INPUT_REPR_DEFAULT: int = 60

ADDRESS_SPACE_LIMIT_FLAGNAME: str = 'address_space_limit_mb'
ADDRESS_SPACE_LIMIT_DEFAULT: int = 4096

DICTIONARY_FLAGNAME: str = 'dictionary'
WORKDIR_FLAGNAME: str = 'workdir'
CORPUS_DIR_FLAGNAME: str = 'corpus_dir'
BINARY_FLAGNAME: str = 'binary'
EXTRA_BINARIES_FLAGNAME: str = 'extra_binaries'
EXIT_ON_CRASH_FLAGNAME: str = 'exit_on_crash'

MAX_LEN_FLAGNAME: str = 'max_len'
NUM_RUNS_FLAGNAME: str = 'num_runs'
BATCH_SIZE_FLAGNAME: str = 'batch_size'
STOP_AFTER_FLAGNAME: str = 'stop_after'

SYMBOLIZER_PATH_FLAGNAME: str = 'symbolizer_path'
SYMBOLIZER_PATH_DEFAULT: str = '/dev/null'

NUM_RUNS_PER_MINIMIZATION: int = 100000


def get_default_arguments() -> dict[str, int | str]:
  return {
      FORK_SERVER_FLAGNAME: FORK_SERVER_DEFAULT,
      RSS_LIMIT_MB_FLAGNAME: RSS_LIMIT_MB_DEFAULT,
      ADDRESS_SPACE_LIMIT_FLAGNAME: ADDRESS_SPACE_LIMIT_DEFAULT,
      TIMEOUT_PER_INPUT_FLAGNAME: TIMEOUT_PER_INPUT_DEFAULT,
      EXIT_ON_CRASH_FLAGNAME: 1,
      SYMBOLIZER_PATH_FLAGNAME: SYMBOLIZER_PATH_DEFAULT,
  }
