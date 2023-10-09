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
"""Constants that are meaningful to Centipede.
Should not have any dependencies.
Note that Centipede arguments take the form -flag=value. Thus any variables
defined in this function that end with the suffix "_FLAG" should contain
"-flag=". Any variable that ends with the suffix "_ARGUMENT" should contain
"-flag=value".
"""

FORK_SERVER_FLAGNAME = 'fork_server'
FORK_SERVER_DEFAULT = 1

RSS_LIMIT_MB_FLAGNAME = 'rss_limit_mb'
RSS_LIMIT_MB_DEFAULT = 4096

TIMEOUT_PER_INPUT_FLAGNAME = 'timeout_per_input'
TIMEOUT_PER_INPUT_DEFAULT = 25
TIMEOUT_PER_INPUT_REPR_DEFAULT = 60

ADDRESS_SPACE_LIMIT_FLAGNAME = 'address_space_limit_mb'
ADDRESS_SPACE_LIMIT_DEFAULT = 4096

DICTIONARY_FLAGNAME = 'dictionary'
WORKDIR_FLAGNAME = 'workdir'
CORPUS_DIR_FLAGNAME = 'corpus_dir'
BINARY_FLAGNAME = 'binary'
EXTRA_BINARIES_FLAGNAME = 'extra_binaries'
EXIT_ON_CRASH_FLAGNAME = 'exit_on_crash'

TIMEOUT_PER_INPUT_REPR = 60


def get_default_arguments():
  return {
      FORK_SERVER_FLAGNAME: FORK_SERVER_DEFAULT,
      RSS_LIMIT_MB_FLAGNAME: RSS_LIMIT_MB_DEFAULT,
      ADDRESS_SPACE_LIMIT_FLAGNAME: ADDRESS_SPACE_LIMIT_DEFAULT,
      TIMEOUT_PER_INPUT_FLAGNAME: TIMEOUT_PER_INPUT_DEFAULT,
      EXIT_ON_CRASH_FLAGNAME: 1,
  }
