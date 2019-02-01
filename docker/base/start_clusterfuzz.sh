#!/bin/bash -ex
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

export DISPLAY=:1
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export PATH="$EXTRA_PATH:$PATH"
export TZ='America/Los_Angeles'

# PATH, PYTHONPATH and LD_* are removed by sudo even with -E,
# so we pass them explicitly.
sudo -E -H -u $USER bash -c "PATH='$PATH' PYTHONPATH='$PYTHONPATH' LD_LIBRARY_PATH='$LD_LIBRARY_PATH' $RUN_CMD"
