# Copyright 2018 Google LLC
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
"""Format changed go code in current branch."""

import os

from local.butler import common


def execute(_):
  """Format changed code using yapf."""
  _, output = common.execute('git diff --name-only origin...')

  go_changed_file_paths = [f for f in output.splitlines() if f.endswith('.go')]
  if not go_changed_file_paths:
    print 'No changed files found, nothing to format.'
    return

  for file_path in go_changed_file_paths:
    if os.path.exists(file_path):
      common.execute('gofmt -w %s' % file_path)
