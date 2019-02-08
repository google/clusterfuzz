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
"""Lint changed code in current branch."""

import os
import sys

from local.butler import common


def execute(_):
  """Lint changed code."""
  if "GOOGLE_CLOUDBUILD" in os.environ:
    # Explicitly compare against master if we're running on the CI
    _, output = common.execute('git diff --name-only master FETCH_HEAD')
  else:
    _, output = common.execute('git diff --name-only FETCH_HEAD')

  py_changed_file_paths = [
      f for f in output.splitlines() if f.endswith('.py') and
      # Exclude auto-generated files.
      not f.endswith('_pb2.py') and not f.endswith('_pb2_grpc.py')
  ]
  go_changed_file_paths = [f for f in output.splitlines() if f.endswith('.go')]

  for file_path in py_changed_file_paths:
    if os.path.exists(file_path):
      common.execute('pylint ' + file_path)
      common.execute('yapf -d ' + file_path)

  golint_path = os.path.join('local', 'bin', 'golint')
  for file_path in go_changed_file_paths:
    if os.path.exists(file_path):
      common.execute(golint_path + ' ' + file_path)

      _, output = common.execute('gofmt -d ' + file_path)
      if output.strip():
        sys.exit(1)
