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
"""Google issue tracker."""

# pylint: disable=line-too-long
from clusterfuzz._internal.issue_management.google_issue_tracker.issue_tracker import \
    IssueTracker


def get_issue_tracker(project, config, issue_tracker_client=None):
  """Gets an IssueTracker for the project."""
  return IssueTracker(project, issue_tracker_client, config)
