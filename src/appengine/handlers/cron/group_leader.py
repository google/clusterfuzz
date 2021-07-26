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
"""The module chooses the leader given a group of testcases. It needs to be here
  because it is used by group_task.py and attribute_builder.py."""

import itertools

import six


def find_index(items, condition_fn):
  """Return the index of the first item whose condition_fn is True."""
  for index, item in enumerate(items):
    if condition_fn(item):
      return index
  return None


def is_reproducible(item):
  """Return True if the testcase is reproducible by checking the
    one_time_crasher_flag."""
  return not item.one_time_crasher_flag


def has_issue(item):
  """Return True if the testcase has an issue."""
  return bool(item.issue_id)


def is_reproducible_and_has_issue(item):
  """Return True if the testcase is reproducible and has an issue."""
  return is_reproducible(item) and has_issue(item)


def choose(testcase_map):
  """Choose one leader for each group. We choose the highest quality testcase to
    be the leader.

    Args:
      testcase_map: a dict of (testcase_id, testcase). A dict contains testcases
          from multiple groups.
  """

  def _key_func(testcase):
    return testcase.group_id

  testcases = sorted([v for _, v in six.iteritems(testcase_map)], key=_key_func)
  for group_id, items in itertools.groupby(testcases, _key_func):
    if group_id == 0:  # group_id=0 means there's no group.
      continue

    items = sorted(items, reverse=True, key=lambda t: t.timestamp)

    for item in items:
      item.is_leader = False

    leader_index = find_index(items, is_reproducible_and_has_issue)
    if leader_index is None:
      leader_index = find_index(items, has_issue)
    if leader_index is None:
      leader_index = find_index(items, is_reproducible)
    if leader_index is None:
      leader_index = 0

    items[leader_index].is_leader = True
