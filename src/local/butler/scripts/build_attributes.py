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
"""Build attributes of every testcase."""

import datetime
import sys

import six

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.datastore import ndb_utils
from local.butler.scripts import attribute_builder
from local.butler.scripts import batcher

BATCH_SIZE = 500


def to_dict(entity):
  """Convert a db.Model instance to a dict."""
  entity_dict = entity.to_dict()
  entity_dict['id'] = entity.key.id()

  for k, v in six.iteritems(entity_dict):
    if isinstance(v, datetime.datetime):
      entity_dict[k] = utils.utc_datetime_to_timestamp(v)

  return entity_dict


def get_diff(before, after):
  """Return differences in string between the two dicts, before and after."""
  diffs = []
  for k, v in six.iteritems(before):
    if k in after:
      if v != after[k]:
        diffs.append((k, (v, after[k])))
    else:
      diffs.append((k, (v, '<MISSING>')))

  for k, v in six.iteritems(after):
    if k not in before:
      diffs.append((k, ('<MISSING>', v)))

  diffs.sort()

  s = ''
  for (key, (before_value, after_value)) in diffs:
    s += '%s:\n' % key
    s += '-%s\n' % before_value
    s += '+%s\n\n' % after_value

  return s


def execute(args):
  """Build keywords."""
  count_diff = 0

  query = data_types.Testcase.query().order(-data_types.Testcase.timestamp)
  for testcases in batcher.iterate(query, BATCH_SIZE):
    for testcase in testcases:
      before_testcase = to_dict(testcase)
      attribute_builder.populate(testcase)
      after_testcase = to_dict(testcase)

      diff = get_diff(before_testcase, after_testcase)
      if (count_diff % 10) == 0 and diff:
        print('Migrate (dry=%s) id:%s\n%s' % (not args.non_dry_run,
                                              testcase.key.id(), diff))

      if diff:
        count_diff += 1

    if args.non_dry_run:
      try:
        ndb_utils.put_multi(testcases)
      except Exception:
        for testcase in testcases:
          try:
            testcase.put()
          except Exception:
            print('Error: %s %s' % (testcase.key.id(), sys.exc_info()))

  print('Done (count_diff=%d)' % count_diff)
