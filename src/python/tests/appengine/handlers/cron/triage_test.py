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
"""Tests for triage task."""

import unittest

from handlers.cron import triage
from tests.test_libs import helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class CrashImportantTest(unittest.TestCase):
  """Tests for is_crash_important."""

  def setUp(self):
    helpers.patch(self, [
        'metrics.crash_stats.get_last_successful_hour',
        'metrics.crash_stats.get',
        'base.utils.utcnow',
    ])
    self.mock.utcnow.return_value = test_utils.CURRENT_TIME

  def test_is_crash_important_1(self):
    """Ensure that a reproducible testcase is important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = False
    testcase.put()

    self.assertTrue(triage.is_crash_important(testcase))

  def test_is_crash_important_2(self):
    """Ensure that an unreproducible testcase with status Unreproducible is
    not important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.status = 'Unreproducible'
    testcase.put()

    self.assertFalse(triage.is_crash_important(testcase))

  def test_is_crash_important_3(self):
    """Ensure that an unreproducible testcase with status Duplicate is
    not important."""
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.status = 'Duplicate'
    testcase.put()

    self.assertFalse(triage.is_crash_important(testcase))

  def test_is_crash_important_4(self):
    """If the unreproducible testcase has another reproducible testcase in
    group, then crash is not important."""
    testcase_1 = test_utils.create_generic_testcase()
    testcase_1.one_time_crasher_flag = True
    testcase_1.group_id = 1
    testcase_1.put()

    testcase_2 = test_utils.create_generic_testcase()
    testcase_2.one_time_crasher_flag = False
    testcase_2.group_id = 1
    testcase_2.put()

    self.assertFalse(triage.is_crash_important(testcase_1))

  def test_is_crash_important_5(self):
    """If we don't have any crash stats data for this unreproducible testcase,
    then we can't make judgement on crash importance, so we return result as
    False."""
    self.mock.get_last_successful_hour.return_value = None
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage.is_crash_important(testcase))

  def test_is_crash_important_6(self):
    """If this unreproducible testcase is less than the total crash threshold,
    then it is not important."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 1,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 14,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage.is_crash_important(testcase))

  def test_is_crash_important_7(self):
    """If this unreproducible testcase spiked only for a certain interval, then
    it is not important."""
    self.mock.get_last_successful_hour.return_value = 417325
    self.mock.get.return_value = (1, [{
        'totalCount':
            125,
        'groups': [{
            'indices': [{
                'count': 125,
                'hour': 417301,
            }],
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertFalse(triage.is_crash_important(testcase))

  def test_is_crash_important_8(self):
    """If this unreproducible testcase is crashing frequently, then it is an
    important crash."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 10,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 140,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    self.assertTrue(triage.is_crash_important(testcase))

  def test_is_crash_important_9(self):
    """If this unreproducible testcase is crashing frequently, but its crash
    type is one of crash type ignores, then it is not an important crash."""
    self.mock.get_last_successful_hour.return_value = 417325
    indices = [{
        'count': 10,
        'hour': day_index
    } for day_index in range(417325, 416989, -24)]
    self.mock.get.return_value = (1, [{
        'totalCount': 140,
        'groups': [{
            'indices': indices,
            'name': 'false',
        },]
    }])
    testcase = test_utils.create_generic_testcase()
    testcase.one_time_crasher_flag = True
    testcase.put()

    for crash_type in ['Hang', 'Out-of-memory', 'Stack-overflow', 'Timeout']:
      testcase.crash_type = crash_type
      self.assertFalse(triage.is_crash_important(testcase))
