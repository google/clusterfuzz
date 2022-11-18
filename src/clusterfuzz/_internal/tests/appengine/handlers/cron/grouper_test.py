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
"""Tests for grouper."""

import datetime
import unittest

from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import grouper


@test_utils.with_cloud_emulators('datastore')
class GrouperTest(unittest.TestCase):
  """Grouper tests."""

  def setUp(self):
    self.testcases = [
        test_utils.create_generic_testcase(),
        test_utils.create_generic_testcase()
    ]
    self.testcase_variants = [
        test_utils.create_generic_testcase_variant(),
        test_utils.create_generic_testcase_variant()
    ]

    helpers.patch(self, [
        'handlers.cron.cleanup.get_top_crashes_for_all_projects_and_platforms',
    ])

    self.mock.get_top_crashes_for_all_projects_and_platforms.return_value = {
        'blah': {},
        'project1': {
            'LINUX': [{
                'crashState': 'foo\n'
                              'bar::Create\n'
                              'test\n',
                'crashType': 'Null-dereference READ',
                'isSecurity': False,
                'totalCount': 2829655
            }, {
                'crashState': 'top_crasher',
                'crashType': 'crash_type1',
                'isSecurity': True,
                'totalCount': 627778
            }],
        }
    }

  def test_same_crash_different_security(self):
    """Test that crashes with same crash states, but different security
      flags."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_state = 'abc\ndef'
    self.testcases[1].security_flag = True
    self.testcases[1].crash_state = 'abc\ndef'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_same_crash_same_security(self):
    """Test that crashes with same crash states and same security flags get
    de-duplicated with one of them removed."""
    for index, t in enumerate(self.testcases):
      t.security_flag = True
      t.crash_state = 'abc\ndef'
      t.timestamp = datetime.datetime.utcfromtimestamp(index)
      t.put()

    grouper.group_testcases()

    testcases = []
    for testcase_id in data_handler.get_open_testcase_id_iterator():
      testcases.append(data_handler.get_testcase_by_id(testcase_id))

    self.assertEqual(len(testcases), 1)
    self.assertEqual(testcases[0].group_id, 0)
    self.assertTrue(testcases[0].is_leader)

  def test_unminimized(self):
    """Test that unminimized testcase is not processed for grouping."""
    self.testcases[0].security_flag = True
    self.testcases[0].crash_state = 'abc\ndef'
    self.testcases[0].crash_type = 'Heap-buffer-overflow\nREAD {*}'
    self.testcases[0].minimized_keys = None
    self.testcases[1].security_flag = True
    self.testcases[1].crash_state = 'abc\ndef'
    self.testcases[1].crash_type = 'Heap-buffer-overflow\nREAD 3'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    testcases = []
    for testcase_id in data_handler.get_open_testcase_id_iterator():
      testcases.append(data_handler.get_testcase_by_id(testcase_id))

    self.assertEqual(len(testcases), 2)
    self.assertEqual(testcases[0].group_id, 0)
    self.assertFalse(testcases[0].is_leader)
    self.assertEqual(testcases[1].group_id, 0)
    self.assertTrue(testcases[1].is_leader)

  def test_different_crash_same_security(self):
    """Test that crashes with different crash states and same security flags
      don't get grouped together."""
    self.testcases[0].security_flag = True
    self.testcases[0].crash_state = 'abc\ndef'
    self.testcases[1].security_flag = True
    self.testcases[1].crash_state = 'uvw\nxyz'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_group_of_one(self):
    """Test that a group id with just one testcase gets removed."""
    self.testcases[0].group_id = 1
    self.testcases[0].put()
    self.testcases[1].key.delete()

    grouper.group_testcases()

    testcase = data_handler.get_testcase_by_id(self.testcases[0].key.id())
    self.assertEqual(testcase.group_id, 0)
    self.assertTrue(testcase.is_leader)

  def test_same_unique_crash_type_with_same_state(self):
    """Test that the crashes with same unique crash type and same state get
    de-duplicated with one of them removed.."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Timeout'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].timestamp = datetime.datetime.utcfromtimestamp(0)
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'Timeout'
    self.testcases[1].crash_state = 'abcde'
    self.testcases[1].timestamp = datetime.datetime.utcfromtimestamp(1)

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    testcases = []
    for testcase_id in data_handler.get_open_testcase_id_iterator():
      testcases.append(data_handler.get_testcase_by_id(testcase_id))

    self.assertEqual(len(testcases), 1)
    self.assertEqual(testcases[0].group_id, 0)
    self.assertTrue(testcases[0].is_leader)

  def test_same_unique_crash_type_with_different_state(self):
    """Test that the crashes with same unique crash type but different state
    don't get grouped together."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Timeout'
    self.testcases[0].crash_state = 'abcdef'
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'Timeout'
    self.testcases[1].crash_state = 'abcde'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_different_unique_crash_type_with_same_state(self):
    """Test that the crashes with different unique crash type but same state
    don't get grouped together."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Timeout'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'Out-of-memory'
    self.testcases[1].crash_state = 'abcde'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_different_unique_crash_type_with_different_state(self):
    """Test that the crashes with different unique crash type and different
    state don't get grouped together."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Timeout'
    self.testcases[0].crash_state = 'abcdef'
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'Out-of-memory'
    self.testcases[1].crash_state = 'abcde'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_different_crash_type_with_similar_state(self):
    """Test that the crashes with different crash types (one of them unique) and
    similar crash state don't get grouped together."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Timeout'
    self.testcases[0].crash_state = 'abcdef'
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'TimeoutX'
    self.testcases[1].crash_state = 'abcde'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_different_project_name_with_similar_state(self):
    """Test that the crashes with different project names and similar crash
    state don't get grouped together."""
    self.testcases[0].security_flag = False
    self.testcases[0].crash_type = 'Heap-buffer-overflow'
    self.testcases[0].crash_state = 'abcdef'
    self.testcases[0].project_name = 'project1'
    self.testcases[1].security_flag = False
    self.testcases[1].crash_type = 'Heap-buffer-overflow'
    self.testcases[1].crash_state = 'abcde'
    self.testcases[1].project_name = 'project2'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_top_crasher_for_variant_analysis(self):
    """Test that top crashers aren't grouped."""
    self.testcases[0].job_type = 'some_type1'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].one_time_crasher_flag = False
    self.testcases[0].crash_type = 'top_crasher'
    self.testcases[0].security_flag = True

    self.testcases[1].job_type = 'some_type2'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'
    self.testcases[1].crash_type = 'crash_type2'
    self.testcases[1].one_time_crasher_flag = False
    self.testcases[1].security_flag = True

    for t in self.testcases:
      t.put()

    self.testcase_variants[1].job_type = 'some_type1'
    self.testcase_variants[1].crash_state = 'abcde'
    self.testcase_variants[1].crash_type = 'crash_type1'
    self.testcase_variants[1].testcase_id = self.testcases[1].key.id()
    self.testcase_variants[1].security_flag = True

    for v in self.testcase_variants:
      v.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())

    # Check none other testcases are grouped together.
    for testcase in self.testcases:
      self.assertEqual(testcase.group_id, 0)
      self.assertTrue(testcase.is_leader)

  def test_same_job_type_for_variant_analysis(self):
    """Tests that testcases with the same job_type don't get grouped together"""
    self.testcases[0].job_type = 'same_type'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[1].job_type = 'same_type'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'

    for t in self.testcases:
      t.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_similar_variants_for_varinat_analysis(self):
    """Tests that testcases with similar variants get deduplicated."""
    self.testcases[0].job_type = 'some_type1'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].one_time_crasher_flag = False
    self.testcases[0].crash_type = 'crash_type1'
    self.testcases[0].security_flag = True
    self.testcases[1].job_type = 'some_type2'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'
    self.testcases[1].crash_type = 'crash_type2'
    self.testcases[1].one_time_crasher_flag = False
    self.testcases[1].security_flag = True

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[2].project_name = 'project1'
    self.testcases[2].crash_type = 'a3'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[3].project_name = 'project1'
    self.testcases[3].crash_type = 'b4'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[4].project_name = 'project1'
    self.testcases[4].crash_type = 'c5'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[5].project_name = 'project1'
    self.testcases[5].crash_type = 'd6'

    for t in self.testcases:
      t.put()

    # testcase2's varinat will be evaluated against testcase1
    self.testcase_variants[0].job_type = 'fake_engine_asan_project1'
    self.testcase_variants[0].testcase_id = self.testcases[0].key.id()
    self.testcase_variants[0].security_flag = True
    self.testcase_variants[1].job_type = 'some_type1'
    self.testcase_variants[1].crash_state = 'abcde'
    self.testcase_variants[1].crash_type = 'crash_type1'
    self.testcase_variants[1].testcase_id = self.testcases[1].key.id()
    self.testcase_variants[1].security_flag = True
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())

    for v in self.testcase_variants:
      v.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())

    # Check testcases 0 and 1 are grouped together and 0 is the leader.
    self.assertNotEqual(self.testcases[0].group_id, 0)
    self.assertNotEqual(self.testcases[1].group_id, 0)
    self.assertEqual(self.testcases[0].group_id, self.testcases[1].group_id)
    self.assertTrue(self.testcases[0].is_leader)
    self.assertFalse(self.testcases[1].is_leader)

    # Check none other testcases are grouped together.
    for i in range(2, 6):
      self.assertEqual(self.testcases[i].group_id, 0)
      self.assertTrue(self.testcases[i].is_leader)

  def test_similar_but_anomalous_variants_for_varinat_analysis(self):
    """Tests that testcases with similar variants but anomalous do not
    get deduplicated. Anomalous variant matches with more than threshold
    testcases. Here, testcase1 matches all (5) testcases, no grouping
    should happen"""

    self.testcases[0].job_type = 'some_type1'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].one_time_crasher_flag = False
    self.testcases[0].crash_type = 'crash_type1'
    self.testcases[0].security_flag = True
    self.testcases[1].job_type = 'some_type2'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'
    self.testcases[1].crash_type = 'crash_type2'
    self.testcases[1].one_time_crasher_flag = False
    self.testcases[1].security_flag = True

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[2].project_name = 'project1'
    self.testcases[2].crash_type = 'crash_type3'
    self.testcases[2].crash_state = 'x2'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[3].project_name = 'project1'
    self.testcases[3].crash_type = 'crash_type4'
    self.testcases[3].crash_state = 'y3'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[4].project_name = 'project1'
    self.testcases[4].crash_type = 'crash_type5'
    self.testcases[4].crash_state = 'z4'

    self.testcases.append(test_utils.create_generic_testcase())
    self.testcases[5].project_name = 'project1'
    self.testcases[5].crash_type = 'crash_type6'
    self.testcases[5].crash_state = 'w5'

    for t in self.testcases:
      t.put()

    # testcase2's varinat will be evaluated against testcase1
    self.testcase_variants[0].job_type = 'fake_engine_asan_project1'
    self.testcase_variants[0].testcase_id = self.testcases[0].key.id()
    self.testcase_variants[0].security_flag = True
    self.testcase_variants[1].job_type = 'some_type1'
    self.testcase_variants[1].crash_state = 'abcde'
    self.testcase_variants[1].crash_type = 'crash_type1'
    self.testcase_variants[1].testcase_id = self.testcases[1].key.id()
    self.testcase_variants[1].security_flag = True
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())
    self.testcase_variants.append(test_utils.create_generic_testcase_variant())

    for i in range(2, 6):
      self.testcase_variants[i].job_type = 'some_type1'
      self.testcase_variants[i].crash_state = 'abcde'
      self.testcase_variants[i].crash_type = 'crash_type1'
      self.testcase_variants[i].testcase_id = self.testcases[i].key.id()
      self.testcase_variants[i].security_flag = True

    for v in self.testcase_variants:
      v.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_no_reproducible_for_varinat_analysis(self):
    """Tests that no-reproducible testcases with similar variants do not
    get grouped together."""
    self.testcases[0].job_type = 'some_type1'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].one_time_crasher_flag = False
    self.testcases[0].crash_type = 'crash_type1'
    self.testcases[0].security_flag = True
    self.testcases[1].job_type = 'some_type2'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'
    self.testcases[1].crash_type = 'crash_type2'
    self.testcases[1].one_time_crasher_flag = True
    self.testcases[1].security_flag = True

    for t in self.testcases:
      t.put()

    # testcase2's varinat will be evaluated against testcase1
    self.testcase_variants[0].job_type = 'fake_engine_asan_project1'
    self.testcase_variants[0].testcase_id = self.testcases[0].key.id()
    self.testcase_variants[0].security_flag = True
    self.testcase_variants[1].job_type = 'some_type1'
    self.testcase_variants[1].crash_state = 'abcde'
    self.testcase_variants[1].crash_type = 'crash_type1'
    self.testcase_variants[1].testcase_id = self.testcases[1].key.id()
    self.testcase_variants[1].security_flag = True

    for v in self.testcase_variants:
      v.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)

  def test_ignored_crash_type_for_varinat_analysis(self):
    """Tests that testcases of ignored crash type with similar variants
    do not get grouped together."""
    self.testcases[0].job_type = 'some_type1'
    self.testcases[0].project_name = 'project1'
    self.testcases[0].crash_state = 'abcde'
    self.testcases[0].one_time_crasher_flag = False
    self.testcases[0].crash_type = 'crash_type1'
    self.testcases[0].security_flag = True
    self.testcases[1].job_type = 'some_type2'
    self.testcases[1].project_name = 'project1'
    self.testcases[1].crash_state = 'vwxyz'
    self.testcases[1].crash_type = 'Data race'
    self.testcases[1].one_time_crasher_flag = False
    self.testcases[1].security_flag = True

    for t in self.testcases:
      t.put()

    # testcase2's varinat will be evaluated against testcase1
    self.testcase_variants[0].job_type = 'fake_engine_asan_project1'
    self.testcase_variants[0].testcase_id = self.testcases[0].key.id()
    self.testcase_variants[0].security_flag = True
    self.testcase_variants[1].job_type = 'some_type1'
    self.testcase_variants[1].crash_state = 'abcde'
    self.testcase_variants[1].crash_type = 'crash_type1'
    self.testcase_variants[1].testcase_id = self.testcases[1].key.id()
    self.testcase_variants[1].security_flag = True

    for v in self.testcase_variants:
      v.put()

    grouper.group_testcases()

    for index, t in enumerate(self.testcases):
      self.testcases[index] = data_handler.get_testcase_by_id(t.key.id())
      self.assertEqual(self.testcases[index].group_id, 0)
      self.assertTrue(self.testcases[index].is_leader)


@test_utils.with_cloud_emulators('datastore')
class GroupExceedMaxTestcasesTest(unittest.TestCase):
  """Grouper test when a group exceeds maximum number of testcases."""

  def test_group_exceed_max_testcases(self):
    """Test that group auto-shrinks when it exceeds maximum number of
    testcases."""
    for i in range(1, 31):
      testcase = test_utils.create_generic_testcase()
      testcase.crash_type = 'Heap-buffer-overflow'
      testcase.crash_state = 'abcdefgh' + str(i)
      testcase.project_name = 'project'
      testcase.one_time_crasher_flag = False

      # Attach actual issues to some testcases.
      if i in [3, 4, 5]:
        testcase.bug_information = '123'

      # Make some testcases unreproducible.
      if i in [1, 2, 3]:
        testcase.one_time_crasher_flag = True

      testcase.put()

    unrelated_testcase = test_utils.create_generic_testcase()

    grouper.group_testcases()

    testcase_ids = list(data_handler.get_open_testcase_id_iterator())

    # [1, 2] get removed since they are unreproducible testcases.
    # [3] is not removed since it has bug attached (even though unreproducible).
    # [6, 7, 8] are removed to account for max group size. Even though they
    # are reproducible, they are the ones with least weight.
    expected_testcase_ids = [3, 4, 5] + list(range(
        9, 31)) + [unrelated_testcase.key.id()]
    self.assertEqual(expected_testcase_ids, testcase_ids)
