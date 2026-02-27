# Copyright 2026 Google LLC
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
"""Tests for oss_fuzz_cc_groups cron."""

import unittest

import parameterized

from clusterfuzz._internal.cron import oss_fuzz_cc_groups
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class OssFuzzCcGroupsTest(unittest.TestCase):
  """Tests for oss_fuzz_cc_groups."""

  def setUp(self):
    test_helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.google_groups.get_group_id',
        'clusterfuzz._internal.google_cloud_utils.google_groups.create_google_group',
        'clusterfuzz._internal.google_cloud_utils.google_groups.get_google_group_memberships',
        'clusterfuzz._internal.google_cloud_utils.google_groups.add_member_to_group',
        'clusterfuzz._internal.google_cloud_utils.google_groups.delete_google_group_membership',
        'clusterfuzz._internal.google_cloud_utils.google_groups.set_oss_fuzz_access_settings',
        'clusterfuzz._internal.base.utils.is_service_account',
    ])

  def test_main(self):
    """Test main execution for creating groups and syncing project ccs."""
    project1 = data_types.OssFuzzProject(
        name='project1', ccs=['member2@example.com'])
    project2 = data_types.OssFuzzProject(
        name='project2', ccs=['member2@example.com', 'member3@example.com'])
    project1.put()
    project2.put()

    # project1 group does not exist, so create it.
    # project2 group exists, only sync members.
    self.mock.get_group_id.side_effect = [None, 'group2_id']
    self.mock.create_google_group.return_value = True

    self.mock.get_google_group_memberships.return_value = {
        'member1@example.com': 'membership1',
        'member2@example.com': 'membership2',
    }
    self.mock.is_service_account.return_value = False

    self.assertTrue(oss_fuzz_cc_groups.main())

    # project1 check
    self.mock.create_google_group.assert_called_with(
        'project1-ccs@oss-fuzz.com',
        group_description=(
            'External CCs in OSS-Fuzz issue tracker for project: project1'))

    # project2 check
    self.mock.add_member_to_group.assert_called_with('group2_id',
                                                     'member3@example.com')
    self.mock.delete_google_group_membership.assert_called_with(
        'group2_id', 'member1@example.com', 'membership1')

  def test_main_exec_for_new_group(self):
    """Test main execution for a newly created group."""
    project1 = data_types.OssFuzzProject(
        name='project1', ccs=['member2@example.com'])
    project1.put()
    self.mock.get_group_id.return_value = '1'
    self.mock.get_google_group_memberships.return_value = {
        'member1@gserviceaccount.com': 'membership1'
    }
    self.mock.set_oss_fuzz_access_settings.return_value = True
    self.mock.is_service_account.return_value = True

    self.assertTrue(oss_fuzz_cc_groups.main())
    self.mock.create_google_group.assert_not_called()
    self.mock.get_group_id.assert_called_once_with('project1-ccs@oss-fuzz.com')
    self.mock.set_oss_fuzz_access_settings.assert_called_once_with(
        'project1-ccs@oss-fuzz.com')
    self.mock.add_member_to_group.assert_called_once_with(
        '1', 'member2@example.com')
    self.mock.delete_google_group_membership.assert_not_called()

  def test_create_fail(self):
    """Test group creation failure."""
    project1 = data_types.OssFuzzProject(
        name='project1', ccs=['member2@example.com'])
    project1.put()
    self.mock.get_group_id.return_value = None
    self.mock.create_google_group.return_value = False

    self.assertTrue(oss_fuzz_cc_groups.main())
    self.mock.get_google_group_memberships.assert_not_called()

  def test_get_memberships_fail(self):
    """Test get memberships failure."""
    project1 = data_types.OssFuzzProject(name='project1')
    project1.put()
    self.mock.get_group_id.return_value = 'group1_id'
    self.mock.get_google_group_memberships.return_value = None

    self.assertTrue(oss_fuzz_cc_groups.main())
    self.mock.add_member_to_group.assert_not_called()
    self.mock.delete_google_group_membership.assert_not_called()

  def test_skip_sa_deletion(self):
    """Test that service accounts are not deleted from group."""
    project1 = data_types.OssFuzzProject(name='project1')
    project1.put()
    self.mock.get_group_id.return_value = 'group1_id'
    self.mock.get_google_group_memberships.return_value = {
        'sa@serviceaccount.com': 'membership_sa',
    }
    self.mock.is_service_account.return_value = True

    self.assertTrue(oss_fuzz_cc_groups.main())
    self.mock.delete_google_group_membership.assert_not_called()

  @parameterized.parameterized.expand(
      [('test1@googlemail.com', 'test1@gmail.com'), ('TesT2@gmail.com',
                                                     'test2@gmail.com'),
       ('test3@example.com', 'test3@example.com'), ('test4.dot@gmail.com',
                                                    'test4dot@gmail.com'),
       ('test5.dot@example.com',
        'test5.dot@example.com'), ('test6+alias@example.com',
                                   'test6@example.com'), ('test7.not.an.email',
                                                          None)])
  def test_normalize_email_for_group(self, test_email, normalized_email):
    """Test normalize email for groups method."""
    self.assertEqual(
        oss_fuzz_cc_groups.normalize_email_for_group(test_email),
        normalized_email)
