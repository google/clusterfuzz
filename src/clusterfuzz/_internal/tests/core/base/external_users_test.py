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
"""Tests for external_users."""

import datetime
import unittest

from clusterfuzz._internal.base import external_users
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class ExternalUsersTest(unittest.TestCase):
  """External users test."""

  def setUp(self):
    helpers.patch_environ(self)

    # Fake permissions.
    data_types.ExternalUserPermission(
        email='user@example.com',
        entity_name='fuzzer',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user2@example.com',
        entity_name='fuzz',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.SECURITY).put()

    data_types.ExternalUserPermission(
        email='user3@example.com',
        entity_name='parent_',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user4@example.com',
        entity_name='parent',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user5@example.com',
        entity_name='parent_cg',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user6@example.com',
        entity_name='parens',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user7@example.com',
        entity_name='parent',
        entity_kind=data_types.PermissionEntityKind.FUZZER,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user2@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=True,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user3@example.com',
        entity_name='job2',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.ALL).put()

    data_types.ExternalUserPermission(
        email='user8@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user9@example.com',
        entity_name='job2',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user10@example.com',
        entity_name='job',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='user10@example.com',
        entity_name='job3',
        entity_kind=data_types.PermissionEntityKind.JOB,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.NONE).put()

    data_types.ExternalUserPermission(
        email='uploader1@example.com',
        entity_name=None,
        entity_kind=data_types.PermissionEntityKind.UPLOADER,
        is_prefix=False,
        auto_cc=data_types.AutoCCType.NONE).put()

    # Fake fuzzers.
    data_types.Fuzzer(name='fuzzer').put()
    data_types.Fuzzer(name='parent', jobs=['job', 'job2', 'job3']).put()

    data_types.Job(name='job').put()
    data_types.Job(name='job2').put()
    data_types.Job(name='job3').put()

    data_types.FuzzTarget(
        engine='parent', binary='child', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='parent_child',
        job='job',
        last_run=datetime.datetime.utcnow()).put()

    data_types.FuzzTarget(
        engine='parent', binary='child2', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='parent_child2',
        job='job',
        last_run=datetime.datetime.utcnow()).put()

    data_types.FuzzTarget(
        engine='parent', binary='child', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='parent_child',
        job='job3',
        last_run=datetime.datetime.utcnow()).put()

  def test_allowed_fuzzers(self):
    """allowed_fuzzers_for_user tests."""
    # Direct match.
    result = external_users.allowed_fuzzers_for_user('User@example.com')
    self.assertEqual(result, ['fuzzer'])

    # Prefix on fuzzer name.
    result = external_users.allowed_fuzzers_for_user('uSer2@example.com')
    self.assertEqual(result, ['fuzzer'])

    # Prefix on child fuzzer name.
    result = external_users.allowed_fuzzers_for_user('user3@example.com')
    self.assertEqual(result, ['parent_child', 'parent_child2'])

    # Direct match on a parent fuzzer that has children. Should not have any
    # results.
    result = external_users.allowed_fuzzers_for_user('user4@example.com')
    self.assertEqual(len(result), 0)

    # No such user.
    result = external_users.allowed_fuzzers_for_user('notexist@example.com')
    self.assertEqual(result, [])

  def test_allowed_users_for_fuzzer(self):
    """allowed_users_for_fuzzer tests."""
    # Direct match + a prefix match.
    result = external_users.allowed_users_for_fuzzer('fuzzer')
    self.assertEqual(result, ['user2@example.com', 'user@example.com'])

    # Child fuzzer prefix match.
    result = external_users.allowed_users_for_fuzzer('parent_child')
    self.assertEqual(result, ['user3@example.com', 'user7@example.com'])

  def test_is_fuzzer_allowed_for_user(self):
    """is_fuzzer_allowed_for_user tests."""
    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user('uSer@example.com', 'fuzzer'))
    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user('useR2@example.com',
                                                  'fuzzer'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user3@example.com',
                                                  'fuzzer'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user4@example.com',
                                                  'fuzzer'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user5@example.com',
                                                  'fuzzer'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user6@example.com',
                                                  'fuzzer'))
    # No such user.
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('notexist@example.com',
                                                  'fuzzer'))

    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user1@example.com',
                                                  'parent_child'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user2@example.com',
                                                  'parent_child'))
    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user('user3@example.com',
                                                  'parent_child'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user4@example.com',
                                                  'parent_child'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user5@example.com',
                                                  'parent_child'))
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('user6@example.com',
                                                  'parent_child'))
    # No such user.
    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user('notexist@example.com',
                                                  'fuzzer'))

  def test_is_fuzzer_allowed_for_user_including_jobs(self):
    """is_fuzzer_allowed_for_user tests with include_from_jobs == True."""
    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user(
            'User@example.com', 'parent_child', include_from_jobs=True))

    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user(
            'uSer@example.com', 'parent_child', include_from_jobs=False))

    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user(
            'uSer@example.com', 'parent_child2', include_from_jobs=True))

    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user(
            'user@example.com', 'parent_child2', include_from_jobs=False))

    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user(
            'user@example.com', 'parent_child3', include_from_jobs=True))

    self.assertFalse(
        external_users.is_fuzzer_allowed_for_user(
            'user@example.com', 'parent', include_from_jobs=True))

    self.assertTrue(
        external_users.is_fuzzer_allowed_for_user(
            'user@example.com', 'fuzzer', include_from_jobs=True))

  def test_is_job_allowed_for_user(self):
    """is_job_allowed_for_user tests."""
    self.assertTrue(
        external_users.is_job_allowed_for_user('useR@example.com', 'job'))
    self.assertTrue(
        external_users.is_job_allowed_for_user('user2@example.com', 'job'))
    self.assertTrue(
        external_users.is_job_allowed_for_user('user8@example.com', 'job'))
    self.assertFalse(
        external_users.is_job_allowed_for_user('user3@example.com', 'job'))
    self.assertTrue(
        external_users.is_job_allowed_for_user('User3@example.com', 'job2'))
    self.assertTrue(
        external_users.is_job_allowed_for_user('user9@example.com', 'job2'))
    self.assertFalse(
        external_users.is_job_allowed_for_user('user@example.com', 'job2'))

  def test_is_upload_allowed_for_user(self):
    """is_upload_allowed_for_user tests."""
    self.assertTrue(
        external_users.is_upload_allowed_for_user('uploader1@example.com'))
    self.assertFalse(
        external_users.is_upload_allowed_for_user('user@example.com'))

  def test_cc_users_for_fuzzer(self):
    """cc_users_for_fuzzer tests."""
    result = external_users.cc_users_for_fuzzer('fuzzer', security_flag=False)
    self.assertEqual(result, ['user@example.com'])

    result = external_users.cc_users_for_fuzzer('fuzzer', security_flag=True)
    self.assertEqual(result, ['user2@example.com', 'user@example.com'])

    result = external_users.cc_users_for_fuzzer(
        'parent_child', security_flag=True)
    self.assertListEqual(result, ['user7@example.com'])

  def test_cc_users_for_job(self):
    """cc_users_for_job tests."""
    result = external_users.cc_users_for_job('job', security_flag=False)
    self.assertEqual(result, ['user2@example.com', 'user@example.com'])

    result = external_users.cc_users_for_job('job', security_flag=True)
    self.assertEqual(result, ['user2@example.com', 'user@example.com'])

    result = external_users.cc_users_for_job('job2', security_flag=False)
    self.assertEqual(result, ['user2@example.com', 'user3@example.com'])

  def test_allowed_jobs(self):
    """Test allowed_jobs_for_user."""
    result = external_users.allowed_jobs_for_user('User@example.com')
    self.assertEqual(['job'], result)

    result = external_users.allowed_jobs_for_user('uSer2@example.com')
    self.assertEqual(['job', 'job2', 'job3'], result)

    result = external_users.allowed_jobs_for_user('user3@example.com')
    self.assertEqual(['job2'], result)

    result = external_users.allowed_jobs_for_user('user4@example.com')
    self.assertEqual([], result)

  def test_allowed_fuzzers_including_jobs(self):
    """Tests allowed_fuzzers_for_user with jobs."""
    result = external_users.allowed_fuzzers_for_user(
        'User@example.com', include_from_jobs=True)
    self.assertEqual(['fuzzer', 'parent_child', 'parent_child2'], result)
    result = external_users.allowed_fuzzers_for_user(
        'User8@example.com', include_from_jobs=True)
    self.assertEqual(['parent_child', 'parent_child2'], result)
    result = external_users.allowed_fuzzers_for_user(
        'user8@example.com', include_from_jobs=True, include_parents=True)
    self.assertEqual(['parent', 'parent_child', 'parent_child2'], result)
    result = external_users.allowed_fuzzers_for_user(
        'user9@example.com', include_from_jobs=True)
    self.assertEqual([], result)

    result = external_users.allowed_fuzzers_for_user('user10@example.com')
    self.assertEqual([], result)

    result = external_users.allowed_fuzzers_for_user(
        'user10@example.com', include_from_jobs=True)
    self.assertEqual(['parent_child', 'parent_child2'], result)

    result = external_users.allowed_fuzzers_for_user(
        'user10@example.com', include_from_jobs=True, include_parents=True)
    self.assertEqual(['parent', 'parent_child', 'parent_child2'], result)


if __name__ == '__main__':
  unittest.main()
