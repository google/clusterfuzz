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
"""access tests."""
# pylint: disable=protected-access
import mock
import unittest

from google.appengine.api import users

from datastore import data_types
from issue_management import issue
from issue_management import issue_tracker_manager
from libs import access
from libs import helpers
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class GetUserJobTypeTest(unittest.TestCase):
  """Test get_user_job_type."""

  _FAKE_CONFIG = 'test@test.com\nTest2@test.com;job'

  def setUp(self):
    test_helpers.patch(
        self, ['config.db_config.get_value', 'libs.helpers.get_user_email'])

  def test_none(self):
    """Ensure it returns None when config is invalid."""
    self.mock.get_value.return_value = None
    self.mock.get_user_email.return_value = ''
    self.assertIsNone(access.get_user_job_type())
    self.mock.get_value.assert_has_calls([mock.call('privileged_users')])

  def test_get_job(self):
    """Test getting job for a specific user."""
    self.mock.get_value.return_value = self._FAKE_CONFIG
    self.mock.get_user_email.return_value = 'test2@test.com'
    self.assertEqual('job', access.get_user_job_type())

  def test_get_none(self):
    """Test getting None when the user is globally privileged."""
    self.mock.get_value.return_value = self._FAKE_CONFIG
    self.mock.get_user_email.return_value = 'test@test.com'
    self.assertIsNone(access.get_user_job_type())


class IsPrivilegedUserTest(unittest.TestCase):
  """Test _is_privileged_user."""

  _FAKE_CONFIG = 'Test@test.com\n'

  def setUp(self):
    test_helpers.patch(self, ['config.db_config.get_value'])

  def test_none(self):
    """Ensure it returns False when config is invalid."""
    self.mock.get_value.return_value = None
    self.assertFalse(access._is_privileged_user('test'))
    self.mock.get_value.assert_has_calls([mock.call('privileged_users')])

  def test_global(self):
    """Ensure it returns True if an email is permitted globally."""
    self.mock.get_value.return_value = self._FAKE_CONFIG
    self.assertTrue(access._is_privileged_user('test@test.com'))
    self.mock.get_value.assert_has_calls([mock.call('privileged_users')])


class IsDomainAllowedTest(unittest.TestCase):
  """Test _is_domain_allowed."""

  _FAKE_CONFIG = ['test.com', 'test2.com']

  def setUp(self):
    test_helpers.patch(self, ['config.local_config.AuthConfig.get'])

  def test_none(self):
    """Ensure it returns False when config is invalid."""
    self.mock.get.return_value = []
    self.assertFalse(access._is_domain_allowed('test@test.com'))

  def test_allow(self):
    """Ensure it returns True when the domain is on the list."""
    self.mock.get.return_value = self._FAKE_CONFIG
    self.assertTrue(access._is_domain_allowed('test@test.com'))
    self.assertTrue(access._is_domain_allowed('test@test2.com'))

  def test_forbid(self):
    """Ensure it returns False when the domain is not on the list."""
    self.mock.get.return_value = self._FAKE_CONFIG
    self.assertFalse(access._is_domain_allowed('test.com'))
    self.assertFalse(access._is_domain_allowed('test@test24234.com'))


class GetAccessTest(unittest.TestCase):
  """Test get_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'google.appengine.api.users.get_current_user',
        'google.appengine.api.users.is_current_user_admin',
        'libs.access._is_privileged_user',
        'libs.access._is_domain_allowed',
        'base.external_users.is_fuzzer_allowed_for_user',
        'base.external_users.is_job_allowed_for_user',
    ])
    self.user = users.User('test@test.com', _auth_domain='test')

  def test_get_access_access_redirect(self):
    """Ensure it redirects when user is None."""
    self.mock.get_current_user.return_value = None
    self.mock.is_current_user_admin.return_value = False
    self.assertEqual(access.get_access(), access.UserAccess.Redirected)

  def test_get_access_admin(self):
    """Ensure it allows when user is admin."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = True
    self.assertEqual(access.get_access(), access.UserAccess.Allowed)

  def test_get_access_privileged(self):
    """Ensure it allows when user is privileged."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = False
    self.mock._is_privileged_user.return_value = True
    self.assertEqual(access.get_access(), access.UserAccess.Allowed)

  def test_get_access_allowed_domain(self):
    """For an allowed domain, ensure it allows when privileged is not needed,
       and ensure it denies when privileged is needed."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = False
    self.mock._is_privileged_user.return_value = False
    self.mock._is_domain_allowed.return_value = True
    self.assertEqual(
        access.get_access(need_privileged_access=False),
        access.UserAccess.Allowed)
    self.assertEqual(
        access.get_access(need_privileged_access=True),
        access.UserAccess.Denied)

  def test_get_access_external_fuzzer(self):
    """For a fuzzer, ensure it allows when a user is allowed."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = False
    self.mock._is_privileged_user.return_value = False
    self.mock._is_domain_allowed.return_value = False
    self.mock.is_fuzzer_allowed_for_user.return_value = True
    self.mock.is_job_allowed_for_user.return_value = False
    self.assertEqual(
        access.get_access(fuzzer_name='test'), access.UserAccess.Allowed)
    self.assertEqual(access.get_access(), access.UserAccess.Denied)

  def test_get_access_external_job(self):
    """For a job, ensure it allows when a user is allowed."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = False
    self.mock._is_privileged_user.return_value = False
    self.mock._is_domain_allowed.return_value = False
    self.mock.is_fuzzer_allowed_for_user.return_value = False
    self.mock.is_job_allowed_for_user.return_value = True
    self.assertEqual(
        access.get_access(job_type='test'), access.UserAccess.Allowed)
    self.assertEqual(access.get_access(), access.UserAccess.Denied)

  def test_get_access_denied(self):
    """Ensure it denies when every condition is false."""
    self.mock.get_current_user.return_value = self.user
    self.mock.is_current_user_admin.return_value = False
    self.mock._is_privileged_user.return_value = False
    self.mock._is_domain_allowed.return_value = False
    self.mock.is_fuzzer_allowed_for_user.return_value = False
    self.mock.is_job_allowed_for_user.return_value = False
    self.assertEqual(
        access.get_access(fuzzer_name='test'), access.UserAccess.Denied)
    self.assertEqual(access.get_access(), access.UserAccess.Denied)


class HasAccessTest(unittest.TestCase):
  """Test has_access."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.get_access',
    ])

  def test_allowed(self):
    """Test allowed."""
    self.mock.get_access.return_value = access.UserAccess.Allowed
    self.assertTrue(access.has_access(True, 'a', 'b'))
    self.mock.get_access.assert_has_calls([mock.call(True, 'a', 'b')])

  def test_denied(self):
    """Test denied."""
    self.mock.get_access.return_value = access.UserAccess.Denied
    self.assertFalse(access.has_access(True, 'a', 'b'))
    self.mock.get_access.assert_has_calls([mock.call(True, 'a', 'b')])

  def test_redirected(self):
    """Test redirected."""
    self.mock.get_access.return_value = access.UserAccess.Redirected
    self.assertFalse(access.has_access(True, 'a', 'b'))
    self.mock.get_access.assert_has_calls([mock.call(True, 'a', 'b')])


class CanUserAccessTestcaseTest(unittest.TestCase):
  """Test can_user_access_testcase."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access._is_domain_allowed',
        'libs.access.has_access',
        'libs.helpers.get_user_email',
        'config.db_config.get',
        'issue_management.issue_tracker_utils.get_issue_tracker_manager',
        'issue_management.issue_tracker_manager.IssueTrackerManager',
    ])
    itm = issue_tracker_manager.IssueTrackerManager('test')
    self.mock.get_issue_tracker_manager.return_value = itm
    self.get_issue = itm.get_issue

    self.email = 'test@test.com'
    self.mock.get_user_email.return_value = self.email

    self.bug = issue.Issue()
    self.testcase = data_types.Testcase()
    self.mock.get.return_value = (
        data_types.Config(relax_testcase_restrictions=True))

  def test_allowed(self):
    """Ensure it is true when check_user_access allows for a specific
       job_type."""
    self.mock.has_access.return_value = True
    self.testcase.job_type = 'job'
    self.testcase.fuzzer_name = 'fuzzer'
    self.testcase.security_flag = True
    self.assertTrue(access.can_user_access_testcase(self.testcase))
    self.mock.has_access.assert_has_calls([
        mock.call(
            fuzzer_name='fuzzer', job_type='job', need_privileged_access=True)
    ])

  def _test_bug_access(self):
    self.mock.has_access.return_value = False
    self.get_issue.return_value = self.bug

    self.testcase.bug_information = '1234'
    self.assertTrue(access.can_user_access_testcase(self.testcase))

    self.get_issue.assert_has_calls([mock.call(1234)])

  def test_no_bug(self):
    """Ensure it is false when there's no bug."""
    self.mock.has_access.return_value = False

    self.testcase.bug_information = ''
    self.assertFalse(access.can_user_access_testcase(self.testcase))

    self.get_issue.assert_has_calls([])

  def test_invalid_bug(self):
    """Ensure it is false when testcase's bug is invalid."""
    self.mock.has_access.return_value = False
    self.get_issue.return_value = None

    self.testcase.bug_information = '1234'
    self.assertFalse(access.can_user_access_testcase(self.testcase))

    self.get_issue.assert_has_calls([mock.call(1234)])

  def test_allowed_because_of_cc(self):
    """Ensure it is allowed because the user is CC."""
    self.bug.add_cc(self.email.capitalize())
    self._test_bug_access()

  def test_allowed_because_of_owner(self):
    """Ensure it is allowed because the user is the owner."""
    self.bug.owner = self.email.capitalize()
    self._test_bug_access()

    self.mock.get.return_value = (
        data_types.Config(relax_testcase_restrictions=False))
    self._test_bug_access()

  def test_allowed_because_of_owner_group(self):
    """Ensure it is allowed because the user is the owner of the group bug."""
    self.bug.owner = self.email.capitalize()
    self.get_issue.return_value = self.bug

    self.testcase.bug_information = None
    self.testcase.group_bug_information = 1234
    self.mock.has_access.return_value = False

    self.assertTrue(access.can_user_access_testcase(self.testcase))
    self.get_issue.assert_has_calls([mock.call(1234)])

  def test_allowed_because_of_reporter(self):
    """Ensure it is allowed because the user is the reporter."""
    self.bug.reporter = self.email.capitalize()
    self._test_bug_access()

  def test_allowed_because_of_domain_allowed(self):
    """Ensure it is true when user has bug access and user's email is on the
      domain list but the relaxation is not enabled."""
    self.mock._is_domain_allowed.return_value = True
    self.mock.get.return_value = (
        data_types.Config(relax_testcase_restrictions=False))
    self.bug.add_cc(self.email)
    self._test_bug_access()

  def test_allowed_because_of_uploader(self):
    """Ensure it is allowed because the user is the uploader."""
    self.mock.has_access.return_value = False
    self.mock._is_domain_allowed.return_value = False
    self.testcase.uploader_email = 'test@test.com'
    self.testcase.security_flag = True

    self.assertTrue(access.can_user_access_testcase(self.testcase))

  def test_deny_no_access(self):
    """Ensure it is false when user has bug access but the relaxation is not
      enabled and user's email is not on the allowed domain list."""
    self.mock._is_domain_allowed.return_value = False
    self.mock.has_access.return_value = False
    self.mock.get.return_value = (
        data_types.Config(relax_testcase_restrictions=False))
    self.testcase.bug_information = '1234'
    self.get_issue.return_value = self.bug

    self.bug.add_cc(self.email)
    self.bug.reporter = self.email
    self.bug.owner = ''

    self.assertFalse(access.can_user_access_testcase(self.testcase))

  def test_deny_no_access_and_no_bug_access(self):
    """Ensure it is false when everything is checked."""
    self.mock._is_domain_allowed.return_value = False
    self.mock.has_access.return_value = False
    self.get_issue.return_value = issue.Issue()

    self.testcase.bug_information = '1234'
    self.assertFalse(access.can_user_access_testcase(self.testcase))

    self.get_issue.assert_has_calls([mock.call(1234)])


@test_utils.with_cloud_emulators('datastore')
class CheckAccessAndGetTestcase(unittest.TestCase):
  """Test check_access_and_get_testcase."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.helpers.get_user_email',
    ])
    self.mock.get_user_email.return_value = 'user@example.com'

    token = data_types.CSRFToken()
    token.user_email = self.mock.get_user_email.return_value
    token.put()

    self.testcase = data_types.Testcase()
    self.testcase.put()

  def test_not_logged_in(self):
    """Test not logged in."""
    self.mock.get_user_email.return_value = ''
    with self.assertRaises(helpers.UnauthorizedException):
      access.check_access_and_get_testcase(self.testcase.key.id())

  def test_privileged(self):
    """Test being privileged (never get locked)."""
    self.mock.has_access.return_value = True
    access.check_access_and_get_testcase(self.testcase.key.id())

    with self.assertRaises(helpers.EarlyExitException) as cm:
      access.check_access_and_get_testcase(self.testcase.key.id() + 1)
    self.assertEqual(404, cm.exception.status)
