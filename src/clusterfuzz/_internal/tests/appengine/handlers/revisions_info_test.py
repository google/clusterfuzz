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
"""Tests for revisions_info handler."""
import unittest

from clusterfuzz._internal.tests.test_libs import helpers
from handlers import revisions_info
from libs import helpers as libs_helpers


class RevisionsInfoTest(unittest.TestCase):
  """Tests for the revisions_info handler."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'libs.access.has_access',
        'clusterfuzz._internal.build_management.revisions.'
        'get_component_range_list',
    ])
    # Default to a caller that is allowed to access the job; the access-denied
    # path is exercised explicitly in test_no_access.
    self.mock.has_access.return_value = True
    self.mock.get_component_range_list.return_value = [{
        'component': 'src',
        'link_text': '1:2',
    }]

  def test_has_access(self):
    """Tests that an authorized caller gets the component revision list."""
    result = revisions_info.get_component_revisions_list('job1', '1', None)
    self.assertEqual([{'component': 'src', 'link_text': '1:2'}], result)
    self.mock.has_access.assert_called_with(job_type='job1')

  def test_no_access(self):
    """Tests that a caller without access to the job is denied instead of
    being handed the component/repo/revision list for that job."""
    self.mock.has_access.return_value = False
    with self.assertRaises(libs_helpers.AccessDeniedError):
      revisions_info.get_component_revisions_list('job1', '1', None)
    self.mock.has_access.assert_called_with(job_type='job1')
    self.assertFalse(self.mock.get_component_range_list.called)

  def test_invalid_job_name(self):
    """Tests that an invalid job name is rejected before any access check or
    data lookup."""
    with self.assertRaises(libs_helpers.EarlyExitError):
      revisions_info.get_component_revisions_list('bad job name!', '1', None)
    self.assertFalse(self.mock.has_access.called)
    self.assertFalse(self.mock.get_component_range_list.called)

  def test_empty_job_name(self):
    """Tests that an empty job name is rejected."""
    with self.assertRaises(libs_helpers.EarlyExitError):
      revisions_info.get_component_revisions_list('', '1', None)
    self.assertFalse(self.mock.has_access.called)


if __name__ == '__main__':
  unittest.main()
