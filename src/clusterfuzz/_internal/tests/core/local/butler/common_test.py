# Copyright 2025 Google LLC
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
"""Tests for local common module."""
# pylint: disable=protected-access
import datetime
import os
import unittest

from clusterfuzz._internal.tests.test_libs import helpers
from local.butler import common


class ComputeRevisionTest(unittest.TestCase):
  """Test compute revision method."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'local.butler.common._get_clusterfuzz_commit_sha',
        'local.butler.common._get_clusterfuzz_config_commit_sha',
    ])
    os.environ['USER'] = 'usertest'
    return super().setUp()

  def test_valid_revision_prod(self):
    """Test valid revision with prod appengine release."""
    self.mock._get_clusterfuzz_commit_sha.return_value = '9adf34c'
    self.mock._get_clusterfuzz_config_commit_sha.return_value = 'ac37ff21'
    timestamp = datetime.datetime.strptime('20250401123000', '%Y%m%d%H%M%S')
    revision = '20250401123000-utc-9adf34c-usertest-ac37ff21-prod'

    self.assertEqual(common._compute_revision(timestamp), revision)

  def test_valid_revision_staging(self):
    """Test valid revision with staging appengine release."""
    self.mock._get_clusterfuzz_commit_sha.return_value = '9adf34c'
    self.mock._get_clusterfuzz_config_commit_sha.return_value = 'ac37ff21'
    timestamp = datetime.datetime.strptime('20250401123000', '%Y%m%d%H%M%S')
    revision = '20250401123000-utc-9adf34c-usertest-ac37ff21-staging'

    self.assertEqual(
        common._compute_revision(timestamp, is_staging=True), revision)
