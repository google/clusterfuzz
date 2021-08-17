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
"""Tests for untrusted."""

import os
import unittest

from clusterfuzz._internal.base.untrusted import untrusted_noop
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers


@untrusted_noop()
def test_function():
  return 42


@untrusted_noop(43)
def test_function2():
  return 42


class UntrustedNoopTest(unittest.TestCase):
  """Tests for untrusted_noop."""

  def setUp(self):
    test_helpers.patch_environ(self)

  def test_trusted(self):
    """Test calling function in trusted environment."""
    self.assertEqual(42, test_function())

  def test_untrusted(self):
    """Test calling function in untrusted environment."""
    os.environ['UNTRUSTED_WORKER'] = 'True'
    self.assertIsNone(test_function())
    self.assertEqual(43, test_function2())
