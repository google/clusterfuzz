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
"""Tests for CSP."""

import unittest

from libs import csp


class CSPBuilderTest(unittest.TestCase):
  """Tests for CSPBuilder."""

  def test_simple_policy(self):
    """Ensure that generating a simple policy works as expected."""
    builder = csp.CSPBuilder()

    builder.add('default-src', 'none', quote=True)
    builder.add('connect-src', 'self', quote=True)
    builder.add('script-src', 'self', quote=True)
    builder.add('script-src', 'scripts.test.tld')
    builder.add_sourceless('upgrade-insecure-requests')

    self.assertEqual(
        str(builder), "connect-src 'self'; default-src 'none'; "
        "script-src 'self' scripts.test.tld; upgrade-insecure-requests;")

  def test_policy_modification(self):
    """Ensure that policies can be modified."""
    builder = csp.CSPBuilder()

    builder.add('default-src', 'none', quote=True)
    builder.add('script-src', 'self', quote=True)
    builder.add('script-src', 'unsafe-inline', quote=True)
    builder.add('script-src', 'external.site')
    self.assertEqual(
        str(builder),
        "default-src 'none'; script-src 'self' 'unsafe-inline' external.site;")

    builder.remove('script-src', 'unsafe-inline', quote=True)
    builder.remove('script-src', 'external.site')
    self.assertEqual(str(builder), "default-src 'none'; script-src 'self';")

  def test_exception_on_duplicate_add(self):
    """Ensure that an exception is thrown if we add a duplicate item."""
    builder = csp.CSPBuilder()
    builder.add('default-src', 'none', quote=True)

    with self.assertRaises(AssertionError):
      builder.add('default-src', 'none', quote=True)

    with self.assertRaises(AssertionError):
      builder.add_sourceless('default-src')

    builder.add_sourceless('block-all-mixed-content')
    with self.assertRaises(AssertionError):
      builder.add_sourceless('block-all-mixed-content')

  def test_exception_on_bad_removal(self):
    """Ensure that an exception is thrown if we remove a nonexistent item."""
    builder = csp.CSPBuilder()

    builder.add('default-src', 'none', quote=True)
    builder.remove('default-src', 'none', quote=True)

    with self.assertRaises(AssertionError):
      builder.remove('default-src', 'none', quote=True)

    with self.assertRaises(AssertionError):
      builder.remove('script-src', 'unadded.domain')

  def test_no_exception_from_default_policy(self):
    """Ensure that no exceptions are raised building the default policy."""
    csp.get_default()
