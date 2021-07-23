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
"""Reproduce tool configuration tests."""
import unittest

from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs.reproduce_tool_fakes import \
    FakeResponse
from local.butler.reproduce_tool import config
from local.butler.reproduce_tool import errors


class ReproduceToolConfigurationTest(unittest.TestCase):
  """Tests for ReproduceToolConfiguration."""

  def setUp(self):
    helpers.patch(self, [
        'local.butler.reproduce_tool.http_utils.request',
    ])

  def test_local_server(self):
    """Ensure that we can get the configuration for a local server."""
    self.mock.request.return_value = (FakeResponse(200), '{"x": 1}')
    configuration = config.ReproduceToolConfiguration(
        'http://localhost:9000/testcase-detail/1')

    self.assertEqual(configuration.get('x'), 1)
    self.mock.request.assert_called_once_with(
        'http://localhost:9000/reproduce-tool/get-config', body={})

  def test_https_server(self):
    """Ensure that we can get the configuration for an HTTPS server."""
    self.mock.request.return_value = (FakeResponse(200), '{"x": 1}')
    configuration = config.ReproduceToolConfiguration(
        'https://clusterfuzz/testcase-detail/1')

    self.assertEqual(configuration.get('x'), 1)
    self.mock.request.assert_called_once_with(
        'https://clusterfuzz/reproduce-tool/get-config', body={})

  def test_failure(self):
    """Ensure that we raise an exception if the server encounters an error."""
    self.mock.request.return_value = (FakeResponse(403), '{"x": 1}')

    with self.assertRaises(errors.ReproduceToolUnrecoverableError):
      config.ReproduceToolConfiguration('https://clusterfuzz/testcase-detail/1')
