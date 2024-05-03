# Copyright 2024 Google LLC
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
"""Tests for googlefuzztest engine."""
# pylint: disable=unused-argument
import os
import tempfile
import unittest

from clusterfuzz._internal.bot.fuzzers import engine_common
from clusterfuzz._internal.bot.fuzzers.googlefuzztest import engine
from clusterfuzz._internal.system import new_process
from clusterfuzz._internal.tests.test_libs import helpers

TEST_PATH = os.path.abspath(os.path.dirname(__file__))
BINARY_NAME = "mock_binary"


class GoogleFuzzTestUnitTests(unittest.TestCase):
  """Tests to make sure the fuzzing engine correctly handles logging by passing correct abseil flags"""

  def setUp(self):
    self.mock_temp = tempfile.TemporaryDirectory()
    self.mock_build = tempfile.TemporaryDirectory()
    self.mock_reproducers = tempfile.TemporaryDirectory()
    self.mock_binary = tempfile.TemporaryFile()

  def tearDown(self):
    self.mock_temp.cleanup()
    self.mock_build.cleanup()
    self.mock_reproducers.cleanup()
    self.mock_binary.close()

  def test_googlefuzztest_invoked_with_low_log_volume(self):
    """Test if we call fuzztest with the correct abseil flags to reduce logging volume."""
    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.engine_common.find_fuzzer_path',
        'clusterfuzz._internal.system.new_process.wait_process',
        'subprocess.Popen',
    ])
    engine_impl = engine.Engine()

    self.mock.find_fuzzer_path.return_value = self.mock_binary.name
    self.mock.wait_process.return_value = new_process.ProcessResult(output='')
    self.mock.Popen.return_value = None

    target_path = engine_common.find_fuzzer_path(self.mock_build.name,
                                                 BINARY_NAME)

    options = engine_impl.prepare(None, self.mock_binary.name,
                                  self.mock_build.name)
    results = engine_impl.fuzz(target_path, options, self.mock_reproducers.name,
                               10)

    self.assertIn('--logtostderr', results.command)
    self.assertIn('--minloglevel=3', results.command)
