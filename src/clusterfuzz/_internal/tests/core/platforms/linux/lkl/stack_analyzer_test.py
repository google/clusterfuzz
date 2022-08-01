# Copyright 2020 Google LLC
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
"""Tests for the stack analyzer module for lkl specifically."""

import os
import unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'stack_analyzer_data')
TEST_JOB_NAME = 'test_lkl'

KERNEL_REPRO = """kernel/build u'6eeca0ea35da517952643a3b0c5b2436df4d3230'
kernel/common-patches u'34bbf764ca33bd39922a40ca641139a9362a0812'
kernel/configs u'89ba434b0b7624d6085f22742f01a0d8502e7025'
kernel/cuttlefish-modules u'5375d668eb898993d0acbba27de47e2eb605b0a0'
kernel/goldfish-modules u'f21b72a86766714b06bdc2b532ebd61b10286b26'
kernel/hikey-modules u'33d4b7f884500689a297df156b1c0a29e1c525da'
kernel/manifest u'c85b8efb8d71e931b400942f7716bb5ecac9b1fa'
kernel/prebuilts/build-tools u'96755e2ffffe500011eecd81b63eeaf2d484338e'
kernel/private/lkl u'd0fcd2ee3504f53bba1227805a8ba3828e9279aa'
kernel/tests u'9e155c5f1646097bfa3e71017079b1caf1ba57d4'
platform/prebuilts/boot-artifacts u'45d30d07ad284018481ebb419b5d01b5de72ed02'
platform/prebuilts/build-tools u'167903bfd32b60bcff841422710b7cf489c84fec'
platform/prebuilts/clang/host/linux-x86 u'c1bd0e5040ec38682f101fa6ce35e4e2c0079c0e'
platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 u'e9c7c9eb5c3ab5d4f1f09b3ce97498fc59c3bdcd'
platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9 u'1b12660791807c225dc682addaa37d0b9468349c'
platform/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8 u'71ba8516fe4039ddb00dd0976c211d28d3ff8913'
platform/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9 u'337ac2199f94c781e3c97baf2a0027d004d0097f'
platform/system/tools/mkbootimg u'f59f25d67f55ea6ee879678cfa1bfdd0be5f4019'
"""


# pylint: disable=unused-argument
def _mock_symbolize_stacktrace(stacktrace, enable_inline_frames=True):
  """No-op mocked version of symbolize_stacktrace."""
  return stacktrace


def _mock_fetch_artifact_get(bid,
                             target,
                             regex,
                             output_directory,
                             output_filename_override=None):
  if output_filename_override:
    artifact_path = os.path.join(output_directory, output_filename_override)
    with open(artifact_path, 'w') as artifact_file:
      artifact_file.write(KERNEL_REPRO)


# pylint: enable=unused-argument


class LKLStackAnalyzerTest(unittest.TestCase):
  """LKL specific Stack analyzer tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.'
        'symbolize_stacktrace',
        'clusterfuzz._internal.metrics.logs.log_error',
    ])
    os.environ['JOB_NAME'] = TEST_JOB_NAME

    self.mock.symbolize_stacktrace.side_effect = _mock_symbolize_stacktrace

  def _mock_read_data_from_file(self, file_path, eval_data=True, default=None):
    if file_path.endswith('repo.prop'):
      return self._real_read_data_from_file(file_path, eval_data, default)

    return None

  def _read_test_data(self, name):
    """Helper function to read test data."""
    with open(os.path.join(DATA_DIRECTORY, name)) as handle:
      return handle.read()

  def test_lkl_linkification(self):
    """Test lkl linkification."""
    environment.set_bot_environment()
    self._real_read_data_from_file = utils.read_data_from_file
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
        'clusterfuzz._internal.google_cloud_utils.storage.get_file_from_cache_if_exists',
        'clusterfuzz._internal.google_cloud_utils.storage.store_file_in_cache',
        'clusterfuzz._internal.base.utils.write_data_to_file',
        'clusterfuzz._internal.base.utils.read_data_from_file'
    ])
    self.mock.get.side_effect = _mock_fetch_artifact_get
    self.mock.get_file_from_cache_if_exists.return_value = False
    self.mock.store_file_in_cache.return_value = None
    self.mock.write_data_to_file = None
    self.mock.read_data_from_file.side_effect = self._mock_read_data_from_file

    data = self._read_test_data('lkl_libfuzzer_symbolized.txt')
    expected_stack = self._read_test_data(
        'lkl_libfuzzer_symbolized_linkified.txt')
    actual_state = stack_analyzer.get_crash_data(data)
    self.assertEqual(actual_state.crash_stacktrace, expected_stack)
