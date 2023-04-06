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
"""Tests for the stack analyzer module for android specifically."""

import os
import unittest

from clusterfuzz._internal.base import utils
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'stack_analyzer_data')
TEST_JOB_NAME = 'test'

KERNEL_REPRO = """kernel/build u'c059b39e1caf2b96aa376582eeb93062b43d69d5'
kernel/manifest u'75a64986ab455f8b45087b8ad54db68bcb8988f4'
kernel/private/msm-google u'40e9b2ff3a280a8775cfcd5841e530ce78f94355'
kernel/private/msm-google-extra/audiokernel u'112a618d5b757b0600c69f7385892b3f57ccd93e'
kernel/private/msm-google-modules/data-kernel u'e7210f09d00c91f87b295c7a952f040c73506cc0'
kernel/private/msm-google-modules/fts_touch u'8f6a4e9f5649deff59174ffed1d5c2af196d9f63'
kernel/private/msm-google-modules/qca-wfi-host-cmn u'7d4b05ac12d6a1b5d5247da35ae7e370a2cba07d'
kernel/private/msm-google-modules/qcacld u'0a077b0073c48555d0edb2b9b0510fb883181828'
kernel/private/msm-google-modules/wlan-fw-api u'53d899727e4278f4e9fb46328d740a8fb2d9a493'
kernel/private/tests/patchwork u'204e78fb6d905016bfc16ebe7b64547f388cfdb5'
kernel/tests u'bfef3bb78b23cb3f3f12a6880ecafd5def3b66a5'
platform/external/fff u'c82edb1fc60dc81bd319d9b8d0bee9f8963a6960'
platform/external/googletest u'a037984aea3317260edd1127abb39e30e845bc94'
platform/prebuilts/clang/host/linux-x86 u'4b1f275e6b3826c86f791ae8c4d5ec3563c2fc11'
platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 u'961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c'
platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9 u'cb7b3ac1b7fdb49474ff68761909934d1142f594'
platform/prebuilts/misc u'15560bb32cdb9b47db48eb4865b736df9708a8fe'
platform/tools/repohooks u'233b8010f7f5e3c544b47c68ffae781860156945'
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


class AndroidStackAnalyzerTest(unittest.TestCase):
  """Android specific Stack analyzer tests."""

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

  def test_syzkaller_kasan_android_with_env(self):
    """Test syzkaller kasan."""
    environment.set_value('OS_OVERRIDE', 'ANDROID_KERNEL')
    environment.set_bot_environment()
    self._real_read_data_from_file = utils.read_data_from_file
    test_helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.fetch_artifact.get',
        'clusterfuzz._internal.platforms.android.kernel_utils.get_kernel_hash_and_build_id',
        'clusterfuzz._internal.platforms.android.kernel_utils.get_kernel_name',
        'clusterfuzz._internal.platforms.android.settings.get_product_brand',
        'clusterfuzz._internal.google_cloud_utils.storage.get_file_from_cache_if_exists',
        'clusterfuzz._internal.google_cloud_utils.storage.store_file_in_cache',
        'clusterfuzz._internal.base.utils.write_data_to_file',
        'clusterfuzz._internal.base.utils.read_data_from_file'
    ])
    self.mock.get.side_effect = _mock_fetch_artifact_get
    self.mock.get_kernel_hash_and_build_id.return_value = '40e9b2ff3a2', '12345'
    self.mock.get_kernel_name.return_value = 'device_kernel'
    self.mock.get_product_brand.return_value = 'google'
    self.mock.get_file_from_cache_if_exists.return_value = False
    self.mock.store_file_in_cache.return_value = None
    self.mock.write_data_to_file = None
    self.mock.read_data_from_file.side_effect = self._mock_read_data_from_file

    data = self._read_test_data('kasan_syzkaller_android.txt')
    expected_stack = self._read_test_data(
        'kasan_syzkaller_android_linkified.txt')
    actual_state = stack_analyzer.get_crash_data(data)
    self.assertEqual(actual_state.crash_stacktrace, expected_stack)
