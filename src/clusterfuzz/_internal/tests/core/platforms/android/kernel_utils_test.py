# Copyright 2026 Google LLC
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
"""Tests for kernel_utils."""

# pylint: disable=protected-access

import unittest
from unittest import mock

from clusterfuzz._internal.platforms.android import kernel_utils
from clusterfuzz._internal.tests.test_libs import helpers


class GetCleanKernelPathTest(unittest.TestCase):
  """Tests for _get_clean_kernel_path."""

  def test_clean_path(self):
    """Test that path is cleaned correctly."""
    path = '/buildbot/src/partner-android/BRANCH/private/PROJ/kernel/msm/arch/arm64/kernel/traps.c'
    self.assertEqual(
        kernel_utils._get_clean_kernel_path(path),
        'kernel/msm/arch/arm64/kernel/traps.c')

  def test_no_private(self):
    """Test path without 'private'."""
    path = '/path/to/something/else'
    self.assertEqual(kernel_utils._get_clean_kernel_path(path), path)


class GetKernelStackFrameLinkTest(unittest.TestCase):
  """Tests for get_kernel_stack_frame_link."""

  def test_link_creation(self):
    """Test link creation."""
    stack_frame = '  [<c0667e78>] __do_fault+0x44/0x8c /buildbot/src/partner-android/BRANCH/private/PROJ/kernel/msm/mm/memory.c:3095'
    kernel_prefix = 'kernel/private/msm-google'
    kernel_hash = 'abcdef123456'

    # The expected output should replace the path:line with the link info.
    # The original path was /buildbot/src/partner-android/BRANCH/private/PROJ/kernel/msm/mm/memory.c
    # _get_clean_kernel_path converts it to kernel/msm/mm/memory.c (PROJ removed)
    # kernel_prefix is stripped to msm-google

    # The function constructs:
    # prefix = msm-google
    # hash = abcdef123456
    # path = kernel/msm/mm/memory.c
    # line = 3095
    # display_path = msm-google/kernel/msm/mm/memory.c:3095

    expected_link_part = ('http://go/pakernel/msm-google/+/abcdef123456/'
                          'kernel/msm/mm/memory.c#3095;'
                          'msm-google/kernel/msm/mm/memory.c:3095;')

    result = kernel_utils.get_kernel_stack_frame_link(
        stack_frame, kernel_prefix, kernel_hash)
    self.assertIn(expected_link_part, result)

  def test_no_match(self):
    """Test when regex doesn't match."""
    stack_frame = 'random string'
    self.assertEqual(
        kernel_utils.get_kernel_stack_frame_link(stack_frame, 'prefix', 'hash'),
        stack_frame)


class GetPrefixAndFullHashTest(unittest.TestCase):
  """Tests for _get_prefix_and_full_hash."""

  def test_found(self):
    """Test when hash is found."""
    repo_data = "prefix1 u'fullhash1\nprefix2 u'fullhash2"
    prefix, full_hash = kernel_utils._get_prefix_and_full_hash(
        repo_data, 'fullhash1')
    self.assertEqual(prefix, 'prefix1')
    self.assertEqual(full_hash, 'fullhash1')

  def test_not_found(self):
    """Test when hash is not found."""
    repo_data = "prefix1 u'fullhash1\nprefix2 u'fullhash2"
    prefix, full_hash = kernel_utils._get_prefix_and_full_hash(
        repo_data, 'nonexistent')
    self.assertIsNone(prefix)
    self.assertIsNone(full_hash)


class GetRepoPropDataTest(unittest.TestCase):
  """Tests for _get_repo_prop_data."""

  def setUp(self):
    """Set up mocks."""
    helpers.patch(self, [
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.platforms.android.symbols_downloader.get_repo_prop_archive_filename',
        'clusterfuzz._internal.platforms.android.symbols_downloader.download_kernel_repo_prop_if_needed',
        'clusterfuzz._internal.base.utils.find_binary_path',
        'clusterfuzz._internal.base.utils.read_data_from_file',
        'os.path.exists',
    ])
    self.mock.get_value.return_value = '/symbols'
    self.mock.get_repo_prop_archive_filename.return_value = 'repo.prop'

  def test_success(self):
    """Test success path."""
    self.mock.find_binary_path.return_value = '/symbols/repo.prop'
    self.mock.exists.return_value = True
    self.mock.read_data_from_file.return_value = b'data'

    result = kernel_utils._get_repo_prop_data('build_id', 'target')
    self.assertEqual(result, 'data')

  def test_failure(self):
    """Test failure path."""
    self.mock.find_binary_path.return_value = None

    result = kernel_utils._get_repo_prop_data('build_id', 'target')
    self.assertIsNone(result)


class GetKernelNameTest(unittest.TestCase):
  """Tests for get_kernel_name."""

  def setUp(self):
    """Set up mocks."""
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_product_name',
        'clusterfuzz._internal.platforms.android.settings.get_build_product',
    ])

  def test_default(self):
    """Test default kernel name."""
    self.mock.get_product_name.return_value = 'product'
    self.mock.get_build_product.return_value = 'product'

    with mock.patch.dict(
        'clusterfuzz._internal.platforms.android.constants.PRODUCT_TO_KERNEL',
        {},
        clear=True):
      self.assertEqual(kernel_utils.get_kernel_name(), 'product')

  def test_kasan_strip(self):
    """Test that _kasan is handled."""
    self.mock.get_product_name.return_value = 'product_kasan'
    self.mock.get_build_product.return_value = 'product'

    with mock.patch.dict(
        'clusterfuzz._internal.platforms.android.constants.PRODUCT_TO_KERNEL',
        {},
        clear=True):
      # Based on current implementation, _kasan is NOT stripped because the
      # return value of utils.strip_from_right is ignored.
      self.assertEqual(kernel_utils.get_kernel_name(), 'product_kasan')

  def test_mapping(self):
    """Test mapping."""
    self.mock.get_product_name.return_value = 'product'
    self.mock.get_build_product.return_value = 'alias_product'

    with mock.patch.dict(
        'clusterfuzz._internal.platforms.android.constants.PRODUCT_TO_KERNEL',
        {'alias_product': 'real_product'},
        clear=True):
      self.assertEqual(kernel_utils.get_kernel_name(), 'real_product')


class GetKernelHashAndBuildIdTest(unittest.TestCase):
  """Tests for get_kernel_hash_and_build_id."""

  def setUp(self):
    """Set up mocks."""
    helpers.patch(self, [
        'clusterfuzz._internal.platforms.android.settings.get_kernel_version_string',
    ])

  def test_match(self):
    """Test with matching kernel version string."""
    self.mock.get_kernel_version_string.return_value = (
        'Linux version 3.18.0-g8de8e79-ab1234567 (android-build@google.com)')
    # Expected: (match.group(2), match.group(3))
    # match.group(2) is 'ab1234567 ' (with space)
    # match.group(3) is '1234567'
    self.assertEqual(kernel_utils.get_kernel_hash_and_build_id(),
                     ('ab1234567 ', '1234567'))

  def test_no_match(self):
    """Test with non-matching kernel version string."""
    self.mock.get_kernel_version_string.return_value = 'invalid'
    self.assertEqual(kernel_utils.get_kernel_hash_and_build_id(), (None, None))
