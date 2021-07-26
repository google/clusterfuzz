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
"""Tests for setup."""

import os
import unittest

from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class IsDirectoryOnNfsTest(unittest.TestCase):
  """Tests for the is_directory_on_nfs function."""

  def setUp(self):
    environment.set_value('NFS_ROOT', '/nfs')

  def tearDown(self):
    environment.remove_key('NFS_ROOT')

  def test_is_directory_on_nfs_without_nfs(self):
    """Test is_directory_on_nfs without nfs."""
    environment.remove_key('NFS_ROOT')
    self.assertFalse(setup.is_directory_on_nfs('/nfs/dir1'))

  def test_is_directory_on_nfs_with_nfs_and_data_bundle_on_nfs(self):
    """Test is_directory_on_nfs with nfs and data bundle on nfs."""
    self.assertTrue(setup.is_directory_on_nfs('/nfs/dir1'))

  def test_is_directory_on_nfs_with_nfs_and_data_bundle_on_local(self):
    """Test is_directory_on_nfs with nfs and data bundle on local."""
    self.assertFalse(setup.is_directory_on_nfs('/tmp/dir1'))


# pylint: disable=protected-access
@test_utils.with_cloud_emulators('datastore')
class GetApplicationArgumentsTest(unittest.TestCase):
  """Tests _get_application_arguments."""

  def setUp(self):
    helpers.patch_environ(self)

    data_types.Job(
        name='linux_asan_chrome',
        environment_string=('APP_ARGS = --orig-arg1 --orig-arg2')).put()
    data_types.Job(
        name='linux_msan_chrome_variant',
        environment_string=(
            'APP_ARGS = --arg1 --arg2 --arg3="--flag1 --flag2"')).put()

    data_types.Job(name='libfuzzer_asan_chrome', environment_string=('')).put()
    data_types.Job(
        name='libfuzzer_msan_chrome_variant', environment_string=('')).put()
    data_types.Job(
        name='afl_asan_chrome_variant', environment_string=('')).put()

    self.testcase = test_utils.create_generic_testcase()

  def test_no_minimized_arguments(self):
    """Test that None is returned when minimized arguments is not set."""
    self.testcase.minimized_arguments = ''
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        None,
        setup._get_application_arguments(self.testcase, 'linux_asan_chrome',
                                         'minimize'))
    self.assertEqual(
        None,
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_minimized_arguments_for_non_variant_task(self):
    """Test that minimized arguments are returned for non-variant tasks."""
    self.testcase.minimized_arguments = '--orig-arg2'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--orig-arg2',
        setup._get_application_arguments(self.testcase, 'linux_asan_chrome',
                                         'minimize'))

  def test_no_unique_minimized_arguments_for_variant_task(self):
    """Test that only APP_ARGS is returned if minimized arguments have no
    unique arguments, for variant task."""
    self.testcase.minimized_arguments = '--arg2'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_some_duplicate_minimized_arguments_for_variant_task(self):
    """Test that both minimized arguments and APP_ARGS are returned with
    duplicate args stripped from minimized arguments for variant task."""
    self.testcase.minimized_arguments = '--arg3="--flag1 --flag2" --arg4'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg4 --arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_unique_minimized_arguments_for_variant_task(self):
    """Test that both minimized arguments and APP_ARGS are returned when they
    don't have common args for variant task."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'linux_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg5 --arg1 --arg2 --arg3="--flag1 --flag2"',
        setup._get_application_arguments(
            self.testcase, 'linux_msan_chrome_variant', 'variant'))

  def test_no_job_app_args_for_variant_task(self):
    """Test that only minimized arguments is returned when APP_ARGS is not set
    in job definition."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'libfuzzer_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '--arg5',
        setup._get_application_arguments(
            self.testcase, 'libfuzzer_msan_chrome_variant', 'variant'))

  def test_afl_job_for_variant_task(self):
    """Test that we use a different argument list if this is an afl variant
    task."""
    self.testcase.minimized_arguments = '--arg5'
    self.testcase.job_type = 'libfuzzer_asan_chrome'
    self.testcase.put()

    self.assertEqual(
        '%TESTCASE%',
        setup._get_application_arguments(self.testcase,
                                         'afl_asan_chrome_variant', 'variant'))


# pylint: disable=protected-access
class ClearOldDataBundlesIfNeededTest(fake_filesystem_unittest.TestCase):
  """Tests _clear_old_data_bundles_if_needed."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)

    self.data_bundles_dir = '/data-bundles'
    os.mkdir(self.data_bundles_dir)
    environment.set_value('DATA_BUNDLES_DIR', self.data_bundles_dir)

  def test_evict(self):
    """Tests that eviction works when more than certain number of bundles."""
    for i in range(1, 15):
      os.mkdir(os.path.join(self.data_bundles_dir, str(i)))

    setup._clear_old_data_bundles_if_needed()
    self.assertEqual([str(i) for i in range(5, 15)],
                     sorted(os.listdir(self.data_bundles_dir), key=int))

  def test_no_evict(self):
    """Tests that no eviction is required when less than certain number of
    bundles."""
    for i in range(1, 5):
      os.mkdir(os.path.join(self.data_bundles_dir, str(i)))

    setup._clear_old_data_bundles_if_needed()
    self.assertEqual([str(i) for i in range(1, 5)],
                     sorted(os.listdir(self.data_bundles_dir), key=int))
