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
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


# pylint: disable=protected-access
@test_utils.with_cloud_emulators('datastore')
class GetApplicationArgumentsTest(unittest.TestCase):
  """Tests _get_application_arguments."""

  def setUp(self):
    helpers.patch_environ(self)

    data_types.Job(
        name='linux_asan_chrome',
        environment_string='APP_ARGS = --orig-arg1 --orig-arg2').put()
    data_types.Job(
        name='linux_msan_chrome_variant',
        environment_string=(
            'APP_ARGS = --arg1 --arg2 --arg3="--flag1 --flag2"')).put()

    data_types.Job(name='libfuzzer_asan_chrome', environment_string='').put()
    data_types.Job(
        name='libfuzzer_msan_chrome_variant', environment_string='').put()
    data_types.Job(name='afl_asan_chrome_variant', environment_string='').put()

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


@test_utils.with_cloud_emulators('datastore')
class PreprocessGetDataBundlesTest(unittest.TestCase):
  """Tests for preprocess_get_data_bundles."""

  def setUp(self):
    self.setup_input = uworker_msg_pb2.SetupInput()
    helpers.patch_environ(self)
    environment.set_value('TASK_NAME', 'fuzz')
    environment.set_value('JOB_NAME', 'libfuzzer_chrome_asan')

  def test_no_bundles(self):
    """Tests that preprocess_get_data_bundles works when there are no data
    bundles."""
    setup.preprocess_get_data_bundles('fake', self.setup_input)
    self.assertEqual(list(self.setup_input.data_bundle_corpuses), [])

  def test_bundles(self):
    """Tests that preprocess_get_data_bundles works when there are bundles."""
    bundles_name = 'mybundle'
    bundles = [
        data_types.DataBundle(name=bundles_name),
        data_types.DataBundle(name=bundles_name)
    ]
    for bundle in bundles:
      bundle.put()
    setup.preprocess_get_data_bundles(bundles_name, self.setup_input)
    saved_bundles = [
        uworker_io.entity_from_protobuf(corpus.data_bundle,
                                        data_types.DataBundle)
        for corpus in self.setup_input.data_bundle_corpuses
    ]
    self.assertEqual(bundles, saved_bundles)


@test_utils.with_cloud_emulators('datastore')
class TestPreprocessUpdateFuzzerAndDataBundles(unittest.TestCase):
  """Tests for preprocess_update_fuzzer_and_data_bundles."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get_signed_upload_url',
        'clusterfuzz._internal.google_cloud_utils.blobs.get_signed_download_url',
        'clusterfuzz._internal.bot.tasks.task_types.is_remote_utask',
        'clusterfuzz._internal.bot.tasks.setup._update_fuzzer',
        'clusterfuzz._internal.bot.tasks.setup._clear_old_data_bundles_if_needed',
        'clusterfuzz._internal.bot.tasks.setup.update_data_bundle',
    ])
    self.mock.get_signed_upload_url.return_value = 'https://fake/upload'
    self.mock.get_signed_download_url.return_value = 'https://fake/download'
    self.fuzzer_name = 'fuzzer'
    data_bundle_name = 'data_bundle_name'
    data_types.Fuzzer(
        name=self.fuzzer_name, data_bundle_name=data_bundle_name).put()
    self.data_bundle = data_types.DataBundle(name=data_bundle_name)
    self.data_bundle.put()
    data_types.DataBundle(name=data_bundle_name).put()
    helpers.patch_environ(self)
    environment.set_value('FUZZERS_DIR', '/fuzzer')

  def test_data_bundles(self):
    """Tests that data bundles are set properly in preprocess."""
    self.mock.is_remote_utask.return_value = False
    setup_input = setup.preprocess_update_fuzzer_and_data_bundles(
        self.fuzzer_name)
    setup.update_fuzzer_and_data_bundles(setup_input)
    self.assertEqual(self.mock.update_data_bundle.call_count, 2)
