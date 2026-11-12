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
"""variant_task tests."""
import unittest

from clusterfuzz._internal.bot import testcase_manager
from clusterfuzz._internal.bot.tasks.utasks import variant_task
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class GetVariantTestcaseForJob(unittest.TestCase):
  """Test _get_variant_testcase_for_job."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_same_job(self):
    """Test variant task with same job."""
    testcase = test_utils.create_generic_testcase()
    variant_testcase = variant_task._get_variant_testcase_for_job(  # pylint: disable=protected-access
        testcase, testcase.job_type)
    self.assertEqual(testcase, variant_testcase)

  def test_blackbox_fuzzer_job(self):
    """Test variant task with blackbox fuzzer job."""
    testcase = test_utils.create_generic_testcase()
    testcase.job_type = 'linux_asan_project'
    testcase.put()

    variant_testcase = variant_task._get_variant_testcase_for_job(  # pylint: disable=protected-access
        testcase, 'linux_msan_project')
    self.assertEqual(testcase, variant_testcase)

  def test_engine_fuzzer_job(self):
    """Test variant task with an engine fuzzer job."""
    testcase = data_types.Testcase(
        job_type='libfuzzer_asan_project',
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libfuzzer_project_binary_name',
        project_name='project',
        crash_type='crash-type',
        crash_address='0x1337',
        crash_state='A\nB\nC\n',
        crash_revision=1337)
    testcase.set_metadata(
        'fuzzer_binary_name', 'binary_name', update_testcase=True)

    job = data_types.Job()
    job.name = 'afl_asan_project'
    job.environment_string = 'PROJECT_NAME = project\n'
    job.put()

    variant_testcase = variant_task._get_variant_testcase_for_job(  # pylint: disable=protected-access
        testcase, 'afl_asan_project')
    self.assertNotEqual(testcase, variant_testcase)
    self.assertEqual(testcase.key.id(), variant_testcase.key.id())
    self.assertEqual('afl', variant_testcase.fuzzer_name)
    self.assertEqual('afl_project_binary_name',
                     variant_testcase.overridden_fuzzer_name)
    self.assertEqual('afl_asan_project', variant_testcase.job_type)

    self.assertEqual('crash-type', variant_testcase.crash_type)
    self.assertEqual('0x1337', variant_testcase.crash_address)
    self.assertEqual('A\nB\nC\n', variant_testcase.crash_state)
    self.assertEqual(1337, variant_testcase.crash_revision)
    self.assertEqual('binary_name',
                     variant_testcase.get_metadata('fuzzer_binary_name'))

    # Test that a put() call does not change original testcase.
    variant_testcase.comments = 'ABC'
    variant_testcase.put()
    testcase = data_handler.get_testcase_by_id(testcase.key.id())
    self.assertEqual('', testcase.comments)


@test_utils.with_cloud_emulators('datastore')
class UtaskPreprocessTest(unittest.TestCase):
  """Test utask_preprocess."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.bot.testcase_manager.preprocess_testcase_manager',
        'clusterfuzz._internal.bot.tasks.setup.preprocess_setup_testcase',
        'clusterfuzz._internal.metrics.logs.warning',
    ])
    self.mock.preprocess_setup_testcase.return_value = (
        uworker_msg_pb2.SetupInput())

  def test_target_not_found(self):
    """Test that TargetNotFoundError returns None"""
    testcase = test_utils.create_generic_testcase()
    error = testcase_manager.TargetNotFoundError('Target target_foo not found')
    self.mock.preprocess_testcase_manager.side_effect = error

    result = variant_task.utask_preprocess(
        testcase_id=str(testcase.key.id()),
        job_type=testcase.job_type,
        uworker_env={})

    self.assertIsNone(result)

  def test_invalid_testcase(self):
    """Test that an invalid testcase returns None and does not raise."""
    result = variant_task.utask_preprocess(
        testcase_id='999999', job_type='job_type', uworker_env={})
    self.assertIsNone(result)

  def _create_job_and_variant(self,
                              testcase,
                              job_type,
                              environment_string,
                              status=data_types.TestcaseVariantStatus.PENDING):
    """Creates |job_type| and a variant of |testcase| on it."""
    data_types.Job(name=job_type, environment_string=environment_string).put()
    variant = data_handler.get_or_create_testcase_variant(
        testcase.key.id(), job_type)
    variant.status = status
    variant.put()

  def test_variant_disabled(self):
    """Test that tasks for a job with DISABLE_VARIANT are dropped and the
    pending variant is deleted."""
    testcase = test_utils.create_generic_testcase()
    self._create_job_and_variant(testcase, 'disabled_job',
                                 'DISABLE_VARIANT = True\n')

    result = variant_task.utask_preprocess(
        testcase_id=str(testcase.key.id()),
        job_type='disabled_job',
        uworker_env={})

    self.assertIsNone(result)
    self.mock.preprocess_setup_testcase.assert_not_called()
    self.assertIsNone(
        data_handler.get_testcase_variant(testcase.key.id(), 'disabled_job'))

  def test_variant_experimental(self):
    """Test that tasks for an experimental job are dropped and the pending
    variant is deleted."""
    testcase = test_utils.create_generic_testcase()
    self._create_job_and_variant(testcase, 'experimental_job',
                                 'EXPERIMENTAL = True\n')

    result = variant_task.utask_preprocess(
        testcase_id=str(testcase.key.id()),
        job_type='experimental_job',
        uworker_env={})

    self.assertIsNone(result)
    self.mock.preprocess_setup_testcase.assert_not_called()
    self.assertIsNone(
        data_handler.get_testcase_variant(testcase.key.id(),
                                          'experimental_job'))

  def test_variant_disabled_keeps_finished_variant(self):
    """Test that only pending variants are deleted when variant is disabled."""
    testcase = test_utils.create_generic_testcase()
    self._create_job_and_variant(
        testcase,
        'disabled_job',
        'DISABLE_VARIANT = True\n',
        status=data_types.TestcaseVariantStatus.REPRODUCIBLE)

    result = variant_task.utask_preprocess(
        testcase_id=str(testcase.key.id()),
        job_type='disabled_job',
        uworker_env={})

    self.assertIsNone(result)
    self.assertIsNotNone(
        data_handler.get_testcase_variant(testcase.key.id(), 'disabled_job'))

  def test_variant_not_disabled(self):
    """Test that tasks for a job without DISABLE_VARIANT still run."""
    testcase = test_utils.create_generic_testcase()
    self._create_job_and_variant(testcase, 'enabled_job', '')

    result = variant_task.utask_preprocess(
        testcase_id=str(testcase.key.id()),
        job_type='enabled_job',
        uworker_env={})

    self.assertIsNotNone(result)
    self.mock.preprocess_setup_testcase.assert_called_once()
    self.assertIsNotNone(
        data_handler.get_testcase_variant(testcase.key.id(), 'enabled_job'))
