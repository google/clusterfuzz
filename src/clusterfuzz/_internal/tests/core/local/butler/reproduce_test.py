# Copyright 2025 Google LLC
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
"""Tests for the reproduce butler."""

import argparse
import unittest
from unittest import mock

from clusterfuzz._internal.crash_analysis.crash_result import CrashResult
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from local.butler import reproduce


class ReproduceTestcaseTest(unittest.TestCase):
  """Tests for the _reproduce_testcase function."""

  def setUp(self):
    super().setUp()
    self.addCleanup(mock.patch.stopall)
    self.mock_logs = mock.patch.multiple(
        'local.butler.reproduce.logs',
        error=mock.DEFAULT,
        info=mock.DEFAULT,
        warning=mock.DEFAULT).start()

    helpers.patch(self, [
        'clusterfuzz._internal.datastore.data_handler.get_testcase_by_id',
        'clusterfuzz._internal.datastore.data_types.Job.query',
        'clusterfuzz._internal.system.environment.set_value',
        'clusterfuzz._internal.system.environment.get_value',
        'clusterfuzz._internal.bot.tasks.commands.update_environment_for_job',
        'clusterfuzz._internal.bot.tasks.setup.setup_local_fuzzer',
        'clusterfuzz._internal.bot.tasks.setup.setup_local_testcase',
        'clusterfuzz._internal.build_management.build_manager.setup_build',
        'clusterfuzz._internal.bot.testcase_manager.check_for_bad_build',
        'clusterfuzz._internal.bot.testcase_manager.test_for_crash_with_retries',
        'clusterfuzz._internal.bot.testcase_manager.test_for_reproducibility',
        'clusterfuzz._internal.bot.untrusted_runner.host.stub',
    ])

    self.testcase = data_types.Testcase(
        job_type='test_job', fuzzer_name='test_fuzzer', crash_revision=12345)
    self.testcase.get_fuzz_target = mock.Mock()
    self.job = data_types.Job(name='test_job')
    self.mock.get_testcase_by_id.return_value = self.testcase
    self.mock.query.return_value.get.return_value = self.job

    self.mock.setup_local_fuzzer.return_value = True
    self.mock.setup_local_testcase.return_value = '/tmp/testcase'

    build_result = uworker_msg_pb2.BuildData(is_bad_build=False)
    self.mock.check_for_bad_build.return_value = build_result

    # The crash result needs to be a real object, but we need to control the
    # return value of is_crash().
    crash_result = CrashResult(1, 1, 'mock crash output')
    crash_result.is_crash = mock.Mock(return_value=True)
    self.mock.test_for_crash_with_retries.return_value = crash_result

    self.mock.test_for_reproducibility.return_value = True

    self.mock.get_value.return_value = str(reproduce._DEFAULT_TEST_TIMEOUT)  # pylint: disable=protected-access
    self.args = argparse.Namespace(testcase_id=123, config_dir='/foo')

  def test_success_crash_reproduces(self):
    """Test the full success path where the crash reproduces."""
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access

    self.mock.get_testcase_by_id.assert_called_once_with(123)
    self.mock.setup_local_fuzzer.assert_called_once()
    self.mock.setup_local_testcase.assert_called_once()
    self.mock.setup_build.assert_called_once()
    self.mock.check_for_bad_build.assert_called_once()
    self.mock.test_for_crash_with_retries.assert_called_once()
    self.mock.test_for_reproducibility.assert_called_once()
    self.mock_logs['info'].assert_any_call('The testcase reliably reproduces.')

  def test_success_crash_not_reproduces(self):
    """Test the success path where the crash does not reproduce."""
    self.mock.test_for_reproducibility.return_value = False
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock.test_for_reproducibility.assert_called_once()
    self.mock_logs['info'].assert_any_call(
        'The testcase does not reliably reproduce.')

  def test_testcase_not_found(self):
    """Test that it exits when the testcase is not found."""
    self.mock.get_testcase_by_id.return_value = None
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with(
        'Testcase with ID 123 not found.')
    self.mock.setup_local_fuzzer.assert_not_called()

  def test_job_not_found(self):
    """Test that it exits when the job is not found."""
    self.mock.query.return_value.get.return_value = None
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with(
        f'Job type {self.testcase.job_type} not found for testcase.')
    self.mock.setup_local_fuzzer.assert_not_called()

  def test_setup_fuzzer_fails(self):
    """Test that it exits when fuzzer setup fails."""
    self.mock.setup_local_fuzzer.return_value = False
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with(
        f'Failed to setup fuzzer {self.testcase.fuzzer_name}. Exiting.')
    self.mock.setup_local_testcase.assert_not_called()

  def test_setup_testcase_fails(self):
    """Test that it exits when testcase setup fails."""
    self.mock.setup_local_testcase.return_value = None
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with(
        'Could not setup testcase locally. Exiting.')
    self.mock.setup_build.assert_not_called()

  def test_setup_build_fails(self):
    """Test that it exits when build setup fails."""
    self.mock.setup_build.side_effect = Exception('mock build error')
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with(
        f'Error setting up build for revision '
        f'{self.testcase.crash_revision}: mock build error')
    self.mock.check_for_bad_build.assert_not_called()

  def test_bad_build(self):
    """Test that it exits when a bad build is detected."""
    self.mock.check_for_bad_build.return_value.is_bad_build = True
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['error'].assert_called_with('Bad build detected. Exiting.')
    self.mock.test_for_crash_with_retries.assert_not_called()

  def test_no_crash(self):
    """Test that it exits when the initial crash does not occur."""
    self.mock.test_for_crash_with_retries.return_value.is_crash.return_value = False
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['info'].assert_any_call('No crash occurred. Exiting.')
    self.mock.test_for_reproducibility.assert_not_called()

  def test_invalid_timeout_env(self):
    """Test when TEST_TIMEOUT environment variable is invalid."""
    self.mock.get_value.return_value = 'invalid'
    reproduce._reproduce_testcase(self.args)  # pylint: disable=protected-access
    self.mock_logs['warning'].assert_any_call(
        f"Invalid TEST_TIMEOUT value: invalid. "
        f"Using default: {reproduce._DEFAULT_TEST_TIMEOUT}")  # pylint: disable=protected-access
    # Check that test_for_crash_with_retries was called with default timeout
    _, kwargs = self.mock.test_for_crash_with_retries.call_args
    self.assertEqual(kwargs['test_timeout'], reproduce._DEFAULT_TEST_TIMEOUT)  # pylint: disable=protected-access


if __name__ == '__main__':
  unittest.main()
