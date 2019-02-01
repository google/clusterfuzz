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
"""Tests for data_handler."""

import json
import os
import unittest

import mock
from pyfakefs import fake_filesystem_unittest

from datastore import data_handler
from datastore import data_types
from issue_management import issue
from system import environment
from tests.test_libs import helpers
from tests.test_libs import test_utils


class SetInitialTestcaseMetadata(fake_filesystem_unittest.TestCase):
  """Tests for set_initial_testcase_metadata."""

  def setUp(self):
    test_utils.set_up_pyfakefs(self)
    helpers.patch_environ(self)

  def test_set(self):
    """Test set everything."""
    os.environ['FAIL_RETRIES'] = '3'
    os.environ['FAIL_WAIT'] = '3'
    os.environ['BUILD_KEY'] = 'build_key_value'
    os.environ['BUILD_KEY'] = 'build_key_value'
    os.environ['BUILD_URL'] = 'build_url_value'
    os.environ['APP_DIR'] = 'app_dir_value'
    os.environ['GN_ARGS_PATH'] = 'app_dir_value/args.gn'
    self.fs.CreateFile(
        'app_dir_value/args.gn',
        contents=('is_asan = true\n'
                  'goma_dir = /home/user/goma\n'
                  'use_goma = true\n'
                  'v8_enable_verify_heap = true'))

    testcase = data_types.Testcase()
    data_handler.set_initial_testcase_metadata(testcase)

    metadata = json.loads(testcase.additional_metadata)
    self.assertEqual('build_key_value', metadata['build_key'])
    self.assertEqual('build_url_value', metadata['build_url'])
    self.assertEqual(
        'is_asan = true\nuse_goma = true\nv8_enable_verify_heap = true',
        metadata['gn_args'])


@test_utils.with_cloud_emulators('datastore')
class DataHandlerTest(unittest.TestCase):
  """Tests for various data_handler functions."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'base.utils.default_project_name',
        'config.db_config.get',
    ])

    self.job = data_types.Job(
        name='linux_asan_chrome',
        environment_string=('SUMMARY_PREFIX = project\n'
                            'PROJECT_NAME = project\n'
                            'HELP_URL = help_url\n'))
    self.job2 = data_types.Job(
        name='windows_asan_chrome',
        environment_string=('SUMMARY_PREFIX = project\n'
                            'PROJECT_NAME = project\n'
                            'HELP_URL = help_url\n'))
    self.testcase = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libfuzzer_binary_name',
        crash_type='Crash-type',
        crash_address='0x1337',
        crash_state='A\nB\nC\n')
    self.testcase.set_metadata(
        'fuzzer_binary_name', 'binary_name', update_testcase=False)

    self.testcase_assert = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libfuzzer_binary_name',
        crash_type='ASSERT',
        crash_address='0x1337',
        crash_state='foo != bar\nB\nC\n')
    self.testcase_assert.set_metadata(
        'fuzzer_binary_name', 'binary_name', update_testcase=False)

    self.testcase_null = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libfuzzer_binary_name',
        crash_type='UNKNOWN',
        crash_address='0x1337',
        crash_state='NULL')

    self.testcase_bad_cast = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libfuzzer_binary_name',
        crash_type='Bad-cast',
        crash_address='0x1337',
        crash_state=(
            'Bad-cast to blink::LayoutBlock from blink::LayoutTableSection\n'
            'blink::LayoutObject::ContainerForFixedPosition\n'
            'blink::LayoutObject::Container\n'))

    self.testcase_bad_cast_without_crash_function = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libfuzzer_binary_name',
        crash_type='Bad-cast',
        crash_address='0x1337',
        crash_state=(
            'Bad-cast to blink::LayoutBlock from blink::LayoutTableSection\n'))

    self.local_data_bundle = data_types.DataBundle(name='local_data_bundle')
    self.cloud_data_bundle = data_types.DataBundle(name='cloud_data_bundle')

    self.fuzzer1 = data_types.Fuzzer(
        name='fuzzer1', data_bundle_name=None, jobs=['linux_asan_chrome'])
    self.fuzzer2 = data_types.Fuzzer(
        name='fuzzer2',
        data_bundle_name='local_data_bundle',
        jobs=['linux_asan_chrome'])
    self.fuzzer3 = data_types.Fuzzer(
        name='fuzzer3',
        data_bundle_name='cloud_data_bundle',
        jobs=['linux_asan_chrome'])

    entities_to_put = [
        self.testcase, self.testcase_assert, self.testcase_null,
        self.testcase_bad_cast, self.testcase_bad_cast_without_crash_function,
        self.job, self.job2, self.local_data_bundle, self.cloud_data_bundle,
        self.fuzzer1, self.fuzzer2, self.fuzzer3
    ]
    for entity in entities_to_put:
      entity.put()

    environment.set_value('FUZZ_DATA', '/tmp/inputs/fuzzer-common-data-bundles')
    environment.set_value('FUZZERS_DIR', '/tmp/inputs/fuzzers')
    self.mock.default_project_name.return_value = 'project'

  def test_find_testcase(self):
    """Ensure that find_testcase behaves as expected."""
    crash_type = 'find_testcase_test_type'
    crash_state = 'find_testcase_test_state'
    security_flag = True

    nonsecurity = test_utils.create_generic_testcase()

    reproducible_with_bug = test_utils.create_generic_testcase()
    reproducible_with_bug.bug_information = '123456'
    reproducible_with_bug.one_time_crasher_flag = False

    reproducible_no_bug = test_utils.create_generic_testcase()
    reproducible_no_bug.bug_information = ''
    reproducible_no_bug.one_time_crasher_flag = False

    unreproducible_with_bug = test_utils.create_generic_testcase()
    unreproducible_with_bug.bug_information = '123456'
    unreproducible_with_bug.one_time_crasher_flag = True

    unreproducible_no_bug = test_utils.create_generic_testcase()
    unreproducible_no_bug.bug_information = ''
    unreproducible_no_bug.one_time_crasher_flag = True

    testcases = [
        nonsecurity,
        reproducible_with_bug,
        reproducible_no_bug,
        unreproducible_with_bug,
        unreproducible_no_bug,
    ]

    # Apply generic information to each test case, and put.
    for testcase in testcases:
      testcase.crash_type = crash_type
      testcase.crash_state = crash_state
      testcase.security_flag = security_flag
      testcase.put()

    # We also want to test one non-security issue, so update it.
    nonsecurity.security_flag = False
    nonsecurity.put()

    # Ensure that we don't return anything if we search for an unused state or
    # type.
    self.assertIsNone(
        data_handler.find_testcase('project', crash_type, 'missing_state',
                                   security_flag))
    self.assertIsNone(
        data_handler.find_testcase('project', 'missing type', crash_state,
                                   security_flag))

    # Ensure that we respect security flag when searching.
    result = data_handler.find_testcase('project', crash_type, crash_state,
                                        False)
    self.assertTrue(test_utils.entities_equal(result, nonsecurity))

    # Ensure that we properly prioritize issues.
    no_constraint_result = data_handler.find_testcase(
        'project', crash_type, crash_state, security_flag)
    self.assertTrue(
        test_utils.entities_equal(no_constraint_result, reproducible_with_bug))

    # Favor reproducibility over having a bug filed, and ensure that test cases
    # can be excluded from results.
    exclude_result = data_handler.find_testcase(
        'project',
        crash_type,
        crash_state,
        security_flag,
        testcase_to_exclude=reproducible_with_bug)
    self.assertTrue(
        test_utils.entities_equal(exclude_result, reproducible_no_bug))

  def test_get_issue_description_oom(self):
    """Test get_issue_description for an oom testcase."""
    self.mock.get().name = 'chromium'

    self.testcase.crash_type = 'Out-of-memory'
    self.testcase.crash_stacktrace = (
        'Line1\n'
        'Command: /fuzzer -rss_limit_mb=2048 -timeout=25 -max_len=10 /testcase')
    self.testcase.job_type = 'windows_asan_chrome'
    self.testcase.one_time_crasher_flag = True
    self.testcase.second_crash_stacktrace = 'No crash using abc job type.'
    self.testcase.put()

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Fuzzer: libfuzzer_binary_name\n'
        'Fuzz target binary: binary_name\n'
        'Job Type: windows_asan_chrome\n'
        'Crash Type: Out-of-memory (exceeds 2048 MB)\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'No crash using abc job type.\n\n'
        'See help_url for instructions to reproduce this bug locally.\n\n'
        '%s' % data_handler.FILE_UNREPRODUCIBLE_TESTCASE_TEXT)

  def test_get_issue_description_timeout(self):
    """Test get_issue_description for a timeout testcase."""
    self.mock.get().name = 'chromium'

    self.testcase.crash_type = 'Timeout'
    self.testcase.crash_stacktrace = (
        'Line1\n'
        'Command: /fuzzer -rss_limit_mb=2048 -timeout=25 -max_len=10 /testcase')
    self.testcase.put()

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Fuzzer: libfuzzer_binary_name\n'
        'Fuzz target binary: binary_name\n'
        'Job Type: linux_asan_chrome\n'
        'Crash Type: Timeout (exceeds 25 secs)\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.')

  def test_get_issue_description_different_project(self):
    """Test get_issue_description with a differing project name."""
    self.mock.default_project_name.return_value = 'oss-fuzz'
    self.mock.get().url = 'url'

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Project: project\n'
        'Fuzzer: libfuzzer_binary_name\n'
        'Fuzz target binary: binary_name\n'
        'Job Type: linux_asan_chrome\n'
        'Crash Type: Crash-type\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.')

  def test_get_issue_summary_no_project(self):
    """Test get_issue_description on jobs with no project."""
    self.job.environment_string = ('SUMMARY_PREFIX = prefix\n'
                                   'HELP_URL = help_url\n')
    self.job.put()
    summary = data_handler.get_issue_summary(self.testcase_assert)
    self.assertEqual(summary, 'prefix: ASSERT: foo != bar')

    summary = data_handler.get_issue_summary(self.testcase)
    self.assertEqual(summary, 'prefix: Crash-type in A')

  def test_get_issue_summary(self):
    """Test get_issue_description."""
    summary = data_handler.get_issue_summary(self.testcase_assert)
    self.assertEqual(summary, 'project/binary_name: ASSERT: foo != bar')

    summary = data_handler.get_issue_summary(self.testcase)
    self.assertEqual(summary, 'project/binary_name: Crash-type in A')

  def test_get_issue_summary_null(self):
    """Test get_issue_summary for null crash state."""
    summary = data_handler.get_issue_summary(self.testcase_null)
    self.assertEqual(summary, 'project: NULL')

  def test_get_issue_summary_bad_cast(self):
    """Test get_issue_summary for bad cast."""
    summary = data_handler.get_issue_summary(self.testcase_bad_cast)
    self.assertEqual(
        summary, 'project: Bad-cast to blink::LayoutBlock from '
        'blink::LayoutTableSection in '
        'blink::LayoutObject::ContainerForFixedPosition')

  def test_get_issue_summary_bad_cast_without_crash_function(self):
    """Test get_issue_summary for bad cast without crash function."""
    summary = data_handler.get_issue_summary(
        self.testcase_bad_cast_without_crash_function)
    self.assertEqual(
        summary, 'project: Bad-cast to blink::LayoutBlock from '
        'blink::LayoutTableSection')


@test_utils.with_cloud_emulators('datastore')
class AddBuildMetadataTest(unittest.TestCase):
  """Test add_build_metadata."""

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['BOT_NAME'] = 'bot'

  def _test(self, is_bad_build):
    """Test."""
    data_handler.add_build_metadata(
        job_type='job',
        is_bad_build=is_bad_build,
        crash_revision=1234,
        console_output='console')

    builds = list(data_types.BuildMetadata.query())
    self.assertEqual(1, len(builds))
    self.assertEqual(is_bad_build, builds[0].bad_build)
    self.assertEqual('bot', builds[0].bot_name)
    self.assertEqual('console', builds[0].console_output)
    self.assertEqual('job', builds[0].job_type)
    self.assertEqual(1234, builds[0].revision)

  def test_good(self):
    """Test good build."""
    self._test(True)

  def test_bad(self):
    """Test bad build."""
    self._test(False)


@test_utils.with_cloud_emulators('datastore')
class GetIssueTrackerNameTest(unittest.TestCase):
  """Test get_issue_tracker_name."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_get_from_job(self):
    """Test getting from job."""
    data_types.Job(
        name='job',
        environment_string=('ISSUE_TRACKER = from_job\n'
                            'HELP_URL = help_url\n')).put()
    self.assertEqual('from_job', data_handler.get_issue_tracker_name('job'))

  def test_get_default(self):
    """Test getting default issue tracker."""
    os.environ['ISSUE_TRACKER'] = 'test-issue-tracker'
    self.assertEqual('test-issue-tracker',
                     data_handler.get_issue_tracker_name('job'))


@test_utils.with_cloud_emulators('datastore')
class GetProjectNameTest(unittest.TestCase):
  """Test get_project_name."""

  def setUp(self):
    helpers.patch_environ(self)

  def test_get_from_job(self):
    """Test getting from job."""
    data_types.Job(
        name='job',
        environment_string=('PROJECT_NAME = from_internal_project\n'
                            'HELP_URL = help_url\n')).put()
    self.assertEqual('from_internal_project',
                     data_handler.get_project_name('job'))

  def test_get_from_default(self):
    """Test getting from local config."""
    self.assertEqual('test-project', data_handler.get_project_name('job'))


class GetSecuritySeverityTest(unittest.TestCase):
  """Test _get_security_severity."""

  def setUp(self):
    helpers.patch(self, [
        'crash_analysis.severity_analyzer.get_security_severity',
    ])
    self.gestures = ''
    self.mock.get_security_severity.return_value = 'Low'
    self.crash = mock.Mock(
        crash_type='type', crash_stacktrace='trace', security_flag=False)

  def test_none(self):
    """Test when security_flag is False."""
    self.crash.security_flag = False
    result = data_handler._get_security_severity(  # pylint: disable=protected-access
        self.crash, 'job', self.gestures)
    self.assertIsNone(result)
    self.assertEqual(0, self.mock.get_security_severity.call_count)

  def test_get(self):
    """Test when security_flag is True."""
    self.crash.security_flag = True
    result = data_handler._get_security_severity(  # pylint: disable=protected-access
        self.crash, 'job', self.gestures)

    self.assertEqual('Low', result)
    self.mock.get_security_severity.assert_called_with('type', 'trace', 'job',
                                                       False)


@test_utils.with_cloud_emulators('datastore')
class UpdateImpactTest(unittest.TestCase):
  """Update impact tests."""

  def _make_mock_issue(self):
    mock_issue = mock.Mock(autospec=issue.Issue)
    mock_issue.labels = []

    return mock_issue

  def setUp(self):
    helpers.patch_environ(self)
    self.testcase = data_types.Testcase()
    self.testcase.one_time_crasher_flag = False

  def test_update_impact_stable_from_regression(self):
    """Tests updating impact to Stable from the regression range."""
    self.testcase.regression = '0:1000'
    mock_issue = self._make_mock_issue()

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_called_with('Security_Impact-Stable')
    mock_issue.remove_label.assert_not_called()

  def test_update_impact_stable(self):
    """Tests updating impact to Stable."""
    self.testcase.is_impact_set_flag = True
    self.testcase.impact_stable_version = 'Stable'

    mock_issue = self._make_mock_issue()

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_called_with('Security_Impact-Stable')
    mock_issue.remove_label.assert_not_called()

  def test_update_impact_beta(self):
    """Tests updating impact to Beta."""
    self.testcase.is_impact_set_flag = True
    self.testcase.impact_beta_version = 'Beta'

    mock_issue = self._make_mock_issue()

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_called_with('Security_Impact-Beta')
    mock_issue.remove_label.assert_not_called()

  def test_update_impact_head(self):
    """Tests updating impact to Head."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_called_with('Security_Impact-Head')
    mock_issue.remove_label.assert_not_called()

  def test_no_impact(self):
    """Tests no impact."""
    mock_issue = self._make_mock_issue()

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_not_called()
    mock_issue.remove_label.assert_not_called()

  def test_replace_impact(self):
    """Tests replacing impact."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()
    mock_issue.labels = ['Security_Impact-Beta']

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_called_with('Security_Impact-Head')
    mock_issue.remove_label.assert_called_with('Security_Impact-Beta')

  def test_replace_same_impact(self):
    """Tests replacing same impact."""
    self.testcase.is_impact_set_flag = True

    mock_issue = self._make_mock_issue()
    mock_issue.labels = ['Security_Impact-Head']

    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_not_called()
    mock_issue.remove_label.assert_not_called()

  def test_component_dont_add_label(self):
    """Test that we don't set labels for component builds."""
    self.testcase.job_type = 'job'
    self.testcase.put()

    data_types.Job(
        name='job',
        environment_string=(
            'RELEASE_BUILD_BUCKET_PATH = '
            'https://example.com/blah-v8-component-([0-9]+).zip\n')).put()

    self.testcase.is_impact_set_flag = True
    mock_issue = self._make_mock_issue()
    data_handler.update_issue_impact_labels(self.testcase, mock_issue)
    mock_issue.add_label.assert_not_called()
    mock_issue.remove_label.assert_not_called()
