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

import datetime
import json
import os
import unittest

from google.cloud import ndb
import mock
import parameterized
from pyfakefs import fake_filesystem_unittest

from clusterfuzz._internal.config import local_config
from clusterfuzz._internal.datastore import data_handler
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


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
    self.fs.create_file(
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
    project_config_get = local_config.ProjectConfig.get
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.default_project_name',
        'clusterfuzz._internal.config.db_config.get',
        ('project_config_get',
         'clusterfuzz._internal.config.local_config.ProjectConfig.get'),
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
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libfuzzer_binary_name',
        crash_type='Crash-type',
        crash_address='0x1337',
        crash_state='A\nB\nC\n',
        crash_revision=1337)
    self.testcase.set_metadata(
        'fuzzer_binary_name', 'binary_name', update_testcase=False)

    self.testcase_assert = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='libFuzzer',
        overridden_fuzzer_name='libfuzzer_binary_name',
        crash_type='ASSERT',
        crash_address='0x1337',
        crash_state='foo != bar\nB\nC\n',
        crash_revision=1337)
    self.testcase_assert.set_metadata(
        'fuzzer_binary_name', 'binary_name', update_testcase=False)

    self.testcase_null = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='fuzzer1',
        crash_type='UNKNOWN',
        crash_address='0x1337',
        crash_state='NULL',
        crash_revision=1337)

    self.testcase_empty = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='fuzzer2',
        crash_type='',
        crash_address='',
        crash_state='',
        crash_revision=1337)

    self.testcase_bad_cast = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='fuzzer3',
        crash_type='Bad-cast',
        crash_address='0x1337',
        crash_state=(
            'Bad-cast to blink::LayoutBlock from blink::LayoutTableSection\n'
            'blink::LayoutObject::ContainerForFixedPosition\n'
            'blink::LayoutObject::Container\n'),
        crash_revision=1337)

    self.testcase_bad_cast_without_crash_function = data_types.Testcase(
        job_type='linux_asan_chrome',
        fuzzer_name='fuzzer3',
        crash_type='Bad-cast',
        crash_address='0x1337',
        crash_state=(
            'Bad-cast to blink::LayoutBlock from blink::LayoutTableSection\n'),
        crash_revision=1337)

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
        self.testcase_empty, self.testcase_bad_cast,
        self.testcase_bad_cast_without_crash_function, self.job, self.job2,
        self.local_data_bundle, self.cloud_data_bundle, self.fuzzer1,
        self.fuzzer2, self.fuzzer3
    ]
    for entity in entities_to_put:
      entity.put()

    environment.set_value('FUZZ_DATA', '/tmp/inputs/fuzzer-common-data-bundles')
    environment.set_value('FUZZERS_DIR', '/tmp/inputs/fuzzers')
    self.mock.default_project_name.return_value = 'project'
    self.mock.project_config_get.side_effect = project_config_get

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
    self.testcase.put()

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Fuzzing Engine: libFuzzer\n'
        'Fuzz Target: binary_name\n'
        'Job Type: windows_asan_chrome\n'
        'Crash Type: Out-of-memory (exceeds 2048 MB)\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Crash Revision: https://test-clusterfuzz.appspot.com/revisions?'
        'job=windows_asan_chrome&revision=1337\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.\n\n'
        '%s' % data_handler.FILE_UNREPRODUCIBLE_TESTCASE_TEXT)

  def test_get_issue_description_timeout(self):
    """Test get_issue_description for a timeout testcase."""
    self.mock.get().name = 'chromium'

    self.testcase.crash_type = 'Timeout'
    self.testcase.crash_stacktrace = (
        'Line1\n'
        'Command: /fuzzer -rss_limit_mb=2048 -timeout=25 -max_len=10 /testcase')
    self.testcase.regression = '1337:1338'
    self.testcase.put()

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Fuzzing Engine: libFuzzer\n'
        'Fuzz Target: binary_name\n'
        'Job Type: linux_asan_chrome\n'
        'Crash Type: Timeout (exceeds 25 secs)\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Regressed: https://test-clusterfuzz.appspot.com/revisions?'
        'job=linux_asan_chrome&range=1337:1338\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.')

  def test_get_issue_description_different_project(self):
    """Test get_issue_description with a differing project name."""
    self.mock.default_project_name.return_value = 'oss-fuzz'
    self.mock.get().url = 'url'

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Project: project\n'
        'Fuzzing Engine: libFuzzer\n'
        'Fuzz Target: binary_name\n'
        'Job Type: linux_asan_chrome\n'
        'Crash Type: Crash-type\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Crash Revision: https://test-clusterfuzz.appspot.com/revisions?'
        'job=linux_asan_chrome&revision=1337\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.')

  def test_get_issue_description_blackbox_fuzzer_testcase(self):
    """Test get_issue_description with a blackbox fuzzer testcase."""
    self.mock.default_project_name.return_value = 'oss-fuzz'
    self.mock.get().url = 'url'

    description = data_handler.get_issue_description(self.testcase_null)
    self.assertEqual(
        description, 'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=3\n\n'
        'Project: project\n'
        'Fuzzer: fuzzer1\n'
        'Job Type: linux_asan_chrome\n'
        'Crash Type: UNKNOWN\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  NULL\n'
        'Sanitizer: address (ASAN)\n\n'
        'Crash Revision: https://test-clusterfuzz.appspot.com/revisions?'
        'job=linux_asan_chrome&revision=1337\n\n'
        'Reproducer Testcase: https://test-clusterfuzz.appspot.com/'
        'download?testcase_id=3\n\n'
        'See help_url for instructions to reproduce this bug locally.')

  def test_get_issue_description_additional_issue_fields(self):
    """Test get_issue_description with additional fields set in metadata."""
    self.mock.get().name = 'chromium'

    self.testcase.crash_type = 'Out-of-memory'
    self.testcase.crash_stacktrace = (
        'Line1\n'
        'Command: /fuzzer -rss_limit_mb=2048 -timeout=25 -max_len=10 /testcase')
    self.testcase.job_type = 'windows_asan_chrome'
    self.testcase.one_time_crasher_flag = True
    self.testcase.set_metadata(
        'issue_metadata', {
            'additional_fields': {
                'Acknowledgements': ['Alice', 'Bob', 'Eve', 'Mallory'],
                'Answer': 42,
            }
        })
    self.testcase.put()

    description = data_handler.get_issue_description(self.testcase)
    self.assertEqual(
        description, 'Detailed Report: https://test-clusterfuzz.appspot.com/'
        'testcase?key=1\n\n'
        'Fuzzing Engine: libFuzzer\n'
        'Fuzz Target: binary_name\n'
        'Job Type: windows_asan_chrome\n'
        'Crash Type: Out-of-memory (exceeds 2048 MB)\n'
        'Crash Address: 0x1337\n'
        'Crash State:\n  A\n  B\n  C\n  \n'
        'Sanitizer: address (ASAN)\n\n'
        'Crash Revision: https://test-clusterfuzz.appspot.com/revisions?'
        'job=windows_asan_chrome&revision=1337\n\n'
        'Reproducer Testcase: '
        'https://test-clusterfuzz.appspot.com/download?testcase_id=1\n\n'
        'See help_url for instructions to reproduce this bug locally.\n\n'
        '%s\n\n'
        'Acknowledgements: [\'Alice\', \'Bob\', \'Eve\', \'Mallory\']\n'
        'Answer: 42' % data_handler.FILE_UNREPRODUCIBLE_TESTCASE_TEXT)

  def test_get_issue_summary_with_no_prefix(self):
    """Test get_issue_description on jobs with no prefix."""
    self.job.environment_string = 'HELP_URL = help_url\n'
    self.job.put()
    summary = data_handler.get_issue_summary(self.testcase_assert)
    self.assertEqual(summary, 'binary_name: ASSERT: foo != bar')

    summary = data_handler.get_issue_summary(self.testcase)
    self.assertEqual(summary, 'binary_name: Crash-type in A')

  def test_get_issue_summary_with_non_project_prefix(self):
    """Test get_issue_description on jobs with prefix not equal to project."""
    self.job.environment_string = ('SUMMARY_PREFIX = prefix\n'
                                   'HELP_URL = help_url\n')
    self.job.put()
    summary = data_handler.get_issue_summary(self.testcase_assert)
    self.assertEqual(summary, 'prefix:binary_name: ASSERT: foo != bar')

    summary = data_handler.get_issue_summary(self.testcase)
    self.assertEqual(summary, 'prefix:binary_name: Crash-type in A')

  def test_get_issue_summary_with_project_prefix(self):
    """Test get_issue_description with project name as prefix."""
    summary = data_handler.get_issue_summary(self.testcase_assert)
    self.assertEqual(summary, 'project:binary_name: ASSERT: foo != bar')

    summary = data_handler.get_issue_summary(self.testcase)
    self.assertEqual(summary, 'project:binary_name: Crash-type in A')

  def test_get_issue_summary_null(self):
    """Test get_issue_summary for null crash state."""
    summary = data_handler.get_issue_summary(self.testcase_null)
    self.assertEqual(summary, 'project: Crash with empty stacktrace')

  def test_get_issue_summary_empty(self):
    """Test get_issue_summary for empty crash state and empty crash type."""
    summary = data_handler.get_issue_summary(self.testcase_empty)
    self.assertEqual(summary, 'project: Unknown error with empty stacktrace')

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

  def test_get_data_bundle_name_default(self):
    """Test getting the default data bundle bucket name."""
    self.assertEqual('test-corpus.test-clusterfuzz.appspot.com',
                     data_handler.get_data_bundle_bucket_name('test'))

  def test_get_data_bundle_name_custom_suffix(self):
    """Test getting the data bundle bucket name with custom suffix."""
    self.mock.project_config_get.side_effect = None
    self.mock.project_config_get.return_value = 'custom.suffix.com'
    self.assertEqual('test-corpus.custom.suffix.com',
                     data_handler.get_data_bundle_bucket_name('test'))


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
        'clusterfuzz._internal.crash_analysis.severity_analyzer.get_security_severity',
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


class UpdateTestcaseCommentTest(unittest.TestCase):
  """Update testcase comment tests."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.current_date_time',
    ])

    os.environ['BOT_NAME'] = 'bot'
    os.environ['TASK_NAME'] = 'progression'
    self.testcase = mock.Mock()
    self.testcase.comments = ''
    self.mock.current_date_time.return_value = datetime.datetime(2019, 1, 1)

  def test_update_comment_empty(self):
    """Basic test on a testcase with empty comments."""
    data_handler.update_testcase_comment(
        self.testcase, data_types.TaskState.STARTED, 'message')
    self.assertEqual(
        '[2019-01-01 00:00:00] bot: Progression task started: message.\n',
        self.testcase.comments)

  def test_update_comment_clear(self):
    """Basic test on a testcase with existing comments, and clearing old
    progression messages."""
    self.testcase.comments = (
        '[2018-01-01 00:00:00] bot: Foo.\n'
        '[2018-01-01 00:00:00] bot: Progression task started: message.\n'
        '[2018-01-01 00:00:00] bot: Bar.\n'
        '[2018-01-01 00:00:00] bot: Progression task finished.\n'
        '[2018-01-01 00:00:00] bot: Blah.\n')
    data_handler.update_testcase_comment(
        self.testcase, data_types.TaskState.STARTED, 'message')
    self.assertEqual(
        ('[2018-01-01 00:00:00] bot: Foo.\n'
         '[2018-01-01 00:00:00] bot: Bar.\n'
         '[2018-01-01 00:00:00] bot: Blah.\n'
         '[2019-01-01 00:00:00] bot: Progression task started: message.\n'),
        self.testcase.comments)

  def test_update_comment_truncate(self):
    """Test truncating long comments."""
    self.testcase.comments = '\n' * data_types.TESTCASE_COMMENTS_LENGTH_LIMIT
    data_handler.update_testcase_comment(
        self.testcase, data_types.TaskState.STARTED, 'message')

    self.assertEqual(data_types.TESTCASE_COMMENTS_LENGTH_LIMIT,
                     len(self.testcase.comments))
    expected_new = (
        '[2019-01-01 00:00:00] bot: Progression task started: message.\n')
    expected = (
        '\n' * (data_types.TESTCASE_COMMENTS_LENGTH_LIMIT - len(expected_new)) +
        expected_new)
    self.assertEqual(expected, self.testcase.comments)


@test_utils.with_cloud_emulators('datastore')
class GetFormattedReproductionHelpTest(unittest.TestCase):
  """Test get_formatted_reproduction_help."""

  def setUp(self):
    helpers.patch_environ(self)

    job = data_types.Job()
    job.name = 'job_with_help_format'
    job.environment_string = (
        'HELP_FORMAT = -%TESTCASE%\\n-%FUZZER_NAME%\\n-%FUZZ_TARGET%\\n'
        '-%PROJECT%\\n-%REVISION%\\n-%ENGINE%\\n-%SANITIZER%\\n%ARGS%\\n'
        '%SANITIZER_OPTIONS%\n'
        'PROJECT_NAME = test_project')
    job.put()

    job = data_types.Job()
    job.name = 'ubsan_job_without_help_format'
    job.environment_string = (
        'PROJECT_NAME = test_project\n'
        'APP_ARGS = '
        '--disable-logging --disable-experiments --testcase=%TESTCASE_HTTP_URL%'
    )
    job.put()

    fuzz_target = data_types.FuzzTarget(id='libFuzzer_test_project_test_fuzzer')
    fuzz_target.binary = 'test_fuzzer'
    fuzz_target.project = 'test_project'
    fuzz_target.engine = 'libFuzzer'
    fuzz_target.put()

  def test_libfuzzer_testcase(self):
    """Test the function with a libFuzzer test case."""
    testcase = data_types.Testcase()
    testcase.fuzzer_name = 'libFuzzer'
    testcase.overridden_fuzzer_name = 'libFuzzer_test_project_test_fuzzer'
    testcase.job_type = 'job_with_help_format'
    testcase.crash_revision = 1337
    testcase.minimized_arguments = '%TESTCASE% test_fuzzer -runs=100'
    testcase.put()

    self.assertEqual(
        data_handler.get_formatted_reproduction_help(testcase),
        ('-{id}\n-libFuzzer\n-test_fuzzer\n-test_project\n-1337\n'
         '-libFuzzer\n-ASAN\n-runs=100\n').format(id=testcase.key.id()))

  def test_blackbox_fuzzer_testcase(self):
    """Test the function with a blackbox fuzzer test case."""
    testcase = data_types.Testcase()
    testcase.fuzzer_name = 'simple_fuzzer'
    testcase.job_type = 'job_with_help_format'
    testcase.crash_revision = 1337
    testcase.minimized_arguments = '--disable-logging %TESTCASE_FILE_URL%'
    testcase.put()
    testcase.set_metadata('last_tested_crash_revision', 1338)

    self.assertEqual(
        data_handler.get_formatted_reproduction_help(testcase),
        ('-{id}\n-simple_fuzzer\n-NA\n-test_project\n-1338\n'
         '-NA\n-ASAN\n--disable-logging\n').format(id=testcase.key.id()))

  def test_blackbox_fuzzer_testcase_with_default_help_format(self):
    """Test the function with a blackbox fuzzer test case, with HELP_FORMAT
    set in environment."""
    environment.set_value(
        'HELP_FORMAT',
        '-%TESTCASE%\\n-%FUZZER_NAME%\\n-%FUZZ_TARGET%\\n-%PROJECT%\\n'
        '-%REVISION%\\n-%ENGINE%\\n-%SANITIZER%\\n%ARGS%\\n'
        '%SANITIZER_OPTIONS% ./binary')

    testcase = data_types.Testcase()
    testcase.fuzzer_name = 'simple_fuzzer'
    testcase.job_type = 'ubsan_job_without_help_format'
    testcase.crash_revision = 1337
    testcase.put()

    testcase.set_metadata(
        'env', {
            'ASAN_OPTIONS': {
                'handle_abort': 1,
                'symbolize': 0,
                'redzone': 512,
            },
            'UBSAN_OPTIONS': {
                'halt_on_error': 1,
                'symbolize': 0,
            },
            'OTHER_OPTIONS': {
                'symbolize': 1
            }
        })

    self.assertEqual(
        data_handler.get_formatted_reproduction_help(testcase),
        ('-{id}\n-simple_fuzzer\n-NA\n-test_project\n-1337\n'
         '-NA\n-UBSAN\n--disable-logging --disable-experiments\n'
         'ASAN_OPTIONS="handle_abort=1:redzone=512" '
         'UBSAN_OPTIONS="halt_on_error=1" ./binary'
        ).format(id=testcase.key.id()))

  def test_bazel_test_args(self):
    """Test bazel test args with a libFuzzer test case"""
    environment.set_value('HELP_FORMAT', 'bazel test %BAZEL_TEST_ARGS%')

    testcase = data_types.Testcase()
    testcase.fuzzer_name = 'libFuzzer'
    testcase.overridden_fuzzer_name = 'libFuzzer_test_project_test_fuzzer'
    testcase.job_type = 'ubsan_job_without_help_format'
    testcase.crash_revision = 1337
    testcase.minimized_arguments = (
        '%TESTCASE% test_fuzzer -arg1=val1 -arg2="val2 val3"')
    testcase.put()

    testcase.set_metadata(
        'env', {
            'ASAN_OPTIONS': {
                'handle_abort': 1,
                'symbolize': 0,
                'redzone': 512,
            },
            'UBSAN_OPTIONS': {
                'halt_on_error': 1,
                'symbolize': 0,
            },
            'OTHER_OPTIONS': {
                'symbolize': 1
            }
        })

    self.assertEqual(
        data_handler.get_formatted_reproduction_help(testcase), 'bazel test '
        '--test_env=ASAN_OPTIONS="handle_abort=1:redzone=512" '
        '--test_env=UBSAN_OPTIONS="halt_on_error=1" '
        '--test_arg=-arg1=val1 '
        '--test_arg=\'-arg2=val2 val3\'')

  def test_multi_target_binary(self):
    """Test multi target binaries."""
    fuzz_target = data_types.FuzzTarget()
    fuzz_target.binary = 'base_fuzzer@blah'
    fuzz_target.project = 'test_project'
    fuzz_target.engine = 'googlefuzztest'
    fuzz_target.put()
    environment.set_value('HELP_FORMAT', '%BASE_FUZZ_TARGET%\n%FUZZ_TEST_NAME%')

    testcase = data_types.Testcase()
    testcase.fuzzer_name = 'googlefuzztest'
    testcase.job_type = 'jobtype'
    testcase.overridden_fuzzer_name = 'googlefuzztest_test_project_base_fuzzer-blah'
    testcase.put()

    self.assertEqual(
        data_handler.get_formatted_reproduction_help(testcase),
        'base_fuzzer\nblah')


@test_utils.with_cloud_emulators('datastore')
class RecordFuzzTargetTest(unittest.TestCase):
  """Tests for record_fuzz_target."""

  def setUp(self):
    helpers.patch_environ(self)
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.is_oss_fuzz',
        'clusterfuzz._internal.base.utils.utcnow',
    ])

    self.mock.is_oss_fuzz.return_value = False
    self.mock.utcnow.return_value = datetime.datetime(2018, 1, 1)

  def test_record_fuzz_target(self):
    """Test that record_fuzz_target works."""
    data_handler.record_fuzz_target('libFuzzer', 'child', 'job')
    fuzz_target = ndb.Key(data_types.FuzzTarget, 'libFuzzer_child').get()
    self.assertDictEqual({
        'binary': 'child',
        'engine': 'libFuzzer',
        'project': 'test-project',
    }, fuzz_target.to_dict())

    job_mapping = ndb.Key(data_types.FuzzTargetJob, 'libFuzzer_child/job').get()
    self.assertDictEqual({
        'fuzz_target_name': 'libFuzzer_child',
        'job': 'job',
        'engine': 'libFuzzer',
        'last_run': datetime.datetime(2018, 1, 1, 0, 0),
        'weight': 1.0,
    }, job_mapping.to_dict())

    self.assertEqual('libFuzzer_child', fuzz_target.fully_qualified_name())
    self.assertEqual('child', fuzz_target.project_qualified_name())

  def test_record_fuzz_target_existing(self):
    """Test that record_fuzz_target works when updating an existing entity."""
    data_types.FuzzTarget(
        binary='child', engine='libFuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_child',
        job='job',
        engine='libFuzzer',
        last_run=datetime.datetime(2017, 12, 31, 0, 0)).put()

    data_handler.record_fuzz_target('libFuzzer', 'child', 'job')
    fuzz_target = ndb.Key(data_types.FuzzTarget, 'libFuzzer_child').get()
    self.assertDictEqual({
        'binary': 'child',
        'engine': 'libFuzzer',
        'project': 'test-project',
    }, fuzz_target.to_dict())

    job_mapping = ndb.Key(data_types.FuzzTargetJob, 'libFuzzer_child/job').get()
    self.assertDictEqual({
        'fuzz_target_name': 'libFuzzer_child',
        'job': 'job',
        'engine': 'libFuzzer',
        'last_run': datetime.datetime(2018, 1, 1, 0, 0),
        'weight': 1.0,
    }, job_mapping.to_dict())

    self.assertEqual('libFuzzer_child', fuzz_target.fully_qualified_name())
    self.assertEqual('child', fuzz_target.project_qualified_name())

  def test_record_fuzz_target_no_binary_name(self):
    """Test recording fuzz target with no binary."""
    # Passing None to binary_name is an error. We shouldn't create any
    # FuzzTargets as a result.
    data_handler.record_fuzz_target('libFuzzer', None, 'job')
    fuzz_target = ndb.Key(data_types.FuzzTarget, 'libFuzzer_child').get()
    self.assertIsNone(fuzz_target)

    job_mapping = ndb.Key(data_types.FuzzTargetJob, 'libFuzzer_child/job').get()
    self.assertIsNone(job_mapping)

  @parameterized.parameterized.expand(['child', 'proj_child'])
  def test_record_fuzz_target_ossfuzz(self, binary_name):
    """Test that record_fuzz_target works with OSS-Fuzz projects."""
    self.mock.is_oss_fuzz.return_value = True
    data_types.Job(name='job', environment_string='PROJECT_NAME = proj\n').put()

    data_handler.record_fuzz_target('libFuzzer', binary_name, 'job')
    fuzz_target = ndb.Key(data_types.FuzzTarget, 'libFuzzer_proj_child').get()
    self.assertDictEqual({
        'binary': binary_name,
        'engine': 'libFuzzer',
        'project': 'proj',
    }, fuzz_target.to_dict())

    job_mapping = ndb.Key(data_types.FuzzTargetJob,
                          'libFuzzer_proj_child/job').get()
    self.assertDictEqual({
        'fuzz_target_name': 'libFuzzer_proj_child',
        'job': 'job',
        'engine': 'libFuzzer',
        'last_run': datetime.datetime(2018, 1, 1, 0, 0),
        'weight': 1.0,
    }, job_mapping.to_dict())

    self.assertEqual('libFuzzer_proj_child', fuzz_target.fully_qualified_name())
    self.assertEqual('proj_child', fuzz_target.project_qualified_name())
