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
"""Tests for crash uploader functions."""

import os
import socket
import unittest
import urllib.parse

import mock

from clusterfuzz._internal.chrome import crash_uploader
from clusterfuzz._internal.crash_analysis.stack_parsing import stack_analyzer
from clusterfuzz._internal.protos import process_state_pb2
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import process_handler
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

DATA_DIRECTORY = os.path.join(os.path.dirname(__file__), 'crash_uploader_data')

# CrashReportInfo test variables.
# On crash, Android devices store a MIME containing the crash minidump as well
# as other information needed for chromecrash upload. This file is written to a
# .dmp file, suffixed by the PID to distinguish it from the minidump file
# itself.
SAMPLE_MIME_FILENAME = 'android_mime_minidump'
SAMPLE_MIME_PATH = os.path.join(DATA_DIRECTORY,
                                '%s.mime' % SAMPLE_MIME_FILENAME)
EXPECTED_DMP_PATH = os.path.join(DATA_DIRECTORY,
                                 'android_parsed_minidump_expected.dmp')
ACTUAL_DMP_PATH = os.path.join(DATA_DIRECTORY, '%s.dmp' % SAMPLE_MIME_FILENAME)
EXPECTED_PROCESSED_REPORT_PATH = os.path.join(
    DATA_DIRECTORY, 'expected_processed_report_bytes')
SAMPLE_OUTPUT = open(
    os.path.join(DATA_DIRECTORY, 'android_crash_stack_output'), 'r').read()
SAMPLE_OUTPUT_TO_PARSE = open(
    os.path.join(DATA_DIRECTORY, 'crash_output_to_parse'), 'r').read()
EXPECTED_REPORT_INFO = crash_uploader.CrashReportInfo(
    minidump_path=ACTUAL_DMP_PATH,
    product='Chrome_Android',
    version='46.0.2482.0')

# Environment variables.
TEST_JOB_NAME = 'android_asan_chrome_l'
TEST_OS = 'android'
TEST_FAIL_RETRIES = '4'
TEST_BOT_TMPDIR = DATA_DIRECTORY
TEST_CRASH_STACKTRACES_DIR = DATA_DIRECTORY


class CrashBaseTest(unittest.TestCase):
  """Base for setup, teardown of crash report processing tests."""

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(self, [
        'clusterfuzz._internal.crash_analysis.stack_parsing.stack_symbolizer.filter_binary_path'
    ])

    # For Android, skip symbolization as real device is unavailable.
    self.mock.filter_binary_path.return_value = ''

    os.environ['APP_NAME'] = 'chrome'
    os.environ['BOT_TMPDIR'] = TEST_BOT_TMPDIR
    os.environ['CRASH_STACKTRACES_DIR'] = TEST_CRASH_STACKTRACES_DIR
    os.environ['FAIL_RETRIES'] = TEST_FAIL_RETRIES
    os.environ['JOB_NAME'] = TEST_JOB_NAME
    os.environ['OS_OVERRIDE'] = TEST_OS
    os.environ['UPLOAD_MODE'] = 'staging'

  def tearDown(self):
    if self.needs_file_delete:
      os.remove(ACTUAL_DMP_PATH)


class CrashReportsTest(CrashBaseTest):
  """Crash report processing tests."""

  def _validate_dmp_contents(self, my_expected_dmp_path, my_actual_dmp_path):
    """Check dmp contents at given path are as expected."""
    try:
      expected_dmp_file_contents = open(my_expected_dmp_path, 'rb').read()
      actual_dmp_file_contents = open(my_actual_dmp_path, 'rb').read()
      self.assertEqual(actual_dmp_file_contents, expected_dmp_file_contents)
    except IOError:
      self.fail('Could not find processed %s or %s.' % (my_expected_dmp_path,
                                                        my_actual_dmp_path))

  def _validate_report_fields(self, my_expected_report_info,
                              my_actual_report_info):
    """Check CrashReportInfo object created correctly."""
    # Only check fields the uploader will need (e.g. we don't care so much
    # about un/symbolized stacktraces.
    self.assertEqual(my_actual_report_info.minidump_info.path,
                     my_expected_report_info.minidump_info.path)
    self.assertEqual(my_actual_report_info.serialized_crash_stack_frames,
                     my_expected_report_info.serialized_crash_stack_frames)
    self.assertEqual(my_actual_report_info.product,
                     my_expected_report_info.product)
    self.assertEqual(my_actual_report_info.version,
                     my_expected_report_info.version)

  @test_utils.supported_platforms('LINUX')
  def test_parse_output_to_processed_report(self):
    """Tests if given output parses to the expected symbolized stack bytes."""
    self.needs_file_delete = False
    state = stack_analyzer.get_crash_data(SAMPLE_OUTPUT_TO_PARSE)
    actual_report_bytes = crash_uploader.get_symbolized_stack_bytes(
        state.crash_type, state.crash_address, state.frames)
    with open(EXPECTED_PROCESSED_REPORT_PATH, 'rb') as expected_report:
      expected_report_bytes = expected_report.read()

    self.assertEqual(actual_report_bytes, expected_report_bytes)

  def test_parse_output_to_processed_report_bad_stack(self):
    """Tests if given bad stack fails to parse to a processed report."""
    self.needs_file_delete = False
    actual_report_bytes = crash_uploader.get_symbolized_stack_bytes(
        'reason', 12345, [None])
    self.assertIsNone(actual_report_bytes)

  def test_parse_output_to_processed_report_big_addresses(self):
    """Tests that given output with big addresses prototizes."""
    self.needs_file_delete = False
    actual_report_bytes = crash_uploader.get_symbolized_stack_bytes(
        'reason', '0xfffffffffffffff4', [])
    actual_report_proto = process_state_pb2.ProcessStateProto()
    actual_report_proto.ParseFromString(actual_report_bytes)

    self.assertEqual(actual_report_proto.crash.address, -12)

  def test_to_report_metadata_and_back(self):
    """Test to report metadata and back."""
    self.needs_file_delete = False

    expected_report_info = crash_uploader.CrashReportInfo()
    expected_report_info.product = 'Chrome_Android'
    expected_report_info.version = '59.0.3035.0'
    expected_report_info.testcase_id = 'CF_TESTSUITE_TEST_UPLOAD'
    expected_report_info.bot_id = 'test_upload'
    with open(EXPECTED_PROCESSED_REPORT_PATH, 'rb') as processed_report:
      expected_report_info.serialized_crash_stack_frames = (
          processed_report.read())

    report_metadata = expected_report_info.to_report_metadata()
    actual_report_info = crash_uploader.crash_report_info_from_metadata(
        report_metadata)

    self._validate_report_fields(expected_report_info, actual_report_info)

  def test_parse_mime_to_crash_report_info(self):
    """Tests if parsing sample MIME file produces expected CrashReportInfo
       object."""
    self.needs_file_delete = True
    report_info = crash_uploader.parse_mime_to_crash_report_info(
        SAMPLE_MIME_PATH)

    # Check processed (extracted) dmp contents are what we expect.
    self._validate_dmp_contents(EXPECTED_DMP_PATH, ACTUAL_DMP_PATH)

    # Check object fields are what we expect.
    self._validate_report_fields(EXPECTED_REPORT_INFO, report_info)

  @mock.patch('clusterfuzz._internal.platforms.android.adb.run_shell_command')
  @mock.patch('clusterfuzz._internal.platforms.android.adb.run_command')
  def test_get_crash_info(self, mock_run_shell_command, mock_run_command):
    """Tests if parsing sample output (crash-stacks stacktrace) produces
       expected CrashReportInfo object (on Android; on other platforms,
       should fail)."""
    self.needs_file_delete = True

    # Process the output string, mocking the adb commands appropriately.
    sample_mime_device_path = os.path.join(
        '/data/data/com.google.android.apps.chrome/cache/Crash Reports',
        '%s.dmp1' % SAMPLE_MIME_FILENAME)
    mock_run_shell_command.return_value = sample_mime_device_path
    mock_run_command.return_value = sample_mime_device_path
    report_info = crash_uploader.get_crash_info(SAMPLE_OUTPUT)

    # Check processed (extracted) dmp contents are what we expect.
    self._validate_dmp_contents(EXPECTED_DMP_PATH, ACTUAL_DMP_PATH)

    # Check object fields are what we expect.
    self._validate_report_fields(EXPECTED_REPORT_INFO, report_info)

    # Sanity checks for failing on other platforms.
    os.environ['OS_OVERRIDE'] = 'mac'
    if crash_uploader.get_crash_info(SAMPLE_OUTPUT):
      os.environ['OS_OVERRIDE'] = TEST_OS
      self.fail('Expected none for non-Android.')

  @mock.patch('clusterfuzz._internal.google_cloud_utils.blobs.write_blob')
  def test_store_minidump(self, mock_write_testcase):
    """Tests (very roughly) minidump upload to blobstore: just check there /is/
       a blobstore ID returned."""
    self.needs_file_delete = False
    mock_write_testcase.return_value = '11111'

    sample_report_info = crash_uploader.CrashReportInfo(
        minidump_path=EXPECTED_DMP_PATH,
        product='Chrome_Android',
        version='46.0.2482.0')
    minidump_key = sample_report_info.store_minidump()
    if not minidump_key:
      self.fail('Could not upload minidump to blobstore.')

  def test_get_crash_info_and_stacktrace(self):
    """Tests crash stacktrace retry logic."""
    self.needs_file_delete = False

    with mock.patch.object(crash_uploader,
                           'get_crash_info') as mock_get_crash_info:
      with mock.patch.object(process_handler,
                             'run_process') as mock_run_process:
        # First try expected retry success.
        mock_get_crash_info.side_effect = [None, EXPECTED_REPORT_INFO]
        mock_run_process.side_effect = ([(None, None, SAMPLE_OUTPUT)] * 2)
        crash_info, _ = crash_uploader.get_crash_info_and_stacktrace(
            '', SAMPLE_OUTPUT, None)
        if crash_info is None:
          self.fail('Could not get crash info after retries.')

        # And check expected retry failure.
        retry_limit = int(os.environ['FAIL_RETRIES'])
        mock_get_crash_info.side_effect = [None] * (retry_limit + 1)
        mock_run_process.side_effect = (
            [(None, None, SAMPLE_OUTPUT)] * (retry_limit + 1))
        crash_info, _ = crash_uploader.get_crash_info_and_stacktrace(
            '', SAMPLE_OUTPUT, None)
        if crash_info is not None:
          self.fail('Expected failure to get crash info after retries, '
                    'got success.')


@test_utils.integration
class CrashUploadTest(CrashBaseTest):
  """Crash upload tests."""

  @classmethod
  def setUpClass(cls):
    os.environ['UPLOAD_MODE'] = 'staging'
    cls.server_error = cls.get_server_error()

  @classmethod
  def get_server_error(cls):
    """Get server error."""
    upload_url = crash_uploader.CRASH_REPORT_UPLOAD_URL[environment.get_value(
        'UPLOAD_MODE')]
    ping_url = urllib.parse.urlsplit(upload_url).netloc
    try:
      # Use a port that has been used for crash/ uploads before.
      sock = socket.create_connection((ping_url, 443), timeout=1)
      sock.close()
      return None
    except (socket.error, socket.timeout) as e:
      return 'Failed to connect to crash/: %s' % e

  def test_upload_processed_report(self):
    """Tests (very roughly) crash report upload with a processed report: just
       check there /is/ a returned report id."""
    self.needs_file_delete = False

    report_info = crash_uploader.CrashReportInfo()
    report_info.product = 'Chrome_Android'
    report_info.version = '59.0.3035.0'
    report_info.testcase_id = 'CF_TESTSUITE_TEST_UPLOAD'
    report_info.bot_id = 'test_upload'
    with open(EXPECTED_PROCESSED_REPORT_PATH, 'rb') as processed_report:
      report_info.serialized_crash_stack_frames = processed_report.read()

    # Attempt upload.
    if self.server_error:
      self.fail(self.server_error)
    report_id = report_info.upload()
    if not report_id:
      self.fail('No report id returned.')
