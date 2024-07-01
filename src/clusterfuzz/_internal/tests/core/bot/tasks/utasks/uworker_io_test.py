# Copyright 2023 Google LLC
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
"""Tests for uworker_io."""

import datetime
import os
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.protos import uworker_msg_pb2
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils

DEFAULT_SIGNED_URL_MINUTES = 24 * 60

# pylint: disable=protected-access


class TestGetUrls(unittest.TestCase):
  """Tests that functions for getting urls for uploading and downloading input
  and output work properly."""
  FAKE_URL = 'https://fake'
  WORKER_INPUT_BUCKET = 'UWORKER_INPUT'
  WORKER_OUTPUT_BUCKET = 'UWORKER_OUTPUT'
  NEW_IO_FILE_NAME = 'new-filename'
  EXPECTED_INPUT_GCS_PATH = '/UWORKER_INPUT/new-filename'
  EXPECTED_OUTPUT_GCS_PATH = '/UWORKER_OUTPUT/new-filename'

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['TEST_UWORKER_INPUT_BUCKET'] = self.WORKER_INPUT_BUCKET
    os.environ['TEST_UWORKER_OUTPUT_BUCKET'] = self.WORKER_OUTPUT_BUCKET
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get',
        'clusterfuzz._internal.google_cloud_utils.storage._sign_url',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.generate_new_input_file_name',
    ])

    self.mock.get.return_value = False
    self.mock._sign_url.return_value = self.FAKE_URL
    self.mock.generate_new_input_file_name.return_value = self.NEW_IO_FILE_NAME

  def test_get_uworker_output_urls(self):
    """Tests that get_uworker_output_urls works."""
    expected_urls = (self.FAKE_URL, self.EXPECTED_OUTPUT_GCS_PATH)
    self.assertEqual(
        uworker_io.get_uworker_output_urls(self.EXPECTED_INPUT_GCS_PATH),
        expected_urls)
    self.mock._sign_url.assert_called_with(
        self.EXPECTED_OUTPUT_GCS_PATH,
        method='PUT',
        minutes=DEFAULT_SIGNED_URL_MINUTES)

  def test_get_uworker_input_urls(self):
    """Tests that get_uworker_input_urls works."""
    expected_urls = (self.FAKE_URL, self.EXPECTED_INPUT_GCS_PATH)
    self.assertEqual(uworker_io.get_uworker_input_urls(), expected_urls)
    self.mock._sign_url.assert_called_with(
        self.EXPECTED_INPUT_GCS_PATH,
        method='GET',
        minutes=DEFAULT_SIGNED_URL_MINUTES)


@test_utils.with_cloud_emulators('datastore')
class RoundTripTest(unittest.TestCase):
  """Tests round trips for serializing+deserializing as well as
  downloading and uploading inputs and outputs."""
  WORKER_INPUT_BUCKET = 'UWORKER_INPUT'
  WORKER_OUTPUT_BUCKET = 'UWORKER_OUTPUT'
  NEW_IO_FILE_NAME = 'new-filename'
  FAKE_URL = 'https://fake'

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['TEST_UWORKER_INPUT_BUCKET'] = self.WORKER_INPUT_BUCKET
    os.environ['TEST_UWORKER_OUTPUT_BUCKET'] = self.WORKER_OUTPUT_BUCKET
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get',
        'clusterfuzz._internal.google_cloud_utils.storage._sign_url',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.generate_new_input_file_name',
    ])
    self.mock.get.return_value = False
    self.mock._sign_url.return_value = self.FAKE_URL
    self.mock.generate_new_input_file_name.return_value = self.NEW_IO_FILE_NAME
    crash_type = 'type'
    crash_addr = 'addr'
    crash_state = 'NY :-)'
    self.testcase = data_types.Testcase()
    key = ndb.Key(data_types.Testcase, 'key')
    self.testcase.key = key
    self.testcase.crash_type = crash_type
    self.testcase.crash_address = crash_addr
    self.testcase.crash_state = crash_state
    self.testcase.put()
    self.env = {'ENVVAR': '1'}
    self.download_url = 'https://fake-signed-download-url'
    self.job_type = 'job'
    self.maxDiff = None

  def test_upload_and_download_input(self):
    """Tests that uploading and downloading input works. This means that input
    serialization and deserialization works."""
    # Create input for the uworker.
    uworker_input = uworker_msg_pb2.Input(
        testcase=uworker_io.entity_to_protobuf(self.testcase),
        uworker_env=self.env,
        setup_input=uworker_msg_pb2.SetupInput(
            testcase_download_url=self.FAKE_URL),
    )

    # Create a mocked version of write_data so that when we upload the uworker
    # input, it goes to a known file we can read from.
    write_data_tempfile = None

    def write_data(data, _):
      with open(write_data_tempfile.name, 'wb') as fp:
        fp.write(data)
      return True

    write_data_name = ('clusterfuzz._internal.google_cloud_utils.storage.'
                       'write_data')

    with tempfile.NamedTemporaryFile() as temp_file, mock.patch(
        write_data_name, write_data) as _:
      # write_data will now write the data to temp_file.
      write_data_tempfile = temp_file

      # Create a mocked version of download_signed_url that will read the data
      # from the file copy_file_to wrote to.
      def download_signed_url(url, local_path=None):
        del url
        del local_path
        with open(temp_file.name, 'rb') as fp:
          return fp.read()

      with tempfile.TemporaryDirectory() as tmp_dir:
        os.environ['BOT_TMPDIR'] = tmp_dir
        uworker_io.serialize_and_upload_uworker_input(uworker_input)
        with mock.patch(
            'clusterfuzz._internal.google_cloud_utils.storage.'
            'download_signed_url', download_signed_url) as _:
          downloaded_input = uworker_io.download_and_deserialize_uworker_input(
              self.FAKE_URL)

    # Test that testcase (de)serialization worked.
    downloaded_testcase = uworker_io.entity_from_protobuf(
        downloaded_input.testcase, data_types.Testcase)
    self.assertEqual(self.testcase.crash_type, downloaded_testcase.crash_type)
    self.assertEqual(self.testcase.crash_address,
                     downloaded_testcase.crash_address)
    self.assertEqual(self.testcase.crash_state, downloaded_testcase.crash_state)
    self.assertEqual(self.testcase.key.serialized(),
                     downloaded_testcase.key.serialized())

    self.assertEqual(uworker_input.uworker_env, downloaded_input.uworker_env)
    self.assertEqual(uworker_input.uworker_output_upload_url,
                     downloaded_input.uworker_output_upload_url)
    self.assertEqual(uworker_input.setup_input.testcase_download_url,
                     downloaded_input.setup_input.testcase_download_url)

  def test_upload_and_download_output(self):
    """Tests that uploading and downloading uworker output works. This means
    that output serialization and deserialization works."""
    # Set up a wrapped testcase and modify it as a uworker would.
    testcase = self.testcase
    testcase.regression = '1'
    testcase.timestamp = datetime.datetime.now()
    testcase.crash_type = 'new-crash_type'

    # Prepare an output that tests db entity change tracking and
    # (de)serialization.
    crash_time = 1
    output = uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)
    output.crash_time = crash_time

    # Create a version of upload_signed_url that will "upload" the data to a
    # known file on disk that we can read back.
    upload_signed_url_tempfile = None

    def upload_signed_url(data, src):
      del src
      with open(upload_signed_url_tempfile, 'wb') as fp:
        fp.write(data)
      return True

    upload_signed_url_name = ('clusterfuzz._internal.google_cloud_utils.'
                              'storage.upload_signed_url')

    with tempfile.TemporaryDirectory() as tmp_dir, mock.patch(
        upload_signed_url_name, upload_signed_url) as _:

      os.environ['BOT_TMPDIR'] = tmp_dir
      output_temp_file = os.path.join(tmp_dir, 'output-temp-file')
      upload_signed_url_tempfile = output_temp_file
      uworker_io.serialize_and_upload_uworker_output(output, self.FAKE_URL)

      download_input_based_on_output_url_name = (
          'clusterfuzz._internal.bot.tasks.utasks.uworker_io.'
          'download_input_based_on_output_url')
      read_data_name = (
          'clusterfuzz._internal.google_cloud_utils.storage.read_data')

      def read_data(_):
        with open(upload_signed_url_tempfile, 'rb') as fp:
          return fp.read()

      uworker_env = {'PATH': '/blah'}
      uworker_input = uworker_msg_pb2.Input(
          uworker_env=uworker_env, testcase_id='one-two')
      with mock.patch(
          download_input_based_on_output_url_name,
          return_value=uworker_input) as _, mock.patch(read_data_name,
                                                       read_data):

        downloaded_output = (
            uworker_io.download_and_deserialize_uworker_output(self.FAKE_URL))

    # Test that the rest of the output was (de)serialized correctly.
    self.assertEqual(downloaded_output.crash_time, 1)
    self.assertEqual(downloaded_output.error_type,
                     uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)
    self.assertEqual(downloaded_output.uworker_input.testcase_id,
                     uworker_input.testcase_id)
    self.assertEqual(downloaded_output.uworker_input.uworker_env, uworker_env)

  def test_output_error_serialization(self):
    """Tests that errors can be returned by the tasks."""
    test_timeout = 1337
    output = uworker_msg_pb2.Output(
        error_type=uworker_msg_pb2.ErrorType.TESTCASE_SETUP,
        test_timeout=test_timeout)
    serialized = uworker_io.serialize_uworker_output(output)
    processed_output = uworker_io.deserialize_uworker_output(serialized)
    self.assertEqual(processed_output.test_timeout, test_timeout)

  def test_update_fuzzer_and_data_bundle_input(self):
    """Tests that we can serialize and deserialize
    update_fuzzer_and_data_bundle_input."""
    bundle1 = data_types.DataBundle(name='name1')
    bundle2 = data_types.DataBundle(name='name2')
    bundle1.put()
    bundle2.put()
    data_bundle_corpuses = [
        uworker_msg_pb2.DataBundleCorpus(
            data_bundle=uworker_io.entity_to_protobuf(bundle1)),
        uworker_msg_pb2.DataBundleCorpus(
            data_bundle=uworker_io.entity_to_protobuf(bundle2)),
    ]
    setup_input = uworker_msg_pb2.SetupInput(
        data_bundle_corpuses=data_bundle_corpuses)
    uworker_input = uworker_msg_pb2.Input(setup_input=setup_input)
    serialized = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(serialized)
    setup_input = deserialized.setup_input
    deserialized_data_bundles = [
        uworker_io.entity_from_protobuf(bundle.data_bundle,
                                        data_types.DataBundle)
        for bundle in setup_input.data_bundle_corpuses
    ]
    self.assertEqual(deserialized_data_bundles[0].name, bundle1.name)
    self.assertEqual(deserialized_data_bundles[1].name, bundle2.name)

  def test_minimization_output_serialization(self):
    """Tests that we can serialize and deserialize MinimizeTaskOutput."""
    expected_last_crash_result_dict = {
      'crash_type': 'test-use-after-free',
      'crash_address': '0x61b00001f7d0',
      'crash_state': 'test crash state',
      'crash_stacktrace': 'test stacktrace --------+' \
        '#0 0x64801a in frame0() src/test.cpp:1819:15' ,
    }
    expected_flaky_stack = True
    pre_serialized_minimize_task_output = uworker_msg_pb2.MinimizeTaskOutput(
        last_crash_result_dict=expected_last_crash_result_dict,
        flaky_stack=expected_flaky_stack)
    uworker_output = uworker_msg_pb2.Output(
        minimize_task_output=pre_serialized_minimize_task_output)
    serialized = uworker_io.serialize_uworker_output(uworker_output)
    deserialized = uworker_io.deserialize_uworker_output(serialized)
    deserialized_minimize_task_output = deserialized.minimize_task_output
    self.assertEqual(deserialized_minimize_task_output.last_crash_result_dict,
                     expected_last_crash_result_dict)
    self.assertEqual(deserialized_minimize_task_output.flaky_stack,
                     expected_flaky_stack)

  def test_submessage_serialization_and_deserialization(self):
    """Tests that output messages with submessages are serialized and
    deserialized properly."""
    crash_revision = '1337'

    crash_groups = [
        uworker_msg_pb2.FuzzTaskCrashGroup(crashes=[
            uworker_msg_pb2.FuzzTaskCrash(
                crash_type='Abort',
                crash_state='NULL',
                security_flag=True,
            )
        ])
    ]
    output = uworker_msg_pb2.Output(
        fuzz_task_output=uworker_msg_pb2.FuzzTaskOutput(
            crash_revision=crash_revision, crash_groups=crash_groups))
    serialized = uworker_io.serialize_uworker_output(output)
    deserialized = uworker_io.deserialize_uworker_output(serialized)
    self.assertEqual(deserialized.fuzz_task_output.crash_groups, crash_groups)

    self.assertEqual(deserialized.fuzz_task_output.crash_revision,
                     crash_revision)


class ComplexFieldsTest(unittest.TestCase):
  """Tests handling of complex proto fields (e.g. lists and
  submessages)."""

  def test_list_initialize(self):
    """Tests that initialization with a list works."""
    analyze_task_input = uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=[0])
    uworker_input = uworker_msg_pb2.Input(analyze_task_input=analyze_task_input)
    wire_format = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(wire_format)
    self.assertEqual(deserialized.analyze_task_input.bad_revisions, [0])

  def test_list_update(self):
    """Tests that updating a list works."""
    analyze_task_input = uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=[0])
    analyze_task_input.bad_revisions.extend([1])
    uworker_input = uworker_msg_pb2.Input(analyze_task_input=analyze_task_input)
    wire_format = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(wire_format)
    self.assertEqual(deserialized.analyze_task_input.bad_revisions, [0, 1])

  def test_map_update(self):
    """Tests that updating a map works."""
    output = uworker_msg_pb2.Output(issue_metadata={'a': 'b', 'c': 'd'})
    output.issue_metadata.clear()
    output.issue_metadata.update({'e': 'f'})
    wire_format = uworker_io.serialize_uworker_output(output)
    deserialized = uworker_io.deserialize_uworker_output(wire_format)
    self.assertEqual(deserialized.issue_metadata, {'e': 'f'})

  def test_submessage_references(self):
    """Tests that updating a submessage works both when directly reading from
    uworker_input and from reading from it once it has been serialized and
    deserialized."""
    analyze_task_input = uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=[0])
    uworker_input = uworker_msg_pb2.Input(analyze_task_input=analyze_task_input)
    uworker_input.analyze_task_input.bad_revisions.append(-1)
    uworker_input.analyze_task_input.bad_revisions.extend([2])
    uworker_input.analyze_task_input.bad_revisions.append(3)
    analyze_task_input.bad_revisions.append(4)
    self.assertEqual(analyze_task_input.bad_revisions, [0, 4])
    wire_format = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(wire_format)
    self.assertEqual(deserialized.analyze_task_input.bad_revisions,
                     [0, -1, 2, 3])

  def test_unset_a_message_field(self):
    """Tests that clearing a field works."""
    analyze_task_input = uworker_msg_pb2.AnalyzeTaskInput(bad_revisions=[0])
    uworker_input = uworker_msg_pb2.Input(analyze_task_input=analyze_task_input)

    uworker_input.ClearField("analyze_task_input")
    wire_format = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(wire_format)
    self.assertFalse(deserialized.HasField("analyze_task_input"))
