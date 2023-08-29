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


class UworkerEntityWrapperTest(unittest.TestCase):
  """Tests for UworkerEntityWrapper, a core part of how ndb models/data_types
  are used by uworkers."""
  VALUE = 1
  NEW_VALUE = 2

  def setUp(self):

    class ModelClass(data_types.Model):
      a = ndb.IntegerProperty()

      def change_a(self):
        self.a = 9

    self.underlying_entity = ModelClass()
    self.underlying_entity.a = self.VALUE
    self.wrapped = uworker_io.UworkerEntityWrapper(self.underlying_entity)

  def test_reflecting_underlying(self):
    """Tests that UworkerEntityWrapper reflects values on the underlying
    entity."""
    self.assertEqual(self.wrapped.a, self.VALUE)

  def test_method_modifying(self):
    """Tests that we can track changes by method calls."""
    self.underlying_entity.change_a()
    self.assertEqual(self.wrapped.get_changed_attrs(), {'a'})

  def test_modifying_underlying(self):
    """Tests that UworkerEntityWrapper modifies attributes on the underlying
    entity, and that when queried, reflects those values back."""
    self.wrapped.a = self.NEW_VALUE
    self.assertEqual(self.wrapped.a, self.NEW_VALUE)
    self.assertEqual(self.underlying_entity.a, self.NEW_VALUE)

    self.wrapped.b = self.NEW_VALUE
    self.assertEqual(self.wrapped.b, self.NEW_VALUE)
    self.assertEqual(self.underlying_entity.b, self.NEW_VALUE)

    # Test with setattr to make sure we handle fanciness.
    setattr(self.wrapped, 'c', self.NEW_VALUE)
    self.assertEqual(self.wrapped.c, self.NEW_VALUE)
    self.assertEqual(self.underlying_entity.c, self.NEW_VALUE)

  def test_no_changes(self):
    """Tests that UworkerEntityWrapper works when nothing is modified"""
    self.assertEqual(self.wrapped.get_changed_attrs(), set())
    x = self.wrapped.a
    del x
    self.assertEqual(self.wrapped.get_changed_attrs(), set())

  def test_tracking_changes(self):
    """Tests that UworkerEntityWrapper tracks attributes on the underlying
    entity."""
    # If a user sets an attribute we need to track that, even if nothing is
    # actually changed.
    self.wrapped.a = self.VALUE
    self.wrapped.b = self.VALUE
    setattr(self.wrapped, 'c', self.VALUE)
    expected = {'a', 'b', 'c'}
    self.assertEqual(self.wrapped._wrapped_changed_attributes, expected)

  def test_not_adding_fields(self):
    """Tests that UworkerEntityWrapper isn't adding fields to the
    underlying_entity when not intended by the user."""
    # Change the underlying entity to something that isn't MagicMock.
    self.wrapped._entity = {}

    with self.assertRaises(AttributeError):
      self.wrapped.nonexistent  # pylint: disable=pointless-statement

    with self.assertRaises(AttributeError):
      getattr(self.wrapped, 'also_non_existent')  # pylint: disable=pointless-statement


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


class UworkerOutputTest(unittest.TestCase):
  """Tests for UworkerOutput."""

  def setUp(self):
    self.output = uworker_io.UworkerOutput()

  def test_error_and_testcase_behavior(self):
    """Tests that the error and testcase attrs are handled properly,
    in that they can be accessed with out being explicitly set
    (defaulting to None) but don't appear in to_dict until they are
    set."""
    # Test that these can be accessed without an attribute error.
    self.output.testcase  # pylint: disable=pointless-statement
    self.output.error  # pylint: disable=pointless-statement
    error_value = 1
    self.output.error = error_value
    self.assertEqual(self.output.error, error_value)
    self.assertEqual(self.output.proto.error, error_value)


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
    uworker_input = uworker_io.UworkerInput(
        testcase=self.testcase,
        uworker_env=self.env,
        testcase_download_url=self.FAKE_URL,
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
    downloaded_testcase = downloaded_input.testcase
    self.assertEqual(self.testcase.crash_type, downloaded_testcase.crash_type)
    self.assertEqual(self.testcase.crash_address,
                     downloaded_testcase.crash_address)
    self.assertEqual(self.testcase.crash_state, downloaded_testcase.crash_state)
    self.assertEqual(self.testcase.key.serialized(),
                     downloaded_testcase.key.serialized())
    # Things will break horribly if we pass an unwrapped entity.
    self.assertIsInstance(downloaded_testcase, uworker_io.UworkerEntityWrapper)

    self.assertDictEqual(uworker_input.uworker_env,
                         downloaded_input.uworker_env)
    self.assertEqual(uworker_input.uworker_output_upload_url,
                     downloaded_input.uworker_output_upload_url)
    self.assertEqual(uworker_input.testcase_download_url,
                     downloaded_input.testcase_download_url)

  def test_upload_and_download_output(self):
    """Tests that uploading and downloading uworker output works. This means
    that output serialization and deserialization works."""
    # Set up a wrapped testcase and modify it as a uworker would.
    testcase = uworker_io.UworkerEntityWrapper(self.testcase)
    testcase.regression = '1'
    testcase.timestamp = datetime.datetime.now()
    testcase.crash_type = 'new-crash_type'

    # Prepare an output that tests db entity change tracking and
    # (de)serialization.
    crash_time = 1
    output = uworker_io.UworkerOutput(
        error=uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)
    output.crash_time = crash_time
    output.testcase = testcase

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
      uworker_input = uworker_io.UworkerInput(
          uworker_env=uworker_env, testcase_id='one-two')
      with mock.patch(
          download_input_based_on_output_url_name,
          return_value=uworker_input) as _, mock.patch(read_data_name,
                                                       read_data):

        downloaded_output = (
            uworker_io.download_and_deserialize_uworker_output(self.FAKE_URL))

        self.assertEqual(downloaded_output.testcase.regression,
                         testcase.regression)
        self.assertEqual(downloaded_output.testcase.crash_type,
                         testcase.crash_type)
        self.assertEqual(downloaded_output.testcase.timestamp,
                         testcase.timestamp)

    # Test that the rest of the output was (de)serialized correctly.
    self.assertEqual(downloaded_output.testcase.key.serialized(),
                     self.testcase.key.serialized())
    self.assertEqual(downloaded_output.crash_time, 1)
    self.assertEqual(downloaded_output.error,
                     uworker_msg_pb2.ErrorType.ANALYZE_BUILD_SETUP)
    self.assertEqual(downloaded_output.uworker_input.testcase_id,
                     uworker_input.testcase_id)
    self.assertDictEqual(downloaded_output.uworker_input.uworker_env,
                         uworker_env)

  def test_output_error_serialization(self):
    """Tests that errors can be returned by the tasks."""
    test_timeout = 1337
    output = uworker_io.UworkerOutput(
        error=uworker_msg_pb2.ErrorType.TESTCASE_SETUP,
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
    data_bundles = [bundle1, bundle2]
    update_input = uworker_io.UpdateFuzzerAndDataBundleInput(
        data_bundles=data_bundles)
    uworker_input = uworker_io.UworkerInput(
        update_fuzzer_and_data_bundles_input=update_input)
    serialized = uworker_io.serialize_uworker_input(uworker_input)
    deserialized = uworker_io.deserialize_uworker_input(serialized)
    update_input = deserialized.update_fuzzer_and_data_bundles_input
    self.assertEqual(update_input.data_bundles[0].name, bundle1.name)
    self.assertEqual(update_input.data_bundles[1].name, bundle2.name)

  def test_additional_metadata(self):
    """Tests that additional_metadata field on Testcase is serialized and
    deserialized properly."""
    testcase = data_types.Testcase()
    testcase.put()
    uworker_input = uworker_io.UworkerInput(testcase=testcase)
    serialized = uworker_io.serialize_uworker_input(uworker_input)
    uworker_input = uworker_io.deserialize_uworker_input(serialized)
    additional_metadata = r'{"gn_args": "is_asan = true\nis_clang = true"}'
    uworker_input.testcase.set_metadata(
        'gn_args', 'is_asan = true\nis_clang = true', False)
    self.assertEqual(uworker_input.testcase.get_changed_attrs(),
                     {'additional_metadata'})
    output = uworker_io.UworkerOutput(testcase=uworker_input.testcase)
    serialized_output = uworker_io.serialize_uworker_output(output)
    deserialized = uworker_io.deserialize_uworker_output(serialized_output)
    self.assertEqual(deserialized.testcase.additional_metadata,
                     additional_metadata)

  def test_submessage_serialization_and_deserialization(self):
    """Tests that output messages with submessages are serialized and
    deserialized properly."""
    crash_revision = '1337'
    crashes = [{
        'is_new': False,
        'count': 1,
        'crash_type': 'Abort',
        'crash_state': 'NULL',
        'security_flag': True,
    }]
    output = uworker_io.UworkerOutput(
        fuzz_task_output=uworker_io.FuzzTaskOutput(
            crash_revision=crash_revision, job_run_crashes=crashes))
    serialized = uworker_io.serialize_uworker_output(output)
    deserialized = uworker_io.deserialize_uworker_output(serialized)
    self.assertEqual(deserialized.fuzz_task_output.job_run_crashes, crashes)
    self.assertEqual(deserialized.fuzz_task_output.crash_revision,
                     crash_revision)
