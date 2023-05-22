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

import os
import shutil
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb

from clusterfuzz._internal.bot.tasks.utasks import uworker_errors
from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.datastore import data_types
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
    self.underlying_entity = mock.MagicMock()
    self.underlying_entity.a = self.VALUE
    self.wrapped = uworker_io.UworkerEntityWrapper(self.underlying_entity)

  def test_reflecting_underlying(self):
    """Tests that UworkerEntityWrapper reflects values on the underlying
    entity."""
    self.assertEqual(self.wrapped.a, self.VALUE)

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
    self.assertEqual(self.wrapped._wrapped_changed_attributes, {})
    x = self.wrapped.a
    del x
    self.assertEqual(self.wrapped._wrapped_changed_attributes, {})

  def test_tracking_changes(self):
    """Tests that UworkerEntityWrapper tracks attributes on the underlying
    entity."""
    # If a user sets an attribute we need to track that, even if nothing is
    # actually changed.
    self.wrapped.a = self.VALUE
    self.wrapped.b = self.VALUE
    setattr(self.wrapped, 'c', self.VALUE)
    expected = {'a': self.VALUE, 'b': self.VALUE, 'c': self.VALUE}
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
  WORKER_IO_BUCKET = 'UWORKER_IO'
  NEW_IO_FILE_NAME = 'new-filename'
  EXPECTED_GCS_PATH = '/UWORKER_IO/new-filename'

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['TEST_UWORKER_IO_BUCKET'] = self.WORKER_IO_BUCKET
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get',
        'clusterfuzz._internal.google_cloud_utils.storage._sign_url',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.generate_new_io_file_name',
    ])

    self.mock.get.return_value = False
    self.mock._sign_url.return_value = self.FAKE_URL
    self.mock.generate_new_io_file_name.return_value = self.NEW_IO_FILE_NAME

  def test_get_uworker_output_urls(self):
    """Tests that get_uworker_output_urls works."""
    expected_urls = (self.FAKE_URL, self.EXPECTED_GCS_PATH)
    self.assertEqual(uworker_io.get_uworker_output_urls(), expected_urls)
    self.mock._sign_url.assert_called_with(
        self.EXPECTED_GCS_PATH,
        method='PUT',
        minutes=DEFAULT_SIGNED_URL_MINUTES)

  def test_get_uworker_input_urls(self):
    """Tests that get_uworker_input_urls works."""
    expected_urls = (self.FAKE_URL, self.EXPECTED_GCS_PATH)
    self.assertEqual(uworker_io.get_uworker_input_urls(), expected_urls)
    self.mock._sign_url.assert_called_with(
        self.EXPECTED_GCS_PATH,
        method='GET',
        minutes=DEFAULT_SIGNED_URL_MINUTES)


@test_utils.with_cloud_emulators('datastore')
class RoundTripTest(unittest.TestCase):
  """Tests round trips for download and uploading inputs and outputs."""
  WORKER_IO_BUCKET = 'UWORKER_IO'
  NEW_IO_FILE_NAME = 'new-filename'
  EXPECTED_GCS_PATH = '/UWORKER_IO/new-filename'
  FAKE_URL = 'https://fake'

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['FAIL_RETRIES'] = '1'
    os.environ['TEST_UWORKER_IO_BUCKET'] = self.WORKER_IO_BUCKET
    helpers.patch(self, [
        'clusterfuzz._internal.google_cloud_utils.storage.get',
        'clusterfuzz._internal.google_cloud_utils.storage._sign_url',
        'clusterfuzz._internal.bot.tasks.utasks.uworker_io.generate_new_io_file_name',
    ])
    self.mock.get.return_value = False
    self.mock._sign_url.return_value = self.FAKE_URL
    self.mock.generate_new_io_file_name.return_value = self.NEW_IO_FILE_NAME
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
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_upload_and_download_input(self):
    """Tests that uploading and downloading input works. This means that input
    serialization and deserialization works."""
    # Create input for the uworker.
    uworker_input = {
        'testcase': self.testcase,
        'uworker_env': self.env,
        'testcase_download_url': self.FAKE_URL
    }

    # Create a mocked version of copy_file_to so that when we upload the uworker
    # input, it goes to a known file we can read from.
    copy_file_to_tempfile = None

    def copy_file_to(src, _):
      shutil.copyfile(src, copy_file_to_tempfile.name)
      return True

    copy_file_to_name = ('clusterfuzz._internal.google_cloud_utils.storage.'
                         'copy_file_to')

    with tempfile.NamedTemporaryFile() as temp_file, mock.patch(
        copy_file_to_name, copy_file_to) as _:
      # copy_file_to will now copy the file to temp_file.
      copy_file_to_tempfile = temp_file

      # Create a mocked version of download_signed_url that will read the data
      # from the file copy_file_to wrote to.
      def download_signed_url(url, local_path=None):
        del url
        del local_path
        with open(temp_file.name, 'rb') as fp:
          return fp.read()

      uworker_io.serialize_and_upload_uworker_input(
          uworker_input, self.job_type, self.FAKE_URL)
      with mock.patch(
          'clusterfuzz._internal.google_cloud_utils.storage.download_signed_url',
          download_signed_url) as _:
        downloaded_input = uworker_io.download_and_deserialize_uworker_input(
            self.FAKE_URL)

    # Test that testcase (de)serialization worked.
    downloaded_testcase = downloaded_input.pop('testcase')
    self.assertEqual(self.testcase.crash_type, downloaded_testcase.crash_type)
    self.assertEqual(self.testcase.crash_address,
                     downloaded_testcase.crash_address)
    self.assertEqual(self.testcase.crash_state, downloaded_testcase.crash_state)
    self.assertEqual(self.testcase.key.serialized(),
                     downloaded_testcase.key.serialized())

    # Now test that the rest of the input was (de)serialized properly.
    del uworker_input['testcase']
    self.assertDictEqual(uworker_input, downloaded_input)

  def test_upload_and_download_output(self):
    """Tests that uploading and downloading uworker output works. This means
    that output serialization and deserialization works."""
    # Set up a wrapped testcase and modify it as a uworker would.
    testcase = uworker_io.UworkerEntityWrapper(self.testcase)
    testcase.newattr = 'newattr-value'
    testcase.crash_type = 'new-crash_type'

    # Prepare an output that tests db entity change tracking and
    # (de)serialization.
    field_value = 'field-value'
    output = uworker_io.UworkerOutput(
        error=uworker_errors.Type.ANALYZE_BUILD_SETUP)
    output.field = field_value
    output.testcase = testcase
    output.uworker_input = {}

    # Create a version of upload_signed_url that will "upload" the data to a
    # known file on disk that we can read back.
    upload_signed_url_tempfile = None

    def upload_signed_url(data, src):
      del src
      with open(upload_signed_url_tempfile.name, 'w') as fp:
        fp.write(data)
      return True

    upload_signed_url_name = ('clusterfuzz._internal.google_cloud_utils.'
                              'storage.upload_signed_url')
    copy_file_from_name = ('clusterfuzz._internal.google_cloud_utils.storage.'
                           'copy_file_from')

    with tempfile.NamedTemporaryFile() as temp_file, mock.patch(
        upload_signed_url_name, upload_signed_url) as _:
      upload_signed_url_tempfile = temp_file
      uworker_io.serialize_and_upload_uworker_output(output, self.FAKE_URL)

      # Create a version of copy_file_from that will "downloads" the data from
      # the file upload_signed_url wrote it to.
      def copy_file_from(gcs_url, local_path):
        del gcs_url
        shutil.copyfile(temp_file.name, local_path)
        return True

      with mock.patch(copy_file_from_name, copy_file_from) as _:
        downloaded_output = uworker_io.download_and_deserialize_uworker_output(
            self.FAKE_URL)

    # Test that the entity (de)serialization and change tracking working.
    downloaded_testcase = downloaded_output.pop('testcase')
    self.assertEqual(downloaded_testcase.newattr, testcase.newattr)
    self.assertEqual(downloaded_testcase.crash_type, testcase.crash_type)

    # Test that the rest of the output was (de)serialized correctly.
    self.assertEqual(downloaded_testcase.key.serialized(),
                     self.testcase.key.serialized())
    error = downloaded_output.pop('error')
    self.assertEqual(error, uworker_errors.Type.ANALYZE_BUILD_SETUP)
    self.assertDictEqual(downloaded_output, {
        'field': field_value,
        'uworker_input': {}
    })
