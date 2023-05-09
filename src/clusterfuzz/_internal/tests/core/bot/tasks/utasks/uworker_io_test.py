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
import unittest
from unittest import mock

from clusterfuzz._internal.bot.tasks.utasks import uworker_io
from clusterfuzz._internal.tests.test_libs import helpers

DEFAULT_SIGNED_URL_MINUTES = 1440


class UworkerEntityWrapperTest(unittest.TestCase):
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
    self.assertEqual(self.wrapped._wrapped_changed_attributes, expected)  # pylint: disable=protected-access

  def test_not_adding_fields(self):
    """Tests that UworkerEntityWrapper isn't adding fields to the
    underlying_entity."""
    # Change the underlying entity to something that isn't MagicMock.
    self.wrapped._entity = {}

    with self.assertRaises(AttributeError):
      self.wrapped.nonexistent

    with self.assertRaises(AttributeError):
      getattr(self.wrapped, 'also_non_existent')


# class TestGetIOUrls(unittest.TestCase):
#   def setUp(self):
#     helpers.patch_environ(self)
#     os.environ['TEST_WORKER_IO_BUCKET'] = self.WORKER_IO_BUCKET


class TestUploadUworkerInput(unittest.TestCase):
  """Tests that upload_uworker_input works."""
  FAKE_URL = 'https://fake'
  WORKER_IO_BUCKET = 'UWORKER_IO'
  NEW_IO_FILE_NAME = 'new-filename'
  EXPECTED_GCS_PATH = '/UWORKER_IO/new-filename'

  def setUp(self):
    helpers.patch_environ(self)
    os.environ['TEST_UWORKER_IO_BUCKET'] = self.WORKER_IO_BUCKET
    helpers.patch(
        self,
        [
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
    self.mock._sign_url.assert_called_with(self.EXPECTED_GCS_PATH, method='PUT', minutes=DEFAULT_SIGNED_URL_MINUTES)

  def test_get_uworker_input_urls(self):
    """Tests that get_uworker_input_urls works."""
    expected_urls = (self.FAKE_URL, self.EXPECTED_GCS_PATH)
    self.assertEqual(uworker_io.get_uworker_input_urls(), expected_urls)
    self.mock._sign_url.assert_called_with(self.EXPECTED_GCS_PATH, method='GET', minutes=DEFAULT_SIGNED_URL_MINUTES)


class InputSerializationTest(unittest.TestCase):
  def test_serialize_uworker_input(self):
    uworker_input = {'builtin_type_1': 1, 'builtin_type_2': {'a': 1}}
  def test_roundtrip(self):
    """Tests that serializing and deserializing uworker input results in the
    same input."""
