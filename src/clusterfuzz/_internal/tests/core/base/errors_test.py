# Copyright 2024 Google LLC
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
"""Tests for errors.py."""

import unittest

from clusterfuzz._internal.base import errors
from clusterfuzz._internal.google_cloud_utils import storage


class TestErrorInList(unittest.TestCase):
  """Tests error_in_list."""

  def test_error_in_list(self):
    try:
      raise storage.ExpiredSignedUrlError(
          'Expired token, failed to download uworker_input: https://google.com',
          'https://google.com', 'Response text here')
    except storage.ExpiredSignedUrlError as e:
      self.assertTrue(
          errors.error_in_list(str(e), errors.BOT_ERROR_TERMINATION_LIST))

  def test_arbitrary_error(self):
    """Tests proper handling of errors not in the list."""
    self.assertFalse(
        errors.error_in_list('RuntimeError', errors.BOT_ERROR_TERMINATION_LIST))
