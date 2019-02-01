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
"""logger tests."""
import unittest

from platforms.android import logger


class IsLineValidTest(unittest.TestCase):
  """Tests is_line_valid."""

  def test_debug(self):
    """Tests debug line."""
    self.assertFalse(
        logger.is_line_valid('D/ConnectivityService(  812): notifyType'))

  def test_verbose(self):
    """Tests verbose line."""
    self.assertFalse(
        logger.is_line_valid('V/chromium( 8572): [VERBOSE1:] Not implemented.'))

  def test_url(self):
    """Tests verbose line."""
    # pylint: disable=line-too-long
    self.assertTrue(
        logger.is_line_valid(
            'V/chromium( 8530): [VERBOSE1:network_delegate.cc(31)] '
            'NetworkDelegate::NotifyBeforeURLRequest: '
            'https://en.m.wikipedia.org'))
    # pylint: enable=line-too-long

  def test_info(self):
    """Tests info line."""
    self.assertTrue(
        logger.is_line_valid(
            'I/chromium( 8530): [INFO:CONSOLE(166)] Hello friend!'))
