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
"""form tests."""
import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from libs import form


@test_utils.with_cloud_emulators('datastore')
class GenerateCrsfTokenTest(unittest.TestCase):
  """Test generate_csrf_token."""

  _NOW = datetime.datetime.utcfromtimestamp(10000)
  _LATER = datetime.datetime.utcfromtimestamp(10001)
  _BEFORE = datetime.datetime.utcfromtimestamp(9999)

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.base.utils.utcnow',
        'libs.helpers.get_user_email',
        'os.urandom',
    ])
    self.mock.get_user_email.return_value = 'test@test.com'

  def make_token(self, value, time):
    token = data_types.CSRFToken()
    token.value = value
    token.expiration_time = time
    token.user_email = self.mock.get_user_email.return_value
    return token

  def test_valid_token(self):
    """Ensure it returns the valid token when the valid token is there."""
    self.mock.utcnow.return_value = self._NOW
    self.make_token(value='token', time=self._LATER).put()
    self.assertEqual(form.generate_csrf_token(), 'token')

  def test_valid_token_html(self):
    """Ensure it returns the valid token in HTML when the valid token is
    there."""
    self.mock.utcnow.return_value = self._NOW
    self.make_token(value='token', time=self._LATER).put()
    self.assertEqual(
        form.generate_csrf_token(html=True),
        '<input type="hidden" name="csrf_token" value="token" />')

  def test_invalid_token(self):
    """Ensure it returns a new token when the valid token expires"""
    self.mock.utcnow.return_value = self._NOW
    self.mock.urandom.return_value = b'a'
    self.make_token(value='token', time=self._BEFORE).put()
    self.assertEqual(form.generate_csrf_token(), 'YQ==')

    tokens = list(
        data_types.CSRFToken.query(
            data_types.CSRFToken.user_email == 'test@test.com'))
    self.assertEqual(len(tokens), 1)
    self.assertGreater(tokens[0].expiration_time, self._NOW)
    self.assertEqual(tokens[0].value, 'YQ==')
