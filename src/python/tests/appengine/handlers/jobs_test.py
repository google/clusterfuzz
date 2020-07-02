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
"""Tests for jobs."""
import collections
import unittest
import webapp2
import webtest

from datastore import data_types
from handlers import jobs
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class JobsTest(unittest.TestCase):
  """Jobs tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.access.get_access',
        'libs.helpers.get_user_email',
        'libs.gcs.prepare_blob_upload',
    ])
    self.mock.prepare_blob_upload.return_value = (
        collections.namedtuple('GcsUpload', [])())
    self.app = webtest.TestApp(
        webapp2.WSGIApplication([('/', jobs.JsonHandler)]))

  def _create_job(self,
                  name,
                  environment_string,
                  description='',
                  platform='LINUX'):
    """Create a test job."""
    job = data_types.Job()
    job.name = name
    if environment_string.strip():
      job.environment_string = environment_string
    job.platform = platform
    job.descripton = description
    job.put()

    return job

  def test_get_results(self):
    """Test get_results."""
    self.mock.has_access.return_value = True
    job1 = self._create_job('test_job1', 'APP_NAME = launcher1.py\n')
    job2 = self._create_job('test_job2', 'APP_NAME = launcher2.py\n')
    job3 = self._create_job('test_job3', 'APP_NAME = launcher3.py\n')
    job4 = self._create_job('test_job4', 'APP_NAME = launcher4.py\n')

    expected_items = [
        job1.key.id(), job2.key.id(),
        job3.key.id(), job4.key.id()]

    resp = self.app.post_json('/', {'page': 1})

    self.assertListEqual(
        expected_items,
        [item['id'] for item in resp.json['items']]
    )
