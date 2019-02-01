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

from datastore import data_types
from handlers import jobs
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class JobsTest(unittest.TestCase):
  """Jobs tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.get_access',
        'libs.helpers.get_user_email',
        'libs.form.generate_csrf_token',
        'libs.gcs.prepare_blob_upload',
    ])
    self.mock.generate_csrf_token.return_value = None
    self.mock.prepare_blob_upload.return_value = (
        collections.namedtuple('GcsUpload', [])())

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
    job = self._create_job(
        'test_job', 'APP_NAME = launcher.py\n')
    expected = {
        'templates': [],
        'jobs': [job],
        'fieldValues': {
            'csrf_token':
                None,
            'queues': [{
                'display_name': 'Android',
                'name': 'ANDROID'
            }, {
                'display_name': 'Android (x86)',
                'name': 'ANDROID_X86'
            }, {
                'display_name': 'Chrome OS',
                'name': 'CHROMEOS'
            }, {
                'display_name': 'Fuchsia OS',
                'name': 'FUCHSIA'
            }, {
                'display_name': 'Linux',
                'name': 'LINUX'
            }, {
                'display_name': 'Linux (untrusted)',
                'name': 'LINUX_UNTRUSTED'
            }, {
                'display_name': 'Linux (with GPU)',
                'name': 'LINUX_WITH_GPU'
            }, {
                'display_name': 'Mac',
                'name': 'MAC'
            }, {
                'display_name': 'Windows',
                'name': 'WINDOWS'
            }, {
                'display_name': 'Windows (with GPU)',
                'name': 'WINDOWS_WITH_GPU'
            }],
            'update_job_template_url':
                '/update-job-template',
            'update_job_url':
                '/update-job',
            'upload_info':
                collections.OrderedDict(),
        },
    }
    results = jobs.Handler.get_results()
    self.assertEqual(expected, results)
