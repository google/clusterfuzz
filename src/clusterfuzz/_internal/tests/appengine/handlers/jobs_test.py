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
import string
import unittest
from unittest import mock

import flask
import webtest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import jobs
from libs import form


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
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=jobs.JsonHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

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

  def test_post(self):
    """Test post method."""
    self.mock.has_access.return_value = True
    expected_items = {1: [], 2: [], 3: []}

    for job_num, job_suffix in enumerate(string.ascii_lowercase):
      job_name = "test_job_" + job_suffix
      job = self._create_job(job_name, 'APP_NAME = launcher.py\n')
      expected_items[(job_num // 10) + 1].append(job.key.id())

    resp = self.app.post_json('/', {'page': 1})
    self.assertListEqual(expected_items[1],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 2})
    self.assertListEqual(expected_items[2],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 3})
    self.assertListEqual(expected_items[3],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'page': 4})
    self.assertListEqual([], [item['id'] for item in resp.json['items']])

  def test_fuzzers_result(self):
    """Test fuzzers result obtained in post method."""
    self.mock.has_access.return_value = True

    job = self._create_job('test_job', 'APP_NAME = launcher.py\n')
    fuzzer = data_types.Fuzzer()
    fuzzer.name = 'fuzzer'
    fuzzer.jobs = ['test_job']
    fuzzer.put()

    resp = self.app.post_json('/', {'page': 1})
    self.assertListEqual([job.key.id()],
                         [item['id'] for item in resp.json['items']])
    self.assertIn('fuzzer', resp.json['items'][0]['fuzzers'])


@test_utils.with_cloud_emulators('datastore')
class JobsSearchTest(unittest.TestCase):
  """Jobs search tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.has_access',
        'libs.access.get_access',
        'libs.helpers.get_user_email',
        'libs.gcs.prepare_blob_upload',
    ])
    self.mock.prepare_blob_upload.return_value = (
        collections.namedtuple('GcsUpload', [])())
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=jobs.JsonHandler.as_view('/'))
    self.app = webtest.TestApp(flaskapp)

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

  def test_post(self):
    """Test post method."""
    self.mock.has_access.return_value = True

    job_asan = self._create_job('test_job_asan', 'PROJECT_NAME = proj_1\n')
    job_ubsan = self._create_job('test_job_ubsan', 'PROJECT_NAME = proj_2\n')

    resp = self.app.post_json('/', {'q': "asan"})
    self.assertListEqual([job_asan.key.id()],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "ubsan"})
    self.assertListEqual([job_ubsan.key.id()],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "testing"})
    self.assertListEqual([], [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "test"})
    self.assertListEqual(
        [job_asan.key.id(), job_ubsan.key.id()],
        [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "1"})
    self.assertListEqual([job_asan.key.id()],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "2"})
    self.assertListEqual([job_ubsan.key.id()],
                         [item['id'] for item in resp.json['items']])

    resp = self.app.post_json('/', {'q': "proj"})
    self.assertListEqual(
        [job_asan.key.id(), job_ubsan.key.id()],
        [item['id'] for item in resp.json['items']])


@test_utils.with_cloud_emulators('datastore')
class JobsUpdateTest(unittest.TestCase):
  """Job update tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.auth.get_current_user',
        'libs.access.has_access',
        'libs.access.get_access',
        'libs.gcs.prepare_blob_upload',
        'clusterfuzz._internal.fuzzing.fuzzer_selection.update_mappings_for_job',
    ])
    self.mock.get_current_user().email = 'test@user.com'
    self.mock.prepare_blob_upload.return_value = (
        collections.namedtuple('GcsUpload', [])())
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule('/', view_func=jobs.UpdateJob.as_view('/'))
    flaskapp.add_url_rule(
        '/template', view_func=jobs.UpdateJobTemplate.as_view('/template'))
    self.app = webtest.TestApp(flaskapp)

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

  def test_post(self):
    """Test post method."""
    self.mock.has_access.return_value = True
    job = self._create_job('test_job', 'PROJECT_NAME = proj\n')
    resp = self.app.post(
        '/', {
            'csrf_token': form.generate_csrf_token(),
            'name': job.name,
            'desciption': job.description,
            'platform': job.platform,
            'fuzzers': ['test_fuzzer']
        },
        expect_errors=True)
    self.assertEqual(200, resp.status_int)
    self.mock.update_mappings_for_job.assert_called_with(
        mock.ANY, ['test_fuzzer'])

  def test_post_empty_fuzzers(self):
    """Test post method with no fuzzers provided."""
    self.mock.has_access.return_value = True
    job = self._create_job('test_job', 'PROJECT_NAME = proj\n')

    resp = self.app.post(
        '/', {
            'csrf_token': form.generate_csrf_token(),
            'name': job.name,
            'desciption': job.description,
            'platform': job.platform,
            'fuzzers': ''
        },
        expect_errors=True)

    self.assertEqual(200, resp.status_int)
    self.mock.update_mappings_for_job.assert_called_with(mock.ANY, [])

  def test_timeout_reserve_validation(self):
    """Test save-time validation for timeout reserve on jobs and templates."""
    self.mock.has_access.return_value = True
    data_types.JobTemplate(
        name='libfuzzer', environment_string='TEST_TIMEOUT = 65\n').put()

    def post_job(name, env, templates=''):
      return self.app.post(
          '/', {
              'csrf_token': form.generate_csrf_token(),
              'name': name,
              'platform': 'LINUX',
              'templates': templates,
              'environment_string': env,
          },
          expect_errors=True).status_int

    def post_template(name, env):
      return self.app.post(
          '/template', {
              'csrf_token': form.generate_csrf_token(),
              'name': name,
              'environment_string': env,
          },
          expect_errors=True).status_int

    for bad_env in (
        'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 65\n',
        'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = -1\n',
        'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 25s\n',
    ):
      self.assertEqual(400, post_job('libfuzzer_job', bad_env, 'libfuzzer'))

    self.assertEqual(
        200,
        post_job(
            'libfuzzer_job', 'TEST_TIMEOUT = 85\n'
            'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 25\n',
            'libfuzzer'))
    self.assertEqual(
        400,
        post_template(
            'bad_template', 'TEST_TIMEOUT = 65\n'
            'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 65\n'))

    # Clearing the reserve override with None is allowed; TEST_TIMEOUT = None
    # is allowed on a standalone template but rejected on a resolved job.
    self.assertEqual(
        200,
        post_template(
            'reserve_template', 'TEST_TIMEOUT = None\n'
            'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 25\n'))
    self.assertEqual(
        200,
        post_job('clear_reserve_job',
                 'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = None\n',
                 'reserve_template'))
    self.assertEqual(
        400,
        post_job(
            'none_timeout_job', 'TEST_TIMEOUT = None\n'
            'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 5\n'))

    # Template edits reject breaking dependent jobs without deadlocking on
    # pre-existing invalid jobs persisted outside the UI.
    self.assertEqual(
        200,
        post_job('inherited_timeout_job',
                 'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 25\n',
                 'libfuzzer'))
    data_types.Job(
        name='preexisting_bad_job',
        platform='LINUX',
        templates=['libfuzzer'],
        environment_string=(
            'TEST_TIMEOUT = 10\n'
            'TEST_TIMEOUT_RESERVE_FOR_STARTUP_AND_REPORTING = 25\n')).put()

    self.assertEqual(200,
                     post_template('libfuzzer', 'TEST_TIMEOUT = 65\nFOO = 1\n'))
    self.assertEqual(400, post_template('libfuzzer', 'TEST_TIMEOUT = 25\n'))
    self.assertEqual(200, post_template('libfuzzer', 'TEST_TIMEOUT = 30\n'))
