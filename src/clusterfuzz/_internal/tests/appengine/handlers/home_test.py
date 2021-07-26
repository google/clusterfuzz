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
"""Tests for the home page."""

import datetime
import unittest

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers import home
from libs import access
from libs import helpers


@test_utils.with_cloud_emulators('datastore')
class HomeTests(unittest.TestCase):
  """home tests."""

  def setUp(self):
    test_helpers.patch(self, [
        'libs.access.get_access',
        'clusterfuzz._internal.base.external_users.allowed_jobs_for_user',
        'libs.helpers.get_user_email',
    ])

    data_types.Job(
        name='libfuzzer_asan_lib',
        environment_string=('PROJECT_NAME = lib\n'
                            'CORPUS_PRUNE = True')).put()
    data_types.Job(
        name='afl_asan_lib', environment_string=('PROJECT_NAME = lib\n')).put()
    data_types.Job(
        name='libfuzzer_msan_lib',
        environment_string='PROJECT_NAME = lib').put()
    data_types.Job(
        name='afl_asan_lib2',
        environment_string=('PROJECT_NAME = lib2\n')).put()

    data_types.Job(
        name='libfuzzer_asan_lib2',
        environment_string=('PROJECT_NAME = lib2\n'
                            'CORPUS_PRUNE = True')).put()
    data_types.Job(
        name='libfuzzer_ubsan_lib2',
        environment_string='PROJECT_NAME = lib2').put()

    data_types.FuzzTarget(engine='afl', binary='fuzzer', project='lib2').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='afl_lib2_fuzzer',
        job='afl_asan_lib2',
        last_run=datetime.datetime.utcnow()).put()
    data_types.FuzzTarget(
        engine='libFuzzer', binary='fuzzer', project='lib2').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_lib2_fuzzer',
        job='libfuzzer_asan_lib2',
        last_run=datetime.datetime.utcnow()).put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_lib2_fuzzer',
        job='libfuzzer_ubsan_lib2',
        last_run=datetime.datetime.utcnow()).put()

    self.maxDiff = None  # pylint: disable=invalid-name

  def test_no_permissions(self):
    """Test user with no permissions."""
    self.mock.get_user_email.return_value = 'nope@nope.com'
    self.mock.allowed_jobs_for_user.return_value = []
    self.mock.get_access.return_value = access.UserAccess.Denied

    with self.assertRaises(helpers.EarlyExitException):
      home.get_results()

  def test_results_external(self):
    """Test results for external user."""
    self.mock.get_user_email.return_value = 'user@user.com'
    self.mock.allowed_jobs_for_user.return_value = [
        'libfuzzer_asan_lib', 'libfuzzer_msan_lib'
    ]
    self.mock.get_access.return_value = access.UserAccess.Denied

    results = home.get_results()
    self.assertEqual(
        results, {
            'info': {
                'projects': [{
                    'jobs': [{
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'libfuzzer_asan_lib',
                        'single_target': None,
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: memory (MSAN)',
                        'name': u'libfuzzer_msan_lib',
                        'single_target': None,
                        'engine_name': 'libFuzzer',
                        'engine_display_name': 'libFuzzer',
                        'has_stats': True,
                    }],
                    'name':
                        u'lib',
                    'coverage_job':
                        'libfuzzer_asan_lib',
                }],
                'is_internal_user':
                    False,
            }
        })

    self.mock.allowed_jobs_for_user.return_value = [
        'afl_asan_lib', 'libfuzzer_asan_lib', 'libfuzzer_msan_lib',
        'afl_asan_lib2', 'libfuzzer_asan_lib2', 'libfuzzer_ubsan_lib2'
    ]

    results = home.get_results()
    self.assertEqual(
        results, {
            'info': {
                'projects': [{
                    'jobs': [{
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'afl_asan_lib',
                        'single_target': None,
                        'engine_display_name': 'AFL',
                        'engine_name': 'afl',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'libfuzzer_asan_lib',
                        'single_target': None,
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: memory (MSAN)',
                        'name': u'libfuzzer_msan_lib',
                        'single_target': None,
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }],
                    'name':
                        u'lib',
                    'coverage_job':
                        'libfuzzer_asan_lib',
                }, {
                    'jobs': [{
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'afl_asan_lib2',
                        'single_target': 'afl_lib2_fuzzer',
                        'engine_display_name': 'AFL',
                        'engine_name': 'afl',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'libfuzzer_asan_lib2',
                        'single_target': 'libFuzzer_lib2_fuzzer',
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: undefined (UBSAN)',
                        'name': u'libfuzzer_ubsan_lib2',
                        'single_target': 'libFuzzer_lib2_fuzzer',
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }],
                    'name':
                        u'lib2',
                    'coverage_job':
                        'libfuzzer_asan_lib2',
                }],
                'is_internal_user':
                    False,
            }
        })

  def test_results_internal(self):
    """Test results for internal user."""
    self.mock.get_user_email.return_value = 'user@user.com'
    self.mock.allowed_jobs_for_user.return_value = []
    self.mock.get_access.return_value = access.UserAccess.Allowed

    results = home.get_results()
    self.assertEqual(
        results, {
            'info': {
                'projects': [{
                    'jobs': [{
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'afl_asan_lib',
                        'single_target': None,
                        'engine_display_name': 'AFL',
                        'engine_name': 'afl',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'libfuzzer_asan_lib',
                        'single_target': None,
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: memory (MSAN)',
                        'name': u'libfuzzer_msan_lib',
                        'single_target': None,
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }],
                    'name':
                        u'lib',
                    'coverage_job':
                        'libfuzzer_asan_lib',
                }, {
                    'jobs': [{
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'afl_asan_lib2',
                        'single_target': 'afl_lib2_fuzzer',
                        'engine_display_name': 'AFL',
                        'engine_name': 'afl',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: address (ASAN)',
                        'name': u'libfuzzer_asan_lib2',
                        'single_target': 'libFuzzer_lib2_fuzzer',
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }, {
                        'sanitizer_string': 'Sanitizer: undefined (UBSAN)',
                        'name': u'libfuzzer_ubsan_lib2',
                        'single_target': 'libFuzzer_lib2_fuzzer',
                        'engine_display_name': 'libFuzzer',
                        'engine_name': 'libFuzzer',
                        'has_stats': True,
                    }],
                    'name':
                        u'lib2',
                    'coverage_job':
                        'libfuzzer_asan_lib2',
                }],
                'is_internal_user':
                    True,
            }
        })
