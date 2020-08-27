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
"""Tests for ml_train."""

import unittest

import flask
import webtest

from datastore import data_types
from handlers.cron import ml_train
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


@test_utils.with_cloud_emulators('datastore')
class HandlerTest(unittest.TestCase):
  """Tests for Handler."""

  def setUp(self):
    test_helpers.patch_environ(self)
    flaskapp = flask.Flask('testflask')
    flaskapp.add_url_rule(
        '/schedule-ml-train-tasks',
        view_func=ml_train.Handler.as_view('/schedule-ml-train-tasks'))
    self.app = webtest.TestApp(flaskapp)

    test_helpers.patch(
        self, ['base.tasks.add_task', 'handlers.base_handler.Handler.is_cron'])

    # Create fake jobs.
    data_types.Job(
        name='libfuzzer_asan',
        environment_string='USE_CORPUS_FOR_ML = True\n').put()
    data_types.Job(
        name='libfuzzer_msan',
        environment_string='USE_CORPUS_FOR_ML = True\n').put()
    data_types.Job(
        name='afl_asan',
        environment_string='USE_CORPUS_FOR_ML = False\n').put()

    data_types.Job(
        name='libfuzzer_asan_gradientfuzz',
        environment_string=
        'USE_CORPUS_FOR_ML = True\nUSE_LIBFUZZER_FOR_GRADIENTFUZZ = True\n'
    ).put()

    # Create fake fuzzers.
    data_types.Fuzzer(
        name='libFuzzer',
        jobs=['libfuzzer_asan', 'libfuzzer_asan_gradientfuzz']).put()
    data_types.Fuzzer(name='afl', jobs=['afl_asan']).put()

    # Create fake child fuzzers.
    data_types.FuzzTarget(
        engine='libFuzzer', binary='fake_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_fake_fuzzer', job='libfuzzer_asan').put()
    data_types.FuzzTarget(
        engine='afl', binary='fake_fuzzer', project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='afl_fake_fuzzer', job='afl_asan').put()

    data_types.FuzzTarget(
        engine='libFuzzer',
        binary='fake_gradientfuzzer',
        project='test-project').put()
    data_types.FuzzTargetJob(
        fuzz_target_name='libFuzzer_fake_gradientfuzzer',
        job='libfuzzer_asan_gradientfuzz').put()

  def test_add_one_task(self):
    """Test add one task."""
    self.app.get('/schedule-ml-train-tasks')
    self.mock.add_task.assert_any_call(
        'ml_train', 'fake_fuzzer', 'libfuzzer_asan', queue='ml-jobs-linux')
    self.mock.add_task.assert_any_call(
        'gradientfuzz',
        'fake_gradientfuzzer',
        'libfuzzer_asan_gradientfuzz',
        queue='ml-jobs-linux')
