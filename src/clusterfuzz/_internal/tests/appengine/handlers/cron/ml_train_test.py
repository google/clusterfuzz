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

from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils
from handlers.cron import ml_train


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

    test_helpers.patch(self, [
        'clusterfuzz._internal.base.tasks.add_task',
        'handlers.base_handler.Handler.is_cron',
        'clusterfuzz._internal.metrics.logs.log_error'
    ])

    # Create fake jobs.
    data_types.Job(
        name='libfuzzer_asan',
        environment_string='ML_MODELS_TO_USE = rnn_generator').put()
    data_types.Job(name='libfuzzer_msan', environment_string='').put()
    data_types.Job(name='afl_asan', environment_string='').put()

    data_types.Job(
        name='libfuzzer_asan_invalid',
        environment_string='ML_MODELS_TO_USE = invalid_model\n').put()

    # Create fake fuzzers.
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

  def test_add_tasks(self):
    """Tests adding single and multiple tasks."""
    self.app.get('/schedule-ml-train-tasks')
    self.mock.add_task.assert_any_call(
        'train_rnn_generator',
        'libFuzzer_fake_fuzzer',
        'libfuzzer_asan',
        queue='ml-jobs-linux')

    # Ensure that we logged an error for the invalid model.
    self.mock.log_error.assert_called_once_with(
        'Invalid ML model invalid_model for job libfuzzer_asan_invalid.')
