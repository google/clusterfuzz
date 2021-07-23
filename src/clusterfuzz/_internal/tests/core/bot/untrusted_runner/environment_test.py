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
"""Tests for environment."""

import os
import re
import unittest

import mock

from clusterfuzz._internal.bot.untrusted_runner import environment
from clusterfuzz._internal.tests.test_libs import helpers

FORWARDED_ENVIRONMENT_VARIABLES = [
    re.compile(pattern) for pattern in (
        r'^ASAN_OPTIONS$',
        r'^AFL_.*',
        r'^REBASED$',
    )
]

REBASED_ENVIRONMENT_VARIABLES = set([
    'FUZZER_DIR',
    'REBASED',
])


@mock.patch('clusterfuzz._internal.bot.untrusted_runner.environment.'
            'FORWARDED_ENVIRONMENT_VARIABLES', FORWARDED_ENVIRONMENT_VARIABLES)
@mock.patch(
    'clusterfuzz._internal.bot.untrusted_runner.environment.REBASED_ENVIRONMENT_VARIABLES',
    REBASED_ENVIRONMENT_VARIABLES)
class EnvironmentTest(unittest.TestCase):
  """Test environment."""

  def setUp(self):
    helpers.patch(self, [
        'clusterfuzz._internal.bot.untrusted_runner.host.stub',
    ])

    helpers.patch_environ(self)
    os.environ['WORKER_ROOT_DIR'] = '/worker'

  def test_is_forwarded_environment_variable(self):
    """Test is_forwarded_environment_variable."""
    self.assertTrue(
        environment.is_forwarded_environment_variable('ASAN_OPTIONS'))
    self.assertTrue(environment.is_forwarded_environment_variable('REBASED'))
    self.assertFalse(
        environment.is_forwarded_environment_variable('FUZZER_DIR'))
    self.assertFalse(
        environment.is_forwarded_environment_variable('ASAN_OPTIONSS'))
    self.assertTrue(environment.is_forwarded_environment_variable('AFL_'))
    self.assertTrue(environment.is_forwarded_environment_variable('AFL_BLAH'))

  def test_should_rebase_environment_value(self):
    """Test should_rebase_environment_value."""
    self.assertTrue(environment.should_rebase_environment_value('FUZZER_DIR'))
    self.assertTrue(environment.should_rebase_environment_value('REBASED'))
    self.assertFalse(
        environment.should_rebase_environment_value('ASAN_OPTIONS'))
    self.assertFalse(environment.should_rebase_environment_value('AFL_'))

  def test_update_environment(self):
    """Test update environment."""
    environment.update_environment({
        'BLAH': 'abc',
        'BLAH2': os.path.join(os.environ['ROOT_DIR'], 'blah2'),
        'FUZZER_DIR': os.path.join(os.environ['ROOT_DIR'], 'fuzzer'),
    })

    request = self.mock.stub().UpdateEnvironment.call_args[0][0]
    self.assertEqual({
        'BLAH': 'abc',
        'BLAH2': os.path.join(os.environ['ROOT_DIR'], 'blah2'),
        'FUZZER_DIR': '/worker/fuzzer',
    }, request.env)

  def test_set_environment_vars(self):
    """Test set_environment_vars."""
    result = {}
    environment.set_environment_vars(
        result, {
            'ASAN_OPTIONS': 'options',
            'BLAH': 'blah',
            'FUZZER_DIR': os.path.join(os.environ['ROOT_DIR'], 'fuzzer'),
            'REBASED': os.path.join(os.environ['ROOT_DIR'], 'rebased')
        })

    self.assertDictEqual({
        'ASAN_OPTIONS': 'options',
        'REBASED': os.path.join(os.environ['ROOT_DIR'], 'rebased')
    }, result)

    os.environ['TRUSTED_HOST'] = 'True'

    environment.set_environment_vars(
        result, {
            'ASAN_OPTIONS': 'options',
            'BLAH': 'blah',
            'FUZZER_DIR': os.path.join(os.environ['ROOT_DIR'], 'fuzzer'),
            'REBASED': os.path.join(os.environ['ROOT_DIR'], 'rebased')
        })

    self.assertDictEqual({
        'ASAN_OPTIONS': 'options',
        'REBASED': '/worker/rebased',
    }, result)
