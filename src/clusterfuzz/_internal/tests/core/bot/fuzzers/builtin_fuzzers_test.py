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
"""Tests builtin_fuzzers."""

import functools
import os
import unittest

from pyfakefs import fake_filesystem_unittest
import six

from clusterfuzz._internal.bot.fuzzers import builtin
from clusterfuzz._internal.bot.fuzzers import builtin_fuzzers
from clusterfuzz._internal.bot.tasks import fuzz_task
from clusterfuzz._internal.bot.tasks import setup
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.tests.test_libs import helpers
from clusterfuzz._internal.tests.test_libs import test_utils


class BuiltinFuzzersTest(unittest.TestCase):
  """builtin_fuzzers tests."""

  def test_get(self):
    """Tests get()."""
    self.assertIsInstance(
        builtin_fuzzers.get('libFuzzer'), builtin.BuiltinFuzzer)
    self.assertIsNone(builtin_fuzzers.get('does_not_exist'))


# pylint: disable=unused-argument
def _mock_fuzzer_run(output, num_generated, corpus_directory, self,
                     input_directory, output_directory, no_of_files):
  """Mock fuzzer run."""
  for i in range(num_generated):
    with open(os.path.join(output_directory, 'fuzz-%d' % i), 'w') as f:
      f.write('testcase')

  return builtin.BuiltinFuzzerResult(output, corpus_directory)


@test_utils.with_cloud_emulators('datastore')
class BuiltinFuzzersSetupTest(fake_filesystem_unittest.TestCase):
  """Test builtin fuzzers setup."""

  def setUp(self):
    """Setup for builtin fuzzer setup test."""
    helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)
    self.fs.create_dir('/input')
    self.fs.create_dir('/output')
    self.fs.create_dir('/data-bundles')
    environment.set_value('DATA_BUNDLES_DIR', '/data-bundles')

    helpers.patch(self, [
        'clusterfuzz._internal.bot.fuzzers.libFuzzer.fuzzer.LibFuzzer.run',
        'clusterfuzz._internal.metrics.fuzzer_logs.get_bucket',
        'clusterfuzz._internal.google_cloud_utils.blobs.write_blob',
    ])

    self.fuzzer = data_types.Fuzzer(
        revision=1,
        file_size='builtin',
        source='builtin',
        name='libFuzzer',
        max_testcases=4,
        builtin=True)
    self.fuzzer.put()

    self.fuzzer_directory = os.path.join(
        environment.get_value('ROOT_DIR'), 'src', 'clusterfuzz', '_internal',
        'bot', 'fuzzers', 'libFuzzer')

    # Needed since local config is not available with fakefs.
    self.mock.get_bucket.return_value = None
    self.mock.write_blob.return_value = 'sample'

    environment.set_value('JOB_NAME', 'job')
    environment.set_value('INPUT_DIR', '/input')
    environment.set_value('MAX_TESTCASES', 4)

  def test_update_fuzzer(self):
    """Test fuzzer setup."""
    self.assertTrue(setup.update_fuzzer_and_data_bundles('libFuzzer'))
    self.assertEqual(self.fuzzer_directory, environment.get_value('FUZZER_DIR'))

  def test_generate_blackbox_fuzzers(self):
    """Test generate_blackbox_fuzzers (success)."""
    output = ('metadata::fuzzer_binary_name: fuzzer_binary_name\n')
    self.mock.run.side_effect = functools.partial(_mock_fuzzer_run, output, 4,
                                                  'corpus_dir')

    self.assertTrue(setup.update_fuzzer_and_data_bundles('libFuzzer'))

    session = fuzz_task.FuzzingSession('libFuzzer', 'job', 1)
    session.testcase_directory = '/output'
    session.data_directory = '/input'

    (error_occurred, testcase_file_paths, sync_corpus_directory,
     fuzzer_metadata) = session.generate_blackbox_testcases(
         self.fuzzer, self.fuzzer_directory, 4)
    self.assertEqual(1, len(self.mock.run.call_args_list))
    self.assertEqual(('/input', '/output', 4), self.mock.run.call_args[0][1:])

    self.assertFalse(error_occurred)
    six.assertCountEqual(self, [
        '/output/fuzz-0',
        '/output/fuzz-1',
        '/output/fuzz-2',
        '/output/fuzz-3',
    ], testcase_file_paths)

    self.assertEqual('corpus_dir', sync_corpus_directory)
    self.assertDictEqual({
        'fuzzer_binary_name': 'fuzzer_binary_name'
    }, fuzzer_metadata)

  def test_generate_blackbox_fuzzers_fail(self):
    """Test generate_blackbox_fuzzers (failure)."""
    self.mock.run.side_effect = builtin.BuiltinFuzzerException()
    self.assertTrue(setup.update_fuzzer_and_data_bundles('libFuzzer'))

    session = fuzz_task.FuzzingSession('libFuzzer', 'job', 1)
    session.testcase_directory = '/output'
    session.data_directory = '/input'

    with self.assertRaises(builtin.BuiltinFuzzerException):
      session.generate_blackbox_testcases(self.fuzzer, self.fuzzer_directory, 4)
