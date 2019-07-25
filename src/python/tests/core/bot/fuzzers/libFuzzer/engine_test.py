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
"""Tests for libFuzzer engine."""
# pylint: disable=unused-argument

from future import standard_library
standard_library.install_aliases()
import os

import pyfakefs.fake_filesystem_unittest as fake_fs_unittest

from bot.fuzzers.libFuzzer import engine
from bot.fuzzers.libFuzzer import launcher
from tests.test_libs import helpers as test_helpers
from tests.test_libs import test_utils


class PrepareTest(fake_fs_unittest.TestCase):
  """Prepare() tests."""

  def setUp(self):
    # Set up fake filesystem.
    test_helpers.patch_environ(self)
    test_utils.set_up_pyfakefs(self)

    self.fs.CreateDirectory('/build')
    self.fs.CreateDirectory('/inputs')
    self.fs.CreateFile('/path/target')
    self.fs.CreateFile(
        '/path/target.options',
        contents=('[libfuzzer]\n'
                  'max_len=31337\n'
                  'timeout=11\n'))

    os.environ['FUZZ_INPUTS_DISK'] = '/inputs'

    test_helpers.patch(self, ['bot.fuzzers.libFuzzer.launcher.pick_strategies'])

    self.mock.pick_strategies.return_value = launcher.StrategyInfo(
        fuzzing_strategies=['strategy1', 'strategy2'],
        arguments=['-arg1'],
        additional_corpus_dirs=['/new_corpus_dir'],
        extra_env={'extra_env': '1'},
        use_dataflow_tracing=False,
        is_mutations_run=True)

  def test_prepare(self):
    """Test prepare."""
    engine_impl = engine.LibFuzzerEngine()
    options = engine_impl.prepare('/corpus_dir', '/path/target', '/path')
    self.assertEqual('/corpus_dir', options.corpus_dir)
    self.assertItemsEqual(
        ['-max_len=31337', '-timeout=11', '-rss_limit_mb=2048', '-arg1'],
        options.arguments)
    self.assertItemsEqual(['strategy1', 'strategy2'], options.strategies)
    self.assertItemsEqual(['/new_corpus_dir'], options.additional_corpus_dirs)
    self.assertDictEqual({'extra_env': '1'}, options.extra_env)
    self.assertFalse(options.use_dataflow_tracing)
    self.assertTrue(options.is_mutations_run)
