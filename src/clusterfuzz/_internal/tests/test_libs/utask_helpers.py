# Copyright 2023 Google LLC
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
"""Test helpers for utasks."""
import os
import shutil
import tempfile
import unittest

from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.google_cloud_utils import blobs
from clusterfuzz._internal.system import environment
from clusterfuzz._internal.system import shell
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers
from clusterfuzz._internal.tests.test_libs import test_utils

TEST_LIBS_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_LIBS_DATA_DIR = os.path.join(TEST_LIBS_DIR, 'data')
ROOT_DIR = os.path.abspath(os.path.join(*([__file__] + 6 * ['..'])))


@unittest.skipIf(not os.getenv('UTASK_TESTS'), 'Skipping utask tests.')
@test_utils.with_cloud_emulators('datastore')
class UtaskIntegrationTest(unittest.TestCase):
  """Base class for doing integration testing of untrusted_runner."""

  def run(self, *args, **kwargs):
    with tempfile.TemporaryDirectory() as temp_dir:
      self.temp_dir = temp_dir
      shutil.copytree(
          os.path.join(ROOT_DIR, 'bot'), os.path.join(temp_dir, 'bot'))
      shutil.copytree(
          os.path.join(ROOT_DIR, 'configs'), os.path.join(temp_dir, 'configs'))
      super().run(*args, **kwargs)

  def setUp(self):
    test_helpers.patch_environ(self)
    test_helpers.patch(
        self, ['clusterfuzz._internal.bot.tasks.task_creation.create_tasks'])
    self.job_type = 'libfuzzer_asan_job'
    os.environ['ROOT_DIR'] = self.temp_dir
    os.environ['JOB_NAME'] = self.job_type
    environment_string = ('APP_NAME = test_fuzzer\n'
                          'RELEASE_BUILD_BUCKET_PATH = '
                          'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
                          'test-libfuzzer-build-([0-9]+).zip\n'
                          'REVISION_VARS_URL = gs://clusterfuzz-test-data/'
                          'test_libfuzzer_builds/'
                          'test-libfuzzer-build-%s.srcmap.json\n')
    job = data_types.Job(
        name=self.job_type, environment_string=environment_string)
    self.uworker_env = commands.update_environment_for_job(environment_string)
    job.put()
    self.fuzz_target = 'test_fuzzer'
    self.testcase = data_types.Testcase(job_type=self.job_type)
    self.testcase.fuzzed_keys = blobs.write_blob(
        os.path.join(TEST_LIBS_DATA_DIR,
                     'crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'))
    self.testcase.absolute_path = '/mnt/scratch0/clusterfuzz/bot/inputs/fuzzer-testcases/input.test'
    self.testcase.put()
    metadata = data_types.TestcaseUploadMetadata(
        testcase_id=self.testcase.key.id())
    metadata.put()
    os.environ['UTASK_TESTS'] = 'True'
    os.environ['FUZZ_TARGET'] = self.fuzz_target

    environment.set_bot_environment()
    fuzz_inputs = os.environ['FUZZ_INPUTS']
    shell.remove_directory(fuzz_inputs, recreate=True)
    os.environ['CONFIG_DIR_OVERRIDE'] = os.path.abspath(
        os.path.join(ROOT_DIR, 'configs', 'test'))

  def execute(self, utask_module, task_argument, job_type, uworker_env):
    executor = commands.UTaskLocalExecutor(utask_module)
    return executor.execute(task_argument, job_type, uworker_env)
