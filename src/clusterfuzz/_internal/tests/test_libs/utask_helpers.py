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
import unittest

from clusterfuzz._internal.system import environment
from clusterfuzz._internal.datastore import data_types
from clusterfuzz._internal.bot.tasks import commands
from clusterfuzz._internal.tests.test_libs import test_utils
from clusterfuzz._internal.tests.test_libs import helpers as test_helpers

@test_utils.integration
@test_utils.with_cloud_emulators('datastore')
class UtaskIntegrationTest(unittest.TestCase):
  """Base class for doing integration testing of untrusted_runner."""
  def setUp(self):
    test_helpers.patch_environ(self)
    self.job_type = 'libfuzzer_asan_job'
    environment_string=('APP_NAME = test_fuzzer\n'
                        'RELEASE_BUILD_BUCKET_PATH = '
                        'gs://clusterfuzz-test-data/test_libfuzzer_builds/'
                        'test-libfuzzer-build-([0-9]+).zip\n'
                        'REVISION_VARS_URL = gs://clusterfuzz-test-data/'
                        'test_libfuzzer_builds/'
                        'test-libfuzzer-build-%s.srcmap.json\n')
    job = data_types.Job(
      name=self.job_type,
      environment_string=environment_string)
    self.uworker_env = commands.update_environment_for_job(environment_string)
    job.put()

  def execute(self, utask_module, task_argument, job_type, uworker_env):
    executor = commands.UTaskLocalInMemoryExecutor(utask_module)
    return executor.execute(task_argument, job_type, uworker_env)
