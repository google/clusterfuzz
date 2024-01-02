# Copyright 2024 Google LLC
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
"""Cloud Batch helpers for local testing"""

import os
from unittest import mock

from clusterfuzz._internal.google_cloud_utils import batch


@mock.patch(
    'clusterfuzz._internal.google_cloud_utils.batch._get_job',
    return_value=mock.Mock(platform='LINUX'))
@mock.patch(
    'clusterfuzz._internal.system.environment.get_config_directory',
    return_value=os.environ['BATCH_TEST_CONFIG_PATH'])
def _send_test_job(get_config_directory, get_job):
  del get_config_directory
  del get_job
  tasks = [batch.BatchTask('variant', 'libfuzzer_chrome_asan', 'https://fake/')]
  batch.create_uworker_main_batch_jobs(tasks)
