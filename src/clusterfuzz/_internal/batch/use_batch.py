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

import multiprocessing.pool
import os
from typing import Any
from unittest import mock

from clusterfuzz._internal.batch import service
from clusterfuzz._internal.remote_task import remote_task_types


def _create_many() -> None:
  """Creates many jobs."""
  many: list[None] = [None for _ in range(2000)]
  with multiprocessing.pool.Pool(120) as pool:
    pool.map(_send_test_job, many)


@mock.patch(
    'clusterfuzz._internal.batch.service._get_specs_from_config',
    return_value={})
@mock.patch(
    'clusterfuzz._internal.system.environment.get_config_directory',
    return_value=os.environ.get('BATCH_TEST_CONFIG_PATH', ''))
def _send_test_job(
    _: Any = None,
    get_config_directory: Any = None,
    get_specs_from_config: Any = None,
) -> None:
  """Creates a test batch job for local manual testing to ensure job creation
  actually works."""
  del _
  del get_config_directory
  del get_specs_from_config
  tasks = [
      remote_task_types.RemoteTask('variant', 'libfuzzer_chrome_asan',
                                   'https://fake/') for _ in range(10)
  ]
  batch_service = service.GcpBatchService()
  batch_service.create_utask_main_jobs(tasks)
