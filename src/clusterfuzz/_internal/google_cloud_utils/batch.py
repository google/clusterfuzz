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
"""Cloud Batch helpers."""
from typing import List

from clusterfuzz._internal.batch.data_structures import BatchTask
from clusterfuzz._internal.batch.service import BatchService


def create_uworker_main_batch_job(module, job_type, input_download_url):
  """Creates a batch job."""
  service = BatchService()
  return service.create_uworker_main_batch_job(module, job_type,
                                               input_download_url)


def create_uworker_main_batch_jobs(batch_tasks: List[BatchTask]):
  """Creates batch jobs."""
  service = BatchService()
  return service.create_uworker_main_batch_jobs(batch_tasks)
